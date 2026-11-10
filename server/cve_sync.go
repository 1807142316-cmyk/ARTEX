package server

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Autumn-27/artex/cve"
	"github.com/Autumn-27/artex/db"
)

const cveSyncLock int64 = 7337741012
const cveReleaseAPI = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"

type cveSyncService struct {
	server     *Server
	dir        string
	releaseAPI string
	client     *http.Client
	wake       chan struct{}
}

func (s *Server) startCVESync(dataDir string) {
	if s.m.pg == nil {
		return
	}
	endpoint := strings.TrimSpace(os.Getenv("ARTEX_CVE_RELEASE_API"))
	if endpoint == "" {
		endpoint = cveReleaseAPI
	}
	service := &cveSyncService{server: s, dir: filepath.Join(dataDir, "content", "cve"), releaseAPI: endpoint, client: &http.Client{Timeout: 30 * time.Minute}, wake: make(chan struct{}, 1)}
	s.cveSync = service
	go service.run()
}
func (s *Server) getCVESync(w http.ResponseWriter, r *http.Request) {
	status, err := s.m.pg.CVESyncStatus(r.Context())
	if err != nil {
		writeErr(w, 500, "read CVE sync: "+err.Error())
		return
	}
	writeJSON(w, 200, status)
}
func (s *Server) setCVESync(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Enabled         bool `json:"enabled"`
		IntervalMinutes int  `json:"interval_minutes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input); err != nil || input.IntervalMinutes < 5 || input.IntervalMinutes > 10080 {
		writeErr(w, 400, "interval_minutes must be between 5 and 10080")
		return
	}
	if err := s.m.pg.SetCVESyncSettings(r.Context(), input.Enabled, input.IntervalMinutes); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.getCVESync(w, r)
}
func (s *Server) requestCVESync(w http.ResponseWriter, r *http.Request) {
	if s.cveSync == nil {
		writeErr(w, 503, "CVE synchronization unavailable")
		return
	}
	id, err := s.m.pg.QueueCVESync(r.Context(), false)
	if err != nil {
		writeErr(w, 500, "queue CVE sync: "+err.Error())
		return
	}
	if id == 0 {
		writeErr(w, 409, "CVE update already queued or running")
		return
	}
	select {
	case s.cveSync.wake <- struct{}{}:
	default:
	}
	writeJSON(w, 202, map[string]any{"run_id": id, "status": "queued"})
}
func (c *cveSyncService) run() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	// A persisted queued/running job is resumed immediately after a process restart.
	c.step()
	for {
		select {
		case <-c.server.ctx.Done():
			return
		case <-ticker.C:
			c.step()
		case <-c.wake:
			c.step()
		}
	}
}
func (c *cveSyncService) step() {
	ctx := c.server.ctx
	if ctx.Err() != nil {
		return
	}
	conn, err := c.server.m.pg.Conn(ctx)
	if err != nil {
		return
	}
	defer conn.Close()
	var locked bool
	if err = conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, cveSyncLock).Scan(&locked); err != nil || !locked {
		return
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(unlockCtx, `SELECT pg_advisory_unlock($1)`, cveSyncLock)
	}()
	run, err := c.server.m.pg.ActiveCVESync(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		id, queueErr := c.server.m.pg.QueueCVESync(ctx, true)
		if queueErr != nil || id == 0 {
			return
		}
		run, err = c.server.m.pg.ActiveCVESync(ctx)
	}
	if err != nil {
		return
	}
	err = c.execute(ctx, &run)
	// Cancellation leaves durable state active; the next process resumes it.
	if ctx.Err() != nil {
		return
	}
	if finishErr := c.server.m.pg.FinishCVESync(ctx, run.ID, err); finishErr != nil {
		log.Printf("[cve] finish sync: %v", finishErr)
		return
	}
	if cleanupErr := c.pruneCache(ctx); cleanupErr != nil {
		log.Printf("[cve] prune cache: %v", cleanupErr)
	}
}
func (c *cveSyncService) execute(ctx context.Context, run *db.CVESyncRun) error {
	if err := os.MkdirAll(c.dir, 0700); err != nil {
		return err
	}
	if len(run.Assets) == 0 {
		if err := c.prepare(ctx, run); err != nil {
			return err
		}
	}
	if err := c.server.m.pg.PrepareCVESync(ctx, *run); err != nil {
		return err
	}
	position := 0
	batch := make([]db.CVERecord, 0, 250)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := c.server.m.pg.ApplyCVESyncBatch(ctx, run.ID, position, batch); err != nil {
			return err
		}
		batch = batch[:0]
		return nil
	}
	for index, asset := range run.Assets {
		path, hash, err := c.download(ctx, asset)
		if err != nil {
			return err
		}
		if asset.SHA256 != "" && asset.SHA256 != hash {
			_ = os.Remove(path)
			return fmt.Errorf("CVE archive checksum changed for %s", asset.Name)
		}
		asset.SHA256 = hash
		run.Assets[index] = asset
		if err := c.server.m.pg.PrepareCVESync(ctx, *run); err != nil {
			return err
		}
		manifest, err := json.MarshalIndent(map[string]any{"source_version": run.SourceVersion, "asset": asset, "acquired_at": time.Now().UTC(), "parser": "artex-cve-v1", "license": "CVE Program Terms of Use", "license_url": "https://www.cve.org/Legal/TermsOfUse"}, "", "  ")
		if err != nil {
			return err
		}
		if err = os.WriteFile(path+".manifest.json", manifest, 0600); err != nil {
			return err
		}
		callbackFailed := false
		assetRecords := 0
		err = cve.WalkArchive(ctx, path, run.SourceVersion, func(record cve.Record) error {
			assetRecords++
			position++
			if position <= run.Checkpoint {
				return nil
			}
			batch = append(batch, db.CVERecord{ID: record.ID, State: record.State, DataVersion: record.DataVersion, Description: record.Description, Products: record.Products, References: record.References, Published: record.Published, Updated: record.Updated, SourceVersion: record.SourceVersion, ContentHash: record.ContentHash, Raw: record.Raw})
			if len(batch) >= 250 {
				err := flush()
				callbackFailed = err != nil
				return err
			}
			return nil
		})
		if err != nil {
			if !callbackFailed && ctx.Err() == nil {
				_ = os.Remove(path)
			}
			return err
		}
		if assetRecords == 0 {
			_ = os.Remove(path)
			return errors.New("CVE release archive contains no records")
		}
		if err = flush(); err != nil {
			return err
		}
	}
	if position == 0 && len(run.Assets) > 0 {
		return errors.New("CVE release archive contains no records")
	}
	return nil
}
func (c *cveSyncService) prepare(ctx context.Context, run *db.CVESyncRun) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.releaseAPI, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "ARTEX-CVE-sync")
	response, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("CVE release source returned HTTP %d", response.StatusCode)
	}
	var release struct {
		Tag    string `json:"tag_name"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&release); err != nil {
		return err
	}
	if release.Tag == "" {
		return errors.New("CVE release has no source version")
	}
	status, err := c.server.m.pg.CVESyncStatus(ctx)
	if err != nil {
		return err
	}
	run.SourceVersion = release.Tag
	run.BaselineName = status.BaselineName
	run.Assets = []db.CVESyncAsset{}
	var baseline, delta *db.CVESyncAsset
	for _, asset := range release.Assets {
		if !strings.HasSuffix(strings.ToLower(asset.Name), ".zip") {
			continue
		}
		candidate := db.CVESyncAsset{Name: asset.Name, URL: asset.URL}
		if strings.Contains(asset.Name, "all_CVEs_at_midnight") {
			baseline = &candidate
		}
		if strings.Contains(asset.Name, "delta_CVEs") {
			delta = &candidate
		}
	}
	if baseline == nil {
		return errors.New("CVE release has no baseline archive")
	}
	if release.Tag != status.SourceVersion && status.BaselineName == baseline.Name && status.LastSuccess != nil && delta == nil {
		return errors.New("CVE release is incomplete: changed source version has no delta archive")
	}
	// Hourly deltas are cumulative only since the daily baseline. Reapply the new
	// baseline on every baseline change, including arbitrarily long missed windows.
	if status.BaselineName != baseline.Name || status.LastSuccess == nil {
		run.Assets = append(run.Assets, *baseline)
		run.BaselineName = baseline.Name
	}
	if release.Tag != status.SourceVersion && delta != nil {
		run.Assets = append(run.Assets, *delta)
	}
	return nil
}
func (c *cveSyncService) download(ctx context.Context, asset db.CVESyncAsset) (string, string, error) {
	parsed, err := url.Parse(asset.URL)
	if err != nil || parsed.Host == "" || parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", "", errors.New("invalid CVE asset URL")
	}
	path := c.cachePath(asset.URL)
	if file, err := os.Open(path); err == nil {
		hash := sha256.New()
		_, err = io.Copy(hash, file)
		_ = file.Close()
		if err == nil && validateCVEZIP(path) == nil {
			return path, hex.EncodeToString(hash.Sum(nil)), nil
		}
		if err := os.Remove(path); err != nil {
			return "", "", err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
	if err != nil {
		return "", "", err
	}
	response, err := c.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "", "", fmt.Errorf("CVE archive returned HTTP %d", response.StatusCode)
	}
	file, err := os.CreateTemp(c.dir, "download-*.partial")
	if err != nil {
		return "", "", err
	}
	defer os.Remove(file.Name())
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, (2<<30)+1))
	closeErr := file.Close()
	if copyErr != nil {
		return "", "", copyErr
	}
	if closeErr != nil {
		return "", "", closeErr
	}
	if written > 2<<30 {
		return "", "", errors.New("CVE archive exceeds 2 GiB limit")
	}
	if err := validateCVEZIP(file.Name()); err != nil {
		return "", "", err
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return "", "", err
	}
	return path, hex.EncodeToString(hash.Sum(nil)), nil
}

func validateCVEZIP(path string) error {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer reader.Close()
	if len(reader.File) == 0 {
		return errors.New("CVE release archive is empty")
	}
	return nil
}

func (c *cveSyncService) cachePath(assetURL string) string {
	digest := sha256.Sum256([]byte(assetURL))
	return filepath.Join(c.dir, hex.EncodeToString(digest[:])+".zip")
}

var cveCacheName = regexp.MustCompile(`^[a-f0-9]{64}\.zip$`)

// Keep resumable jobs and the most recent successful content. Run metadata and
// manifests remain as the historical provenance ledger after ZIP eviction.
func (c *cveSyncService) pruneCache(ctx context.Context) error {
	rows, err := c.server.m.pg.QueryContext(ctx, `SELECT assets FROM cve_sync_runs WHERE status IN ('queued','running') OR id=(SELECT max(id) FROM cve_sync_runs WHERE status='succeeded' AND jsonb_array_length(assets)>0)`)
	if err != nil {
		return err
	}
	protected := make(map[string]bool)
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		var assets []db.CVESyncAsset
		if err := json.Unmarshal(raw, &assets); err != nil {
			rows.Close()
			return err
		}
		for _, asset := range assets {
			protected[filepath.Base(c.cachePath(asset.URL))] = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	entries, err := os.ReadDir(c.dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	root, err := filepath.Abs(c.dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !cveCacheName.MatchString(entry.Name()) || protected[entry.Name()] {
			continue
		}
		path := filepath.Join(root, entry.Name())
		if filepath.Dir(path) != root {
			return errors.New("CVE cache path escaped content directory")
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
