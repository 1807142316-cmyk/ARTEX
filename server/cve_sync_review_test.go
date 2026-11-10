package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/Autumn-27/artex/db"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCVESyncWaitsForCompleteReleaseAndRetriesMalformedArchive(t *testing.T) {
	if _, _, err := db.DSN(); err != nil {
		t.Skipf("PostgreSQL DSN not configured: %v", err)
	}
	var stage atomic.Int32
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest" {
			assets := []map[string]string{{"name": "2099-03-01_all_CVEs_at_midnight.zip", "browser_download_url": upstream.URL + "/baseline.zip"}}
			tag := "initial-release"
			if stage.Load() == 0 {
				assets = append(assets, map[string]string{"name": "2099-03-01_delta_CVEs_at_0000.zip", "browser_download_url": upstream.URL + "/initial-delta.zip"})
			}
			if stage.Load() > 0 {
				tag = "next-release"
				if stage.Load() > 1 {
					assets = append(assets, map[string]string{"name": "2099-03-01_delta_CVEs_at_1200.zip", "browser_download_url": upstream.URL + "/delta.zip"})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": tag, "assets": assets})
			return
		}
		if r.URL.Path == "/delta.zip" && stage.Load() == 2 {
			_, _ = w.Write([]byte("gateway html instead of zip"))
			return
		}
		var data bytes.Buffer
		zw := zip.NewWriter(&data)
		entry, _ := zw.Create("CVE-2099-99111.json")
		id := "CVE-2099-99111"
		if r.URL.Path == "/delta.zip" {
			id = "CVE-2099-99112"
		}
		_, _ = entry.Write([]byte(`{"cveMetadata":{"cveId":"` + id + `","state":"PUBLISHED"}}`))
		_ = zw.Close()
		_, _ = w.Write(data.Bytes())
	}))
	defer upstream.Close()
	t.Setenv("ARTEX_CVE_RELEASE_API", upstream.URL+"/latest")
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err = m.pg.Exec(`TRUNCATE cve_sync_runs,cve_records RESTART IDENTITY; UPDATE cve_sync_state SET enabled=false,source_version='',baseline_name='',last_success=NULL,next_check=now()+interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	s := New(ctx, m, t.TempDir(), dir, t.TempDir())
	handler := s.Handler()
	token, _ := signJWT(s.jwtKey)
	request := func(method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	run := func(want string) map[string]any {
		t.Helper()
		if got := request("POST", "/api/cve/sync"); got.Code != 202 {
			t.Fatalf("queue=%d %s", got.Code, got.Body.String())
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			var got map[string]any
			_ = json.Unmarshal(request("GET", "/api/cve/sync").Body.Bytes(), &got)
			if got["status"] == want {
				return got
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("did not reach %s: %s", want, request("GET", "/api/cve/sync").Body.String())
		return nil
	}
	run("succeeded")
	stage.Store(1)
	missing := run("failed")
	if missing["source_version"] != "initial-release" {
		t.Fatalf("incomplete release advanced cursor: %v", missing)
	}
	stage.Store(2)
	malformed := run("failed")
	if malformed["source_version"] != "initial-release" {
		t.Fatalf("invalid archive advanced cursor: %v", malformed)
	}
	cacheDir := filepath.Join(dir, "content", "cve")
	oldURL := upstream.URL + "/expired.zip"
	oldDigest := sha256.Sum256([]byte(oldURL))
	oldPath := filepath.Join(cacheDir, hex.EncodeToString(oldDigest[:])+".zip")
	if err := os.WriteFile(oldPath, []byte("expired unused archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldPath+".manifest.json", []byte(`{"source_version":"old"}`), 0600); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(cacheDir, "operator-supplied.zip")
	if err := os.WriteFile(foreign, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	stage.Store(3)
	recovered := run("succeeded")
	if recovered["source_version"] != "next-release" || recovered["added"] != float64(1) {
		t.Fatalf("corrected same URL failed retry: %v", recovered)
	}
	if got := request("GET", "/api/cve?q=CVE-2099-99112"); !strings.Contains(got.Body.String(), "CVE-2099-99112") {
		t.Fatalf("recovered record absent: %s", got.Body.String())
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("unused cached archive retained: %v", err)
	}
	if _, err := os.Stat(oldPath + ".manifest.json"); err != nil {
		t.Fatalf("historical manifest removed: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("non-cache file removed: %v", err)
	}
	latestDigest := sha256.Sum256([]byte(upstream.URL + "/delta.zip"))
	latestPath := filepath.Join(cacheDir, hex.EncodeToString(latestDigest[:])+".zip")
	if _, err := os.Stat(latestPath); err != nil {
		t.Fatalf("latest recovery cache removed: %v", err)
	}
	manifests, _ := filepath.Glob(filepath.Join(dir, "content", "cve", "*.manifest.json"))
	if len(manifests) == 0 {
		t.Fatal("missing content manifests")
	}
}
