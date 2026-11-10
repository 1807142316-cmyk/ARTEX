package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/db"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCVESyncThroughAuthenticatedAPIKeepsOfflineCorpusAfterFailure(t *testing.T) {
	if _, _, err := db.DSN(); err != nil {
		t.Skipf("PostgreSQL DSN not configured: %v", err)
	}
	var generation atomic.Int32
	var sourceFailed atomic.Bool
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sourceFailed.Load() {
			http.Error(w, "source unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/latest" {
			gen := generation.Load()
			_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": fmt.Sprintf("release-%d", gen), "assets": []map[string]any{
				{"name": fmt.Sprintf("2099-01-%02d_all_CVEs_at_midnight.zip", 1+gen/2), "browser_download_url": upstream.URL + fmt.Sprintf("/baseline-%d.zip", gen/2)},
				{"name": fmt.Sprintf("2099-01-01_delta_CVEs_at_%d.zip", gen), "browser_download_url": upstream.URL + fmt.Sprintf("/delta-%d.zip", gen)},
			}})
			return
		}
		var body bytes.Buffer
		zw := zip.NewWriter(&body)
		f, _ := zw.Create("cves/2099/CVE-2099-88111.json")
		state, description := "PUBLISHED", "CVE sync baseline product alpha"
		if strings.Contains(r.URL.Path, "delta-1") || generation.Load() >= 2 {
			state, description = "REJECTED", "Withdrawn by source"
		}
		_, _ = fmt.Fprintf(f, `{"dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2099-88111","state":%q},"containers":{"cna":{"descriptions":[{"lang":"en","value":%q}]}}}`, state, description)
		if strings.Contains(r.URL.Path, "delta-1") || generation.Load() >= 2 {
			f, _ = zw.Create("CVE-2099-88112.json")
			_, _ = f.Write([]byte(`{"cveMetadata":{"cveId":"CVE-2099-88112","state":"PUBLISHED"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"New delta record"}],"affected":[{"vendor":"Acme","product":"Portal","modules":["transport-subsystem"]}]}}}`))
		}
		_ = zw.Close()
		_, _ = w.Write(body.Bytes())
	}))
	defer upstream.Close()
	t.Setenv("ARTEX_CVE_RELEASE_API", upstream.URL+"/latest")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	// Dedicated test DB. These metadata tables contain only this feature's state.
	if _, err = m.pg.Exec(`TRUNCATE cve_sync_runs,cve_records RESTART IDENTITY`); err != nil {
		t.Fatal(err)
	}
	if _, err = m.pg.Exec(`UPDATE cve_sync_state SET enabled=false,source_version='' ,baseline_name='',last_success=NULL,next_check=now()+interval '1 hour' WHERE id=true`); err != nil {
		t.Fatal(err)
	}
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	h := s.Handler()
	token, _ := signJWT(s.jwtKey)
	request := func(method, path, body string, auth bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if auth {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if got := request(http.MethodPost, "/api/cve/sync", "", false); got.Code != 401 {
		t.Fatalf("unauthorized=%d", got.Code)
	}
	if got := request(http.MethodPut, "/api/cve/sync", `{"enabled":false,"interval_minutes":60}`, true); got.Code != 200 {
		t.Fatalf("settings=%d %s", got.Code, got.Body.String())
	}
	wait := func(want string) map[string]any {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			got := request(http.MethodGet, "/api/cve/sync", "", true)
			var status map[string]any
			_ = json.Unmarshal(got.Body.Bytes(), &status)
			if status["status"] == want {
				return status
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("sync did not reach %s: %s", want, request(http.MethodGet, "/api/cve/sync", "", true).Body.String())
		return nil
	}
	if got := request(http.MethodPost, "/api/cve/sync", "", true); got.Code != 202 {
		t.Fatalf("start=%d %s", got.Code, got.Body.String())
	}
	first := wait("succeeded")
	if first["source_version"] != "release-0" || first["added"] != float64(1) {
		t.Fatalf("baseline status=%v", first)
	}
	generation.Store(1)
	if got := request(http.MethodPost, "/api/cve/sync", "", true); got.Code != 202 {
		t.Fatalf("delta start=%d %s", got.Code, got.Body.String())
	}
	second := wait("succeeded")
	if second["source_version"] != "release-1" || second["added"] != float64(1) || second["modified"] != float64(1) {
		t.Fatalf("delta status=%v", second)
	}
	got := request(http.MethodGet, "/api/cve?q=CVE-2099-88111", "", true)
	if got.Code != 200 || !strings.Contains(got.Body.String(), `"state":"REJECTED"`) {
		t.Fatalf("rejection not synced=%s", got.Body.String())
	}
	component := request(http.MethodGet, "/api/cve?q=transport-subsystem", "", true)
	if !strings.Contains(component.Body.String(), "CVE-2099-88112") {
		t.Fatalf("component not searchable: %s", component.Body.String())
	}
	if got := request(http.MethodPost, "/api/cve/sync", "", true); got.Code != 202 {
		t.Fatalf("repeat start=%d", got.Code)
	}
	unchanged := wait("succeeded")
	if unchanged["added"] != float64(0) || unchanged["modified"] != float64(0) {
		t.Fatalf("unchanged release inflated counts: %v", unchanged)
	}
	generation.Store(2)
	if got := request(http.MethodPost, "/api/cve/sync", "", true); got.Code != 202 {
		t.Fatalf("reconciliation start=%d", got.Code)
	}
	reconciled := wait("succeeded")
	if reconciled["baseline_name"] != "2099-01-02_all_CVEs_at_midnight.zip" {
		t.Fatalf("missed daily baseline not reconciled: %v", reconciled)
	}
	sourceFailed.Store(true)
	if got := request(http.MethodPost, "/api/cve/sync", "", true); got.Code != 202 {
		t.Fatalf("failure start=%d %s", got.Code, got.Body.String())
	}
	failed := wait("failed")
	if failed["source_version"] != "release-2" || failed["last_success"] == nil || failed["last_error"] == "" {
		t.Fatalf("failed status lost committed cursor=%v", failed)
	}
	got = request(http.MethodGet, "/api/cve?q=New%20delta%20record", "", true)
	if got.Code != 200 || !strings.Contains(got.Body.String(), "CVE-2099-88112") {
		t.Fatalf("offline corpus unavailable=%s", got.Body.String())
	}
}

func TestCVESyncResumesQueuedWorkAfterCancellationAndRejectsConcurrentStart(t *testing.T) {
	if _, _, err := db.DSN(); err != nil {
		t.Skipf("PostgreSQL DSN not configured: %v", err)
	}
	entered := make(chan struct{}, 1)
	var blocked atomic.Bool
	blocked.Store(true)
	var source *httptest.Server
	source = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest" {

			_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": "recovered-release", "assets": []map[string]string{{"name": "2099-02-01_all_CVEs_at_midnight.zip", "browser_download_url": source.URL + "/baseline.zip"}, {"name": "2099-02-01_delta_CVEs_at_1200.zip", "browser_download_url": source.URL + "/delta.zip"}}})
			return
		}
		if r.URL.Path == "/delta.zip" {
			select {
			case entered <- struct{}{}:
			default:
			}
			if blocked.Load() {
				<-r.Context().Done()
				return
			}
		}
		var b bytes.Buffer
		zw := zip.NewWriter(&b)
		f, _ := zw.Create("CVE-2099-88113.json")
		id := "CVE-2099-88113"
		if r.URL.Path == "/delta.zip" {
			id = "CVE-2099-88114"
		}
		_, _ = fmt.Fprintf(f, `{"cveMetadata":{"cveId":%q,"state":"PUBLISHED"}}`, id)
		_ = zw.Close()
		_, _ = w.Write(b.Bytes())
	}))
	defer source.Close()
	t.Setenv("ARTEX_CVE_RELEASE_API", source.URL+"/latest")
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err = m.pg.Exec(`TRUNCATE cve_sync_runs,cve_records RESTART IDENTITY; UPDATE cve_sync_state SET enabled=true,source_version='',baseline_name='',last_success=NULL,next_check=now()-interval '1 minute'`); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	s := New(ctx, m, t.TempDir(), dir, keyDir)
	h := s.Handler()
	token, _ := signJWT(s.jwtKey)
	request := func(handler http.Handler, method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream not reached")
	}
	progress := request(h, "GET", "/api/cve/sync")
	if !strings.Contains(progress.Body.String(), `"checkpoint":1`) {
		t.Fatalf("committed batch not visible: %s", progress.Body.String())
	}
	if got := request(h, "POST", "/api/cve/sync"); got.Code != 409 {
		t.Fatalf("duplicate queue=%d %s", got.Code, got.Body.String())
	}
	cancel()
	blocked.Store(false)
	nextCtx, nextCancel := context.WithCancel(context.Background())
	defer nextCancel()
	next := New(nextCtx, m, t.TempDir(), dir, keyDir)
	nextHandler := next.Handler()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got := request(nextHandler, "GET", "/api/cve/sync")
		if strings.Contains(got.Body.String(), `"status":"succeeded"`) {
			if !strings.Contains(got.Body.String(), `"added":2`) {
				t.Fatalf("restart duplicated or skipped committed batch: %s", got.Body.String())
			}
			found := request(nextHandler, "GET", "/api/cve?q=CVE-2099-88114")
			if !strings.Contains(found.Body.String(), "CVE-2099-88114") {
				t.Fatalf("resumed record missing: %s", found.Body.String())
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("restart failed to resume: %s", request(nextHandler, "GET", "/api/cve/sync").Body.String())
}
