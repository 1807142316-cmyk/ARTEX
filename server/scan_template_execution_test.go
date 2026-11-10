package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestScanTemplateHTTPRealEngineProducesPendingFindingAndRetainsVersion(t *testing.T) {
	if os.Getenv("ARTEX_NUCLEI_PATH") == "" {
		t.Skip("set ARTEX_NUCLEI_PATH to the pinned real Nuclei executable")
	}
	m := newParityTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	do := func(method, path string, payload any, auth bool) (int, map[string]any) {
		body, _ := json.Marshal(payload)
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		if auth {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var result map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &result)
		return w.Code, result
	}
	var requests atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "GET" || r.URL.Path != "/robots.txt" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /private\n"))
	}))
	defer target.Close()
	id := fmt.Sprintf("artex-execution-%d", time.Now().UnixNano())
	task, err := m.CreateTask("template execution", "record configuration observation", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	content := fmt.Sprintf("id: %s\ninfo:\n  name: Robots availability\n  author: ARTEX\n  severity: info\n  tags: [robots]\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/robots.txt\"]\n    matchers: [{type: status, status: [200]}]\n", id)
	status, imported := do("POST", "/api/scan-templates", map[string]any{"content": content, "license": "AGPL-3.0-only", "source_version": "test-v1"}, true)
	if status != 201 {
		t.Fatalf("import status=%d result=%v", status, imported)
	}
	input := map[string]any{"template_id": id, "target": target.URL, "task_id": task.ID}
	if status, _ := do("POST", "/api/scan-template-runs", input, false); status != 401 {
		t.Fatalf("unauth status=%d", status)
	}
	status, created := do("POST", "/api/scan-template-runs", input, true)
	if status != 202 {
		t.Fatalf("run status=%d result=%v", status, created)
	}
	runID := int64(created["id"].(float64))
	path := fmt.Sprintf("/api/scan-template-runs/%d", runID)
	var run map[string]any
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		status, run = do("GET", path, nil, true)
		if status != 200 {
			t.Fatalf("get status=%d result=%v", status, run)
		}
		if run["status"] != "running" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if run["status"] != "completed" {
		t.Fatalf("run=%v", run)
	}
	if requests.Load() != 1 {
		t.Fatalf("target request count=%d want 1", requests.Load())
	}
	if run["engine_version"] != "3.4.10" || run["template_hash"] != imported["content_hash"] {
		t.Fatalf("provenance=%v", run)
	}
	matches := run["matches"].([]any)
	if len(matches) != 1 {
		t.Fatalf("matches=%v", matches)
	}
	match := matches[0].(map[string]any)
	if !bytes.Contains([]byte(match["request"].(string)), []byte("GET /robots.txt")) || !bytes.Contains([]byte(match["response"].(string)), []byte("Disallow: /private")) {
		t.Fatalf("evidence=%v", match)
	}
	findingID := int64(match["finding_id"].(float64))
	status, finding := do("GET", fmt.Sprintf("/api/exploration/findings/%d", findingID), nil, true)
	if status != 200 || finding["status"] != "pending" {
		t.Fatalf("finding status=%d result=%v", status, finding)
	}
	if run["task_id"] == nil {
		t.Fatal("task association not retained")
	}
	// Replacing the active template does not replace the executed version.
	updated := bytes.ReplaceAll([]byte(content), []byte("Robots availability"), []byte("Changed robots availability"))
	if status, _ := do("POST", "/api/scan-templates", map[string]any{"content": string(updated), "license": "AGPL-3.0-only", "source_version": "test-v2"}, true); status != 201 {
		t.Fatalf("update status=%d", status)
	}
	status, run = do("GET", path, nil, true)
	if status != 200 || run["template_hash"] != imported["content_hash"] || run["template_content"] != strings.TrimSpace(content) {
		t.Fatalf("history lost: status=%d run=%v", status, run)
	}
	if status, _ := do("GET", path, nil, false); status != 401 {
		t.Fatalf("evidence unauth status=%d", status)
	}
	status, history := do("GET", "/api/scan-template-runs?template_id="+id, nil, true)
	if status != 200 || history["total"].(float64) != 1 {
		t.Fatalf("history=%v status=%d", history, status)
	}
	listedMatch := history["items"].([]any)[0].(map[string]any)["matches"].([]any)[0].(map[string]any)
	if listedMatch["request"] != "" || listedMatch["response"] != "" {
		t.Fatal("history list exposes raw evidence")
	}
}

func TestScanTemplateHTTPReportsNoMatchAndConnectionFailure(t *testing.T) {
	if os.Getenv("ARTEX_NUCLEI_PATH") == "" {
		t.Skip("set ARTEX_NUCLEI_PATH to pinned real engine")
	}
	m := newParityTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	do := func(method, path string, payload any) (int, map[string]any) {
		body, _ := json.Marshal(payload)
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	for _, input := range []map[string]any{{"template_id": "artex-robots-index", "target": "file:///etc/passwd"}, {"template_id": "missing-template", "target": "http://127.0.0.1"}} {
		status, _ := do("POST", "/api/scan-template-runs", input)
		if status != 400 && status != 404 {
			t.Fatalf("invalid input accepted status=%d", status)
		}
	}
	target := httptest.NewServer(http.NotFoundHandler())
	for i := 0; i < 2; i++ {
		if i == 1 {
			target.Close()
		}
		status, created := do("POST", "/api/scan-template-runs", map[string]any{"template_id": "artex-robots-index", "target": target.URL})
		if status != 202 {
			t.Fatalf("create=%d %v", status, created)
		}
		path := fmt.Sprintf("/api/scan-template-runs/%.0f", created["id"].(float64))
		var run map[string]any
		for deadline := time.Now().Add(45 * time.Second); time.Now().Before(deadline); {
			_, run = do("GET", path, nil)
			if run["status"] != "running" {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if i == 0 && (run["status"] != "completed" || len(run["matches"].([]any)) != 1 || run["matches"].([]any)[0].(map[string]any)["matched"] != false) {
			t.Fatalf("no-match=%v", run)
		}
		if i == 1 && (run["status"] != "failed" || run["error"] == "") {
			t.Fatalf("connection failure=%v", run)
		}
	}
}

func TestScanTemplateHTTPRejectsIncompatibleContentAndReportsUnavailableEngine(t *testing.T) {
	m := newParityTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	do := func(path string, payload any) (int, string) {
		body, _ := json.Marshal(payload)
		r := httptest.NewRequest("POST", path, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}
	content := "id: multipledoc\ninfo: {name: Multi, severity: info}\nhttp: [{method: GET, path: [\"{{BaseURL}}/\"], matchers: [{type: status, status: [200]}]}]\n---\ncode: [{engine: sh, source: id}]\n"
	if status, body := do("/api/scan-templates", map[string]any{"content": content, "license": "AGPL-3.0-only"}); status != 400 {
		t.Fatalf("multi-document status=%d body=%s", status, body)
	}
	t.Setenv("ARTEX_NUCLEI_PATH", t.TempDir()+"/missing-nuclei")
	if status, body := do("/api/scan-template-runs", map[string]any{"template_id": "artex-robots-index", "target": "http://127.0.0.1"}); status != 503 {
		t.Fatalf("engine unavailable status=%d body=%s", status, body)
	}
}

func TestScanTemplateHTTPBoundsConcurrentRunsAndDoesNotFollowRedirects(t *testing.T) {
	if os.Getenv("ARTEX_NUCLEI_PATH") == "" {
		t.Skip("set ARTEX_NUCLEI_PATH to pinned real engine")
	}
	m := newParityTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, path string, payload any) (int, map[string]any) {
		body, _ := json.Marshal(payload)
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	var followed atomic.Int64
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Add(1); w.WriteHeader(200) }))
	defer redirectTarget.Close()
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	defer target.Close()
	var paths []string
	for i := 0; i < 2; i++ {
		status, run := do("POST", "/api/scan-template-runs", map[string]any{"template_id": "artex-robots-index", "target": target.URL})
		if status != 202 {
			close(release)
			t.Fatalf("start=%d %v", status, run)
		}
		paths = append(paths, fmt.Sprintf("/api/scan-template-runs/%.0f", run["id"].(float64)))
	}
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(15 * time.Second):
			close(release)
			t.Fatal("engine did not send request")
		}
	}
	if status, _ := do("POST", "/api/scan-template-runs", map[string]any{"template_id": "artex-robots-index", "target": target.URL}); status != 429 {
		close(release)
		t.Fatalf("third concurrent status=%d", status)
	}
	close(release)
	for _, path := range paths {
		var run map[string]any
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
			_, run = do("GET", path, nil)
			if run["status"] != "running" {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if run["status"] != "completed" {
			t.Fatalf("redirect run=%v", run)
		}
	}
	if followed.Load() != 0 {
		t.Fatalf("redirect target was contacted %d times", followed.Load())
	}
}
