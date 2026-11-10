package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestScanTemplateRealEngineUsesTaskProxyDespiteInheritedBypass(t *testing.T) {
	if os.Getenv("ARTEX_NUCLEI_PATH") == "" {
		t.Skip("set ARTEX_NUCLEI_PATH to pinned real engine")
	}
	t.Setenv("NO_PROXY", "*")
	t.Setenv("no_proxy", "*")
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
	var routed atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/exit" {
			fmt.Fprint(w, `{"ip":"192.0.2.77"}`)
			return
		}
		if r.URL.Host != "template-target.test" {
			t.Errorf("proxy unexpected host %s", r.URL)
		}
		routed.Add(1)
		fmt.Fprint(w, "routed-template-response")
	}))
	defer proxy.Close()
	status, endpoint := do("POST", "/api/proxies", map[string]any{"name": "template-route", "url": proxy.URL, "check_url": "http://proxy-check.test/exit", "enabled": true})
	if status != 201 {
		t.Fatalf("proxy=%d %v", status, endpoint)
	}
	status, checked := do("POST", fmt.Sprintf("/api/proxies/%.0f/check", endpoint["id"].(float64)), nil)
	if status != 200 || checked["health"] != "healthy" {
		t.Fatalf("health=%d %v", status, checked)
	}
	if status, out := do("PUT", "/api/proxies/settings", map[string]any{"enabled": true}); status != 200 {
		t.Fatalf("settings=%d %v", status, out)
	}
	defer do("PUT", "/api/proxies/settings", map[string]any{"enabled": false})
	input := map[string]any{"template_id": "artex-robots-index", "target": "http://template-target.test"}
	if status, _ := do("POST", "/api/scan-template-runs", input); status != 400 {
		t.Fatalf("pool missing task status=%d", status)
	}
	task, err := m.CreateTask("template routed", "observe HTTP check", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer do("DELETE", "/api/tasks/"+task.ID, nil)
	if status, out := do("POST", "/api/tasks/"+task.ID+"/egress", map[string]any{"proxy_id": endpoint["id"]}); status != 200 {
		t.Fatalf("lease=%d %v", status, out)
	}
	input["task_id"] = task.ID
	status, created := do("POST", "/api/scan-template-runs", input)
	if status != 202 {
		t.Fatalf("start=%d %v", status, created)
	}
	path := fmt.Sprintf("/api/scan-template-runs/%.0f", created["id"].(float64))
	var run map[string]any
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		_, run = do("GET", path, nil)
		if run["status"] != "running" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if run["status"] != "completed" || routed.Load() != 1 {
		t.Fatalf("route count=%d run=%v", routed.Load(), run)
	}
	match := run["matches"].([]any)[0].(map[string]any)
	if !bytes.Contains([]byte(match["response"].(string)), []byte("routed-template-response")) {
		t.Fatalf("wrong evidence=%v", match)
	}
}
