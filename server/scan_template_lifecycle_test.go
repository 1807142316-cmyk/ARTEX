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

func TestAssociatedScanStopsOnTaskPauseAndDeletion(t *testing.T) {
	if os.Getenv("ARTEX_NUCLEI_PATH") == "" {
		t.Skip("set ARTEX_NUCLEI_PATH to pinned real engine")
	}
	for _, action := range []string{"pause", "delete"} {
		t.Run(action, func(t *testing.T) {
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
			var requests atomic.Int64
			started := make(chan struct{}, 1)
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				select {
				case started <- struct{}{}:
				default:
				}
				select {
				case <-r.Context().Done():
				case <-time.After(2 * time.Second):
				}
				_, _ = w.Write([]byte("configuration evidence"))
			}))
			defer target.Close()
			task, err := m.CreateTask("scan lifecycle", "stop related scan", nil, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			id := fmt.Sprintf("lifecycle-%d", time.Now().UnixNano())
			content := fmt.Sprintf("id: %s\ninfo: {name: Lifecycle, author: ARTEX, severity: info}\nhttp: [{method: GET, path: [\"{{BaseURL}}/first\",\"{{BaseURL}}/second\",\"{{BaseURL}}/third\"], matchers: [{type: status, status: [200]}]}]\n", id)
			if status, out := do("POST", "/api/scan-templates", map[string]any{"content": content, "license": "AGPL-3.0-only"}); status != 201 {
				t.Fatalf("import=%d %v", status, out)
			}
			status, created := do("POST", "/api/scan-template-runs", map[string]any{"template_id": id, "target": target.URL, "task_id": task.ID})
			if status != 202 {
				t.Fatalf("run=%d %v", status, created)
			}
			select {
			case <-started:
			case <-time.After(15 * time.Second):
				t.Fatal("no target request")
			}
			if action == "pause" {
				status, out := do("POST", "/api/tasks/"+task.ID+"/control", map[string]any{"action": "pause"})
				if status != 200 {
					t.Fatalf("pause=%d %v", status, out)
				}
			} else {
				status, out := do("DELETE", "/api/tasks/"+task.ID, nil)
				if status != 200 {
					t.Fatalf("delete=%d %v", status, out)
				}
			}
			path := fmt.Sprintf("/api/scan-template-runs/%.0f", created["id"].(float64))
			var run map[string]any
			for deadline := time.Now().Add(12 * time.Second); time.Now().Before(deadline); {
				_, run = do("GET", path, nil)
				if run["status"] != "running" {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if run["status"] != "interrupted" {
				t.Fatalf("task %s scan=%v", action, run)
			}
			if requests.Load() != 1 {
				t.Fatalf("task %s kept making requests: %d", action, requests.Load())
			}
			if len(run["matches"].([]any)) != 0 {
				t.Fatalf("canceled run created candidates: %v", run)
			}
			if run["template_content"] == "" {
				t.Fatal("lost execution provenance")
			}
			if action == "delete" && run["task_id"] != nil {
				t.Fatalf("deleted task FK retained: %v", run)
			}
			status, _ = do("POST", "/api/scan-template-runs", map[string]any{"template_id": id, "target": target.URL, "task_id": task.ID})
			if status != 409 && status != 404 {
				t.Fatalf("unavailable task start status=%d", status)
			}
		})
	}
}
