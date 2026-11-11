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
	"testing"
	"time"

	"github.com/Autumn-27/artex/scantemplate"
)

func TestOfficialTemplateSnapshotHTTPRunsContentMatchersAndExtractors(t *testing.T) {
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
	status, catalog := do("GET", "/api/scan-templates?q=nginx-version", nil)
	if status != 200 || catalog["total"] != float64(1) {
		t.Fatalf("official snapshot absent status=%d result=%v", status, catalog)
	}
	template := catalog["items"].([]any)[0].(map[string]any)
	if template["license"] != "MIT" || template["source_version"] != "13f9bc679405927b7f78eb5dfd3e7260ed3d40f3" || !strings.Contains(template["source_url"].(string), "http/technologies/nginx/nginx-version.yaml") {
		t.Fatalf("missing upstream provenance: %v", template)
	}
	_, bundled, err := scantemplate.OfficialBundle()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := m.PG().ImportScanTemplateBundle(context.Background(), bundled, false); err != nil {
			t.Error(err)
		}
	}()
	beforeHash := template["content_hash"]
	bad := strings.Replace(template["content"].(string), "'nginx/[0-9.]+'", "'['", 1)
	if status, out := do("POST", "/api/scan-templates", map[string]any{"content": bad, "license": "MIT", "source_version": "invalid-update"}); status != 400 {
		t.Fatalf("bad regex accepted status=%d result=%v", status, out)
	}
	_, after := do("GET", "/api/scan-templates?q=nginx-version", nil)
	if after["items"].([]any)[0].(map[string]any)["content_hash"] != beforeHash {
		t.Fatal("invalid update replaced usable template")
	}
	var savedRun map[string]any
	for _, test := range []struct {
		id, header, body string
		matched          bool
		extracted        string
	}{
		{"nginx-version", "nginx/1.24.0", "<html>nginx</html>", true, "nginx/1.24.0"},
		{"nginx-version", "Apache", "nginx/1.24.0", false, ""},
		{"default-nginx-page", "test-server", "<title>Welcome to nginx!</title>", true, ""},
		{"angular-detect", "test-server", `<app-root ng-version="18.2.0"></app-root>`, true, "18.2.0"},
		{"apache-detect", "Apache/2.4.60", "<html>Apache</html>", true, "Apache/2.4.60"},
	} {
		t.Run(test.id+test.header, func(t *testing.T) {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Server", test.header)
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, test.body)
			}))
			defer target.Close()
			status, created := do("POST", "/api/scan-template-runs", map[string]any{"template_id": test.id, "target": target.URL})
			if status != 202 {
				t.Fatalf("start=%d %v", status, created)
			}
			var run map[string]any
			for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
				_, run = do("GET", fmt.Sprintf("/api/scan-template-runs/%.0f", created["id"].(float64)), nil)
				if run["status"] != "running" {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if run["status"] != "completed" {
				t.Fatalf("run=%v", run)
			}
			matches := run["matches"].([]any)
			if len(matches) != 1 || matches[0].(map[string]any)["matched"] != test.matched {
				t.Fatalf("result=%v", matches)
			}
			if test.extracted != "" {
				data, _ := json.Marshal(matches[0])
				if !bytes.Contains(data, []byte(test.extracted)) {
					t.Fatalf("missing extractor value %s: %s", test.extracted, data)
				}
			}
			if savedRun == nil {
				savedRun = run
			}
		})
	}
	if savedRun == nil {
		t.Fatal("no completed official run was retained")
	}
	status, updated := do("POST", "/api/scan-templates", map[string]any{
		"content": template["content"].(string) + "\n# local reviewed revision\n",
		"license": "MIT", "source_url": template["source_url"], "source_version": "local-reviewed-revision",
	})
	if status != http.StatusCreated || updated["content_hash"] == beforeHash {
		t.Fatalf("new revision not saved status=%d result=%v", status, updated)
	}
	if err := m.PG().SeedScanTemplates(ctx); err != nil {
		t.Fatal(err)
	}
	_, reseeded := do("GET", "/api/scan-templates?q=nginx-version", nil)
	if reseeded["items"].([]any)[0].(map[string]any)["content_hash"] != updated["content_hash"] {
		t.Fatal("startup seed overwrote a local revision")
	}
	invalidBatch := append([]scantemplate.BundledTemplate(nil), bundled...)
	invalidBatch[len(invalidBatch)-1].Content += "\x00"
	if err := m.PG().ImportScanTemplateBundle(ctx, invalidBatch, false); err == nil {
		t.Fatal("database accepted an invalid batch")
	}
	_, rolledBack := do("GET", "/api/scan-templates?q=nginx-version", nil)
	if rolledBack["items"].([]any)[0].(map[string]any)["content_hash"] != updated["content_hash"] {
		t.Fatal("failed batch partially replaced the active catalog")
	}
	_, history := do("GET", fmt.Sprintf("/api/scan-template-runs/%.0f", savedRun["id"].(float64)), nil)
	if history["template_hash"] != beforeHash || history["template_content"] != template["content"] || history["source_version"] != template["source_version"] {
		t.Fatalf("template update altered historical content: %v", history)
	}
	oldMatches, _ := json.Marshal(savedRun["matches"])
	newMatches, _ := json.Marshal(history["matches"])
	if !bytes.Equal(oldMatches, newMatches) {
		t.Fatal("template update altered historical request/response evidence")
	}
}
