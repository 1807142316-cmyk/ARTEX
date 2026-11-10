package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestScanTemplateCatalogImportAndSearchRequiresAuthentication(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		if os.Getenv("ARTEX_PG_DSN") != "" {
			t.Fatalf("configured postgres unavailable: %v", err)
		}
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	h := s.Handler()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	content := `id: artex-catalog-api-test
info:
  name: Public robots.txt availability
  author: ARTEX
  severity: info
  description: Detects whether a public robots.txt resource is available.
  reference: [https://www.rfc-editor.org/rfc/rfc9309]
  tags: [robots]
http:
  - method: GET
    path: ["{{BaseURL}}/robots.txt"]
    matchers: [{type: status, status: [200]}]
`
	_, _ = m.pg.Exec(`DELETE FROM scan_templates WHERE template_id='artex-catalog-api-test'`)
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM scan_templates WHERE template_id='artex-catalog-api-test'`) })
	body, _ := json.Marshal(map[string]any{"content": content, "source_url": "https://github.com/1807142316-cmyk/ARTEX", "source_version": "local-1", "license": "AGPL-3.0-only"})
	request := httptest.NewRequest(http.MethodPost, "/api/scan-templates", bytes.NewReader(body))
	unauthorized := httptest.NewRecorder()
	h.ServeHTTP(unauthorized, request)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/scan-templates", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	created := httptest.NewRecorder()
	h.ServeHTTP(created, request)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/api/scan-templates?q=artex-catalog-api-test", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	listed := httptest.NewRecorder()
	h.ServeHTTP(listed, request)
	if listed.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listed.Code, listed.Body.String())
	}
	var result struct {
		Items []db.ScanTemplate `json:"items"`
		Total int               `json:"total"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 || len(result.Items) != 1 || result.Items[0].ID != "artex-catalog-api-test" || result.Items[0].License != "AGPL-3.0-only" {
		t.Fatalf("catalog result=%+v", result)
	}
}
