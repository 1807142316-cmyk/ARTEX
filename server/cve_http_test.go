package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCVEImportAndOfflineSearchThroughAuthenticatedAPI(t *testing.T) {
	m := newParityTestManager(t)
	defer m.Close()

	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	h := s.Handler()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}

	record := json.RawMessage(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2099-76543","state":"PUBLISHED","datePublished":"2099-01-02T03:04:05Z","dateUpdated":"2099-01-03T03:04:05Z"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"Stored cross-site scripting in Acme Portal"}],"affected":[{"vendor":"Acme","product":"Portal","versions":[{"version":"1.0","status":"affected"}]}],"references":[{"url":"https://example.test/advisory"}]},"adp":[{"references":[{"url":"https://example.test/program"}]}]}}`)
	if _, err := m.pg.Exec(`DELETE FROM cve_records WHERE cve_id='CVE-2099-76543'`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM cve_records WHERE cve_id='CVE-2099-76543'`) })
	baselineRequest := httptest.NewRequest(http.MethodGet, "/api/cve/stats", nil)
	baselineRequest.Header.Set("Authorization", "Bearer "+token)
	baselineResponse := httptest.NewRecorder()
	h.ServeHTTP(baselineResponse, baselineRequest)
	var baseline struct {
		Total  int            `json:"total"`
		States map[string]int `json:"states"`
		Years  map[string]int `json:"years"`
	}
	if err := json.Unmarshal(baselineResponse.Body.Bytes(), &baseline); err != nil || baselineResponse.Code != 200 {
		t.Fatalf("initial stats failed: %s", baselineResponse.Body.String())
	}
	request := httptest.NewRequest(http.MethodPost, "/api/cve/import", bytes.NewReader(cveMustJSON(t, map[string]any{"records": []json.RawMessage{record}, "source_version": "fixture-1"})))
	unauthenticated := httptest.NewRecorder()
	h.ServeHTTP(unauthenticated, request)
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated import status=%d body=%s", unauthenticated.Code, unauthenticated.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/api/cve/import", bytes.NewReader(cveMustJSON(t, map[string]any{"records": []json.RawMessage{record}, "source_version": "fixture-1"})))
	request.Header.Set("Authorization", "Bearer "+token)
	imported := httptest.NewRecorder()
	h.ServeHTTP(imported, request)
	if imported.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", imported.Code, imported.Body.String())
	}
	var importResult struct {
		Added    int `json:"added"`
		Modified int `json:"modified"`
	}
	if err := json.Unmarshal(imported.Body.Bytes(), &importResult); err != nil {
		t.Fatal(err)
	}
	if importResult.Added != 1 || importResult.Modified != 0 {
		t.Fatalf("unexpected import result: %+v", importResult)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/cve?q=Acme%20Portal&page=1&limit=10", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	searched := httptest.NewRecorder()
	h.ServeHTTP(searched, request)
	if searched.Code != http.StatusOK {
		t.Fatalf("search status=%d body=%s", searched.Code, searched.Body.String())
	}
	var result struct {
		Items []struct {
			CVEID       string   `json:"cve_id"`
			Description string   `json:"description"`
			Products    []string `json:"products"`
			References  []string `json:"references"`
		} `json:"items"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(searched.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 || len(result.Items) != 1 {
		t.Fatalf("unexpected offline search result: %+v", result)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/cve/import", bytes.NewReader(cveMustJSON(t, map[string]any{"records": []json.RawMessage{record}, "source_version": "fixture-1"})))
	request.Header.Set("Authorization", "Bearer "+token)
	imported = httptest.NewRecorder()
	h.ServeHTTP(imported, request)
	if imported.Code != http.StatusOK {
		t.Fatalf("idempotent import status=%d body=%s", imported.Code, imported.Body.String())
	}
	if err := json.Unmarshal(imported.Body.Bytes(), &importResult); err != nil {
		t.Fatal(err)
	}
	if importResult.Added != 0 || importResult.Modified != 0 {
		t.Fatalf("reimport was not idempotent: %+v", importResult)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/cve/stats", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	stats := httptest.NewRecorder()
	h.ServeHTTP(stats, request)
	if stats.Code != http.StatusOK {
		t.Fatalf("stats status=%d body=%s", stats.Code, stats.Body.String())
	}
	var counts struct {
		Total  int            `json:"total"`
		States map[string]int `json:"states"`
		Years  map[string]int `json:"years"`
	}
	if err := json.Unmarshal(stats.Body.Bytes(), &counts); err != nil {
		t.Fatal(err)
	}
	if counts.Total != baseline.Total+1 || counts.States["PUBLISHED"] != baseline.States["PUBLISHED"]+1 || counts.Years["2099"] != baseline.Years["2099"]+1 {
		t.Fatalf("unexpected real CVE stats: %+v", counts)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/cve?q=not-present&page=999&limit=10", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	noMatch := httptest.NewRecorder()
	h.ServeHTTP(noMatch, request)
	if noMatch.Code != http.StatusOK {
		t.Fatalf("no-match status=%d body=%s", noMatch.Code, noMatch.Body.String())
	}
	var empty struct {
		Items []json.RawMessage `json:"items"`
		Total int               `json:"total"`
	}
	if err := json.Unmarshal(noMatch.Body.Bytes(), &empty); err != nil {
		t.Fatal(err)
	}
	if empty.Total != 0 || len(empty.Items) != 0 {
		t.Fatalf("unexpected no-match page: %+v", empty)
	}

	got := result.Items[0]
	if got.CVEID != "CVE-2099-76543" || got.Description != "Stored cross-site scripting in Acme Portal" ||
		len(got.Products) != 1 || got.Products[0] != "Acme Portal" || len(got.References) != 2 {
		t.Fatalf("record fields were not retained: %+v", got)
	}
}

func cveMustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
