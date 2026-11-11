package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// This opt-in test reads an already imported official corpus through HTTP. It
// never imports records, clears tables, or changes synchronization settings.
func TestCVEFullCorpusAuthenticatedHTTPAcceptance(t *testing.T) {
	expected, err := strconv.Atoi(os.Getenv("ARTEX_CVE_ACCEPTANCE_COUNT"))
	if err != nil || expected < 1 {
		t.Skip("set ARTEX_CVE_ACCEPTANCE_COUNT to the positive expected full-corpus count")
	}
	for _, name := range []string{"ARTEX_LLM_PROVIDER", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"} {
		t.Setenv(name, "")
	}
	m := newParityTestManager(t)
	defer m.Close()
	// A canceled service context prevents background synchronization and task
	// execution while the HTTP requests retain their own live request contexts.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	handler := s.Handler()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(path string, authenticated bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if authenticated {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/api/cve/stats", "/api/cve?q=CVE-2021-44228"} {
		if got := request(path, false); got.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s: status=%d body=%s", path, got.Code, got.Body)
		}
	}
	statsResponse := request("/api/cve/stats", true)
	var stats db.CVEStats
	if err := json.Unmarshal(statsResponse.Body.Bytes(), &stats); err != nil || statsResponse.Code != http.StatusOK {
		t.Fatalf("full-corpus statistics: status=%d body=%s error=%v", statsResponse.Code, statsResponse.Body, err)
	}
	if stats.Total != expected || stats.States["PUBLISHED"] < 1 || stats.States["REJECTED"] < 1 || stats.Years["2021"] < 1 {
		t.Fatalf("full-corpus count/state/year mismatch: expected=%d stats=%+v", expected, stats)
	}
	stateTotal, yearTotal := 0, 0
	for state, count := range stats.States {
		if (state != "PUBLISHED" && state != "REJECTED") || count < 1 {
			t.Fatalf("invalid state aggregate: %q=%d", state, count)
		}
		stateTotal += count
	}
	for year, count := range stats.Years {
		number, err := strconv.Atoi(year)
		if err != nil || len(year) != 4 || number < 1000 || count < 1 {
			t.Fatalf("invalid year aggregate: %q=%d", year, count)
		}
		yearTotal += count
	}
	// Records without datePublished are deliberately absent from year buckets.
	if stateTotal != expected || yearTotal < 1 || yearTotal > expected {
		t.Fatalf("inconsistent aggregates: total=%d states=%d dated=%d", expected, stateTotal, yearTotal)
	}
	search := func(query string, pageNumber, limit int) db.CVEPage {
		t.Helper()
		response := request("/api/cve?q="+url.QueryEscape(query)+"&page="+strconv.Itoa(pageNumber)+"&limit="+strconv.Itoa(limit), true)
		var page db.CVEPage
		if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || response.Code != http.StatusOK {
			t.Fatalf("full-corpus search %q: status=%d body=%s error=%v", query, response.Code, response.Body, err)
		}
		if page.Total < 1 || len(page.Items) < 1 || page.Page != pageNumber || page.Limit != limit {
			t.Fatalf("full-corpus search %q returned no usable page: %+v", query, page)
		}
		return page
	}
	var record *db.CVERecord
	const identifierPageSize, maxIdentifierPages = 100, 20
	searched, matches := 0, 0
	// Identifier text also matches descriptions and references, so newer related
	// CVEs can sort ahead of the original record. Follow bounded public pages.
	for pageNumber := 1; pageNumber <= maxIdentifierPages; pageNumber++ {
		page := search("CVE-2021-44228", pageNumber, identifierPageSize)
		matches = page.Total
		searched += len(page.Items)
		for index := range page.Items {
			if page.Items[index].ID == "CVE-2021-44228" {
				record = &page.Items[index]
				break
			}
		}
		if record != nil || pageNumber*identifierPageSize >= page.Total {
			break
		}
	}
	if record == nil {
		t.Fatalf("official CVE-2021-44228 record not found after reading %d of %d search matches (limit %d pages)", searched, matches, maxIdentifierPages)
	}
	if record.State != "PUBLISHED" || !strings.Contains(strings.ToLower(record.Description), "log4j") || len(record.Products) == 0 || len(record.References) == 0 || strings.TrimSpace(record.SourceVersion) == "" {
		t.Fatalf("official Log4Shell metadata/source was not retained: %+v", record)
	}
	if digest, err := hex.DecodeString(record.ContentHash); err != nil || len(digest) != 32 {
		t.Fatalf("official record content hash is not SHA-256: %q", record.ContentHash)
	}
	var raw struct {
		DataVersion string `json:"dataVersion"`
		Metadata    struct {
			ID    string `json:"cveId"`
			State string `json:"state"`
		} `json:"cveMetadata"`
		Containers map[string]json.RawMessage `json:"containers"`
	}
	if err := json.Unmarshal(record.Raw, &raw); err != nil || raw.Metadata.ID != record.ID || raw.Metadata.State != record.State || raw.DataVersion == "" || len(raw.Containers["cna"]) == 0 {
		t.Fatalf("official raw record was not retained: id=%s error=%v raw=%s", record.ID, err, record.Raw)
	}
	for _, query := range []string{"Apache Log4j", "log4j-core", "cross-site scripting"} {
		page := search(query, 1, 10)
		t.Logf("official corpus search %q: total=%d first=%s", query, page.Total, page.Items[0].ID)
	}
	t.Logf("official corpus accepted through authenticated HTTP: total=%d published=%d rejected=%d dated=%d Log4Shell-source=%s", stats.Total, stats.States["PUBLISHED"], stats.States["REJECTED"], yearTotal, record.SourceVersion)
}
