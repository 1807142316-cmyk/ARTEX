package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestFindingsHTTPFiltersPaginationAndEmptyResults(t *testing.T) {
	m := newParityTestManager(t)
	defer m.Close()

	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	marker := fmt.Sprintf("http-findings-%d", time.Now().UnixNano())
	task, err := m.CreateTask("findings HTTP filter", "exercise finding filters", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(taskID) })

	for _, finding := range []struct {
		severity string
		summary  string
	}{
		{severity: db.SeverityHigh, summary: marker + " first match"},
		{severity: db.SeverityHigh, summary: marker + " second match"},
		{severity: db.SeverityLow, summary: marker + " low match"},
	} {
		if _, err := m.pg.AddFinding(taskID, 0, marker, "searchable finding", finding.severity,
			finding.summary, "", "test", nil); err != nil {
			t.Fatal(err)
		}
	}

	request := httptest.NewRequest(http.MethodGet,
		"/api/exploration/findings?severity=high&q="+marker+"&page=1&limit=1", nil)
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated findings status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet,
		"/api/exploration/findings?severity=high&q="+marker+"&page=1&limit=1", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder = httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("filtered findings status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var page struct {
		Items    []map[string]any `json:"items"`
		Total    int              `json:"total"`
		Page     int              `json:"page"`
		PageSize int              `json:"page_size"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Total != 2 || page.Page != 1 || page.PageSize != 1 {
		t.Fatalf("filtered page did not preserve result count and pagination: %+v", page)
	}
	if page.Items[0]["severity"] != db.SeverityHigh || page.Items[0]["summary"] != marker+" second match" {
		t.Fatalf("unexpected filtered finding: %+v", page.Items[0])
	}

	request = httptest.NewRequest(http.MethodGet,
		"/api/exploration/findings?severity=critical&q="+marker+"&page=1&limit=20", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder = httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("empty findings status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	page = struct {
		Items    []map[string]any `json:"items"`
		Total    int              `json:"total"`
		Page     int              `json:"page"`
		PageSize int              `json:"page_size"`
	}{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 0 || page.Total != 0 || page.Page != 1 || page.PageSize != 20 {
		t.Fatalf("empty filtered page should be explicit and stable: %+v", page)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/exploration/findings/stats", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder = httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("finding stats status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var stats db.FindingStats
	if err := json.Unmarshal(recorder.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if stats.Total < 3 {
		t.Fatalf("finding totals should include persisted rows, got %+v", stats)
	}
}
