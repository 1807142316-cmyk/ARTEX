package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestKnowledgeHTTPRequiresVerifiedPublicationAndDeduplicatesRetrieval(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	do := func(method, path string, payload any, authenticated bool) (int, map[string]any) {
		var body []byte
		if payload != nil {
			body, _ = json.Marshal(payload)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		if authenticated {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var result map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &result)
		return rec.Code, result
	}
	status, baseline := do(http.MethodGet, "/api/knowledge?q=ARTEX-WEB-SQL-PARAMETERS", nil, true)
	if status != http.StatusOK || baseline["total"].(float64) != 1 {
		t.Fatalf("authored baseline missing: status=%d result=%v", status, baseline)
	}
	seeded := baseline["items"].([]any)[0].(map[string]any)
	if seeded["verified"] != false || seeded["reviewed"] != false || seeded["published"] != false || len(seeded["body"].(string)) < 500 {
		t.Fatalf("authored baseline has no substantive draft content or fabricated decisions: %v", seeded)
	}
	code := fmt.Sprintf("KB-%d", time.Now().UnixNano())
	payload := map[string]any{
		"code": code, "category": "web", "kind": "checklist", "tier": "low",
		"summary":    "Use parameterized queries and verify server-side authorization.",
		"body":       "Review query construction and authorization checks; document evidence and remediation.",
		"source_url": "https://owasp.org/www-project-web-security-testing-guide/",
	}
	if status, _ := do(http.MethodPost, "/api/knowledge", payload, false); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated create status=%d, want 401", status)
	}
	status, created := do(http.MethodPost, "/api/knowledge", payload, true)
	if status != http.StatusCreated {
		t.Fatalf("create status=%d body=%v", status, created)
	}
	id := int64(created["id"].(float64))
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM knowledge_entries WHERE id=$1`, id) })

	status, result := do(http.MethodGet, "/api/knowledge/execution?q="+code, nil, true)
	if status != http.StatusOK || result["total"].(float64) != 0 {
		t.Fatalf("draft leaked into default retrieval: status=%d result=%v", status, result)
	}

	status, verified := do(http.MethodPost, fmt.Sprintf("/api/knowledge/%d/verification", id), map[string]any{
		"content_version": 1, "result": "passed", "evidence": "Reviewed the documented mitigation against the current entry version.",
	}, true)
	if status != http.StatusCreated || verified["verified"] != true {
		t.Fatalf("verification status=%d result=%v", status, verified)
	}
	status, blocked := do(http.MethodPost, fmt.Sprintf("/api/knowledge/%d/publish", id), nil, true)
	if status != http.StatusConflict {
		t.Fatalf("unreviewed publication status=%d result=%v", status, blocked)
	}
	status, reviewed := do(http.MethodPost, fmt.Sprintf("/api/knowledge/%d/review", id), map[string]any{"content_version": 1, "approved": true, "redacted": true, "notes": "Reusable content reviewed; target evidence is kept outside the body."}, true)
	if status != http.StatusCreated || reviewed["reviewed"] != true {
		t.Fatalf("review status=%d result=%v", status, reviewed)
	}
	status, published := do(http.MethodPost, fmt.Sprintf("/api/knowledge/%d/publish", id), nil, true)
	if status != http.StatusOK || published["published"] != true {
		t.Fatalf("publish status=%d result=%v", status, published)
	}

	status, result = do(http.MethodGet, "/api/knowledge/execution?q="+code, nil, true)
	if status != http.StatusOK || result["total"].(float64) != 1 {
		t.Fatalf("published search status=%d result=%v", status, result)
	}
	status, first := do(http.MethodPost, fmt.Sprintf("/api/knowledge/%d/retrieve", id), map[string]any{"call_id": "call-1"}, true)
	if status != http.StatusOK || first["body"] != payload["body"] || first["use_count"].(float64) != 1 {
		t.Fatalf("first retrieval status=%d result=%v", status, first)
	}
	status, retry := do(http.MethodPost, fmt.Sprintf("/api/knowledge/%d/retrieve", id), map[string]any{"call_id": "call-1"}, true)
	if status != http.StatusOK || retry["use_count"].(float64) != 1 {
		t.Fatalf("retrieval retry counted twice: status=%d result=%v", status, retry)
	}
	if _, exists := first["evidence"]; exists {
		t.Fatal("verification evidence leaked into reusable content")
	}
	status, revoked := do(http.MethodPost, fmt.Sprintf("/api/knowledge/%d/revoke", id), nil, true)
	if status != http.StatusOK || revoked["revoked"] != true || revoked["published"] != false {
		t.Fatalf("revoke status=%d result=%v", status, revoked)
	}
	status, blocked = do(http.MethodPost, fmt.Sprintf("/api/knowledge/%d/retrieve", id), map[string]any{"call_id": "call-2"}, true)
	if status != http.StatusNotFound {
		t.Fatalf("revoked retrieval status=%d result=%v", status, blocked)
	}
	status, blocked = do(http.MethodPost, fmt.Sprintf("/api/knowledge/%d/publish", id), nil, true)
	if status != http.StatusConflict {
		t.Fatalf("revoked publication status=%d result=%v", status, blocked)
	}
	status, verified = do(http.MethodPost, fmt.Sprintf("/api/knowledge/%d/verification", id), map[string]any{
		"content_version": 1, "result": "passed", "evidence": "Independent recheck after revocation; reusable content remains applicable.",
	}, true)
	if status != http.StatusCreated || verified["revoked"] != false || verified["published"] != false {
		t.Fatalf("reverification status=%d result=%v", status, verified)
	}
	status, published = do(http.MethodPost, fmt.Sprintf("/api/knowledge/%d/publish", id), nil, true)
	if status != http.StatusOK || published["published"] != true {
		t.Fatalf("republication status=%d result=%v", status, published)
	}

	status, updated := do(http.MethodPatch, fmt.Sprintf("/api/knowledge/%d", id), map[string]any{
		"body": "Updated guidance: use parameterized queries, enforce authorization, and record evidence.",
	}, true)
	if status != http.StatusOK || updated["verified"] != false || updated["published"] != false || updated["reviewed"] != false {
		t.Fatalf("substantive update retained verification/publication: status=%d result=%v", status, updated)
	}
	status, blocked = do(http.MethodPost, fmt.Sprintf("/api/knowledge/%d/verification", id), map[string]any{
		"content_version": 1, "result": "passed", "evidence": "This decision belongs to the old text.",
	}, true)
	if status != http.StatusConflict {
		t.Fatalf("stale verification accepted: status=%d result=%v", status, blocked)
	}
	status, result = do(http.MethodGet, "/api/knowledge/execution?q="+code, nil, true)
	if status != http.StatusOK || result["total"].(float64) != 0 {
		t.Fatalf("updated unverified entry leaked into retrieval: status=%d result=%v", status, result)
	}
	status, history := do(http.MethodGet, fmt.Sprintf("/api/knowledge/%d/history", id), nil, true)
	if status != http.StatusOK || len(history["versions"].([]any)) != 2 || len(history["verifications"].([]any)) != 2 {
		t.Fatalf("history status=%d result=%v", status, history)
	}
	status, imported := do(http.MethodPost, "/api/knowledge/import", map[string]any{"items": []any{payload}}, true)
	if status != http.StatusConflict {
		t.Fatalf("changed duplicate import overwrote entry: status=%d result=%v", status, imported)
	}
	status, result = do(http.MethodPatch, fmt.Sprintf("/api/knowledge/%d", id), map[string]any{"body": payload["body"]}, true)
	if status != http.StatusOK {
		t.Fatalf("restore body status=%d result=%v", status, result)
	}
	status, imported = do(http.MethodPost, "/api/knowledge/import", map[string]any{"items": []any{payload}}, true)
	if status != http.StatusOK || imported["skipped"].(float64) != 1 || imported["created"].(float64) != 0 {
		t.Fatalf("identical import not deduplicated: status=%d result=%v", status, imported)
	}
	batchCode := code + "-import"
	batch := map[string]any{"code": batchCode, "summary": "Review evidence retention", "body": "Keep per-target evidence outside reusable knowledge."}
	status, imported = do(http.MethodPost, "/api/knowledge/import", map[string]any{"items": []any{batch, batch}}, true)
	if status != http.StatusOK || imported["created"].(float64) != 1 || imported["skipped"].(float64) != 1 {
		t.Fatalf("batch import status=%d result=%v", status, imported)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM knowledge_entries WHERE code=$1`, batchCode) })
}
