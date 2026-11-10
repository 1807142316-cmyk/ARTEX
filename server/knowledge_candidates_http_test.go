package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestKnowledgeCandidateHTTPCollectsReferencesAndPromotesRedactedDraft(t *testing.T) {
	m := newParityTestManager(t)
	t.Cleanup(func() { m.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	t.Cleanup(func() { cancel(); s.archiveWG.Wait(); <-s.side.done })
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	do := func(method, path string, payload any, authenticated bool) (int, map[string]any, string) {
		body, _ := json.Marshal(payload)
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		if authenticated {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out, w.Body.String()
	}
	task, err := m.CreateTask("knowledge provenance", "preserve traceable references", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	findingID, err := m.pg.AddFinding(taskID, 0, "configuration", "private-target", "low", "private summary", "credential=must-not-copy", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.DeleteFinding(findingID); _ = m.pg.DeleteTask(taskID) })
	snapshot := db.TrafficEvidenceSnapshot{SourceTrafficID: "existing-traffic", CapturedAt: 1, URL: "https://private-target/secret", Method: "GET", Status: 200, ReqHead: "Authorization: must-not-copy", RespHead: "Set-Cookie: must-not-copy", ReqHash: "reqhash", RespHash: "resphash"}
	snapshot.ID = db.TrafficSnapshotID(snapshot)
	err = m.pg.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		return db.AddFindingTrafficTx(tx, findingID, []db.PreparedTrafficEvidence{{Ref: db.TrafficRef{TrafficID: "existing-traffic", Role: "verification"}, Snapshot: snapshot}})
	})
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/exploration/findings/%d/knowledge-candidate", findingID)
	if status, _, _ := do(http.MethodPost, path, nil, false); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated collection status=%d", status)
	}
	status, candidate, raw := do(http.MethodPost, path, nil, true)
	if status != http.StatusCreated || candidate["finding_id"].(float64) != float64(findingID) || candidate["task_id"].(float64) != float64(taskID) {
		t.Fatalf("collection status=%d body=%s", status, raw)
	}
	if strings.Contains(raw, "must-not-copy") || strings.Contains(raw, "private-target") || strings.Contains(raw, "private summary") {
		t.Fatalf("raw target evidence copied to candidate: %s", raw)
	}
	refs := candidate["evidence_refs"].([]any)
	if len(refs) != 1 || refs[0].(map[string]any)["snapshot_id"] != snapshot.ID || candidate["source_hash"] == "" {
		t.Fatalf("source evidence references absent: %s", raw)
	}
	status, retry, raw := do(http.MethodPost, path, nil, true)
	if status != http.StatusOK || retry["id"] != candidate["id"] {
		t.Fatalf("collection retry duplicated candidate: status=%d body=%s", status, raw)
	}
	candidateID := int64(candidate["id"].(float64))
	promotePath := fmt.Sprintf("/api/knowledge/candidates/%d/promote", candidateID)
	input := map[string]any{"code": fmt.Sprintf("CANDIDATE-%d", findingID), "summary": "Review transport cookie configuration", "body": "Inspect cookie attributes and document remediation without target secrets."}
	status, _, raw = do(http.MethodPost, promotePath, input, true)
	if status != http.StatusBadRequest {
		t.Fatalf("promotion without redaction acknowledgement status=%d body=%s", status, raw)
	}
	input["redacted"] = true
	status, entry, raw := do(http.MethodPost, promotePath, input, true)
	if status != http.StatusCreated || entry["verified"] != false || entry["published"] != false || entry["reviewed"] != false {
		t.Fatalf("promotion status=%d body=%s", status, raw)
	}
	entryID := int64(entry["id"].(float64))
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM knowledge_entries WHERE id=$1`, entryID) })
	status, history, raw := do(http.MethodGet, fmt.Sprintf("/api/knowledge/%d/history", entryID), nil, true)
	if status != http.StatusOK || len(history["candidate_sources"].([]any)) != 1 || strings.Contains(raw, "must-not-copy") {
		t.Fatalf("promotion provenance lost or copied evidence: status=%d body=%s", status, raw)
	}
	status, retry, raw = do(http.MethodPost, promotePath, input, true)
	if status != http.StatusOK || retry["id"] != entry["id"] {
		t.Fatalf("promotion retry duplicated draft: status=%d body=%s", status, raw)
	}
	_, _ = m.pg.Exec(`UPDATE findings SET evidence='changed private evidence' WHERE id=$1`, findingID)
	status, changed, raw := do(http.MethodPost, path, nil, true)
	if status != http.StatusCreated || changed["id"] == candidate["id"] || changed["source_hash"] == candidate["source_hash"] {
		t.Fatalf("changed source content did not create distinct candidate: status=%d body=%s", status, raw)
	}
}
