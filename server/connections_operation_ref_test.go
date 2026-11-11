package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestConnectionOperationRecordsSessionSequenceAndOutputRef pins the added
// operation detail: every record carries the session sequence it ran against,
// and a non-empty output carries a content reference of the form sha256:<hex>
// so the stored output can be verified without being re-read.
func TestConnectionOperationRecordsSessionSequenceAndOutputRef(t *testing.T) {
	e := newConnectionTestEnv(t)
	const secret = "{{SECRET_ref8kw2md9xt4rn1vq5yz3hs}}"
	stub := newShellStub(t, secret)
	adapter := e.createAdapter(t, map[string]any{
		"name": fmt.Sprintf("ref-%d", time.Now().UnixNano()), "kind": "http_phpcmd",
		"base_url": stub.url(), "secret": secret, "secret_ref": "ref-key", "timeout_seconds": 5,
	})
	adapterID := int64(adapter["id"].(float64))
	code, synced := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/sync", adapterID), nil, true)
	if code != 200 {
		t.Fatalf("sync=%d %v", code, synced)
	}
	sessionID := int64(synced["session"].(map[string]any)["id"].(float64))

	var sequence int64
	if err := e.m.pg.QueryRowContext(t.Context(), `SELECT sequence FROM session_inventory WHERE id=$1`, sessionID).Scan(&sequence); err != nil {
		t.Fatal(err)
	}

	path := fmt.Sprintf("/api/connections/sessions/%d/operations", sessionID)
	requestID := fmt.Sprintf("ref-%d", time.Now().UnixNano())
	code, created := e.call(t, "POST", path, map[string]any{
		"action": "exec", "argv": []string{"/bin/echo", "artex-ok"}, "request_id": requestID,
	}, true)
	if code != 200 {
		t.Fatalf("exec=%d %v", code, created)
	}

	// JSON exposes both fields.
	seqValue, ok := created["session_sequence"]
	if !ok || seqValue == nil {
		t.Fatalf("operation JSON has no session_sequence: %v", created)
	}
	if int64(seqValue.(float64)) != sequence {
		t.Fatalf("session_sequence=%v want %d", seqValue, sequence)
	}
	outputRef, _ := created["output_ref"].(string)
	wantHash := sha256.Sum256([]byte("artex-ok\n"))
	wantRef := "sha256:" + hex.EncodeToString(wantHash[:])
	if outputRef != wantRef {
		t.Fatalf("output_ref=%q want %q", outputRef, wantRef)
	}

	// And the row itself carries them, for readers that never touch the API.
	row, found := readOperation(t, e, sessionID, requestID)
	if !found {
		t.Fatal("operation row missing")
	}
	if row.SessionSequence == nil || *row.SessionSequence != sequence {
		t.Fatalf("stored session_sequence=%v want %d", row.SessionSequence, sequence)
	}
	if row.OutputRef == nil || *row.OutputRef != wantRef {
		t.Fatalf("stored output_ref=%v want %q", row.OutputRef, wantRef)
	}

	// An operation with no output has no reference: an empty hash would imply
	// there is output to verify.
	emptyID := fmt.Sprintf("ref-empty-%d", time.Now().UnixNano())
	code, empty := e.call(t, "POST", path, map[string]any{
		"action": "exec", "argv": []string{"/bin/sh", "-c", "exit 7"}, "request_id": emptyID,
	}, true)
	if code != 200 || empty["status"] != "failed" {
		t.Fatalf("empty exec=%d %v", code, empty)
	}
	if ref, _ := empty["output_ref"].(string); ref != "" {
		t.Fatalf("empty output got a reference: %q", ref)
	}
	emptyRow, found := readOperation(t, e, sessionID, emptyID)
	if !found {
		t.Fatal("empty operation row missing")
	}
	if emptyRow.OutputRef != nil {
		t.Fatalf("stored empty output_ref=%v", *emptyRow.OutputRef)
	}
	if emptyRow.SessionSequence == nil || *emptyRow.SessionSequence != sequence {
		t.Fatalf("empty operation lost its sequence: %v", emptyRow.SessionSequence)
	}

	// A refused capability is recorded too, and also carries the sequence.
	unsupportedID := fmt.Sprintf("ref-unsupported-%d", time.Now().UnixNano())
	code, unsupported := e.call(t, "POST", path, map[string]any{
		"action": "upload", "request_id": unsupportedID,
	}, true)
	if code != 422 {
		t.Fatalf("unsupported=%d", code)
	}
	if int64(unsupported["session_sequence"].(float64)) != sequence {
		t.Fatalf("unsupported session_sequence=%v", unsupported["session_sequence"])
	}

	// The paginated operation history returns both fields for every record.
	code, history := e.call(t, "GET", path+"?limit=100", nil, true)
	if code != 200 {
		t.Fatalf("history=%d %v", code, history)
	}
	if !strings.Contains(connectionJSON(history), "output_ref") || !strings.Contains(connectionJSON(history), "session_sequence") {
		t.Fatalf("operation history missing the new fields")
	}
	items, _ := history["items"].([]any)
	if len(items) == 0 {
		t.Fatal("operation history empty")
	}
	for _, raw := range items {
		row := raw.(map[string]any)
		if _, ok := row["session_sequence"]; !ok {
			t.Fatalf("history row has no session_sequence: %v", row)
		}
		if _, ok := row["output_ref"]; !ok {
			t.Fatalf("history row has no output_ref: %v", row)
		}
	}
}
