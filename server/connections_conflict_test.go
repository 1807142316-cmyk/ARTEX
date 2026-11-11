package server

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestConnectionAdapterNameConflictIsDetectedBySQLState: a duplicate adapter name
// must produce 409 from the unique index. The check matches SQLSTATE 23505 on
// the driver error rather than searching the error string for the constraint
// name, because the message text is not part of any interface and changes with
// server version and locale.
func TestConnectionAdapterNameConflictIsDetectedBySQLState(t *testing.T) {
	e := newConnectionTestEnv(t)
	const secret = "{{SECRET_dup2kw7md9xt4rn1vq5yz8hs}}"
	stub := newShellStub(t, secret)
	name := fmt.Sprintf("dup-%d", time.Now().UnixNano())
	first := e.createAdapter(t, map[string]any{
		"name": name, "kind": "http_phpcmd", "base_url": stub.url(), "secret": secret,
		"secret_ref": "dup-key", "timeout_seconds": 5,
	})
	if first["name"] != name {
		t.Fatalf("first create=%v", first)
	}

	code, conflict := e.call(t, "POST", "/api/connections/adapters", map[string]any{
		"name": name, "kind": "http_phpcmd", "base_url": stub.url(), "secret": secret,
		"secret_ref": "dup-key", "timeout_seconds": 5,
	}, true)
	if code != 409 {
		t.Fatalf("duplicate name=%d %v", code, conflict)
	}

	// Renaming a second adapter onto a taken name is the same conflict.
	second := e.createAdapter(t, map[string]any{
		"name": name + "-b", "kind": "http_phpcmd", "base_url": stub.url(), "secret": secret,
		"secret_ref": "dup-key", "timeout_seconds": 5,
	})
	secondID := int64(second["id"].(float64))
	code, renamed := e.call(t, "PUT", fmt.Sprintf("/api/connections/adapters/%d", secondID), map[string]any{
		"name": name, "kind": "http_phpcmd", "base_url": stub.url(), "secret_ref": "dup-key", "timeout_seconds": 5,
	}, true)
	if code != 409 {
		t.Fatalf("rename onto taken name=%d %v", code, renamed)
	}

	// A missing adapter is still a 404, not a conflict: sql.ErrNoRows must not be
	// swallowed by the generic database-error branch.
	code, _ = e.call(t, "PUT", "/api/connections/adapters/999999999", map[string]any{
		"name": name + "-missing", "kind": "http_phpcmd", "base_url": stub.url(),
		"secret_ref": "dup-key", "timeout_seconds": 5,
	}, true)
	if code != 404 {
		t.Fatalf("missing adapter=%d", code)
	}

	// And the classifier itself is precise: sql.ErrNoRows and an unrelated
	// wrapped error are not conflicts.
	if connectionAdapterNameConflict(sql.ErrNoRows) {
		t.Fatal("sql.ErrNoRows classified as a name conflict")
	}
	if connectionAdapterNameConflict(errors.New("connection reset")) {
		t.Fatal("unrelated error classified as a name conflict")
	}
}
