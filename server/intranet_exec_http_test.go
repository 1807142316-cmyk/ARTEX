package server

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// intranetExecFixture is one task + adapter + synced session + live credential
// reference, i.e. exactly what the worker needs before intranet_exec can run.
type intranetExecFixture struct {
	e         *connectionTestEnv
	taskID    int64
	adapterID int64
	sessionID int64
}

func (f intranetExecFixture) exec(t *testing.T, taskID, sessionID int64, command string) (string, error) {
	t.Helper()
	executor := f.e.s.intranetExecutor()
	if executor == nil {
		t.Fatal("intranet executor is not wired: the adapter seam is still nil")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return executor.Exec(ctx, taskID, sessionID, command)
}

// newIntranetExecFixture builds the fixture through the authenticated HTTP API
// and asserts the intranet context actually became available, so a later
// assertion about execution cannot pass on a context the API never offered.
func newIntranetExecFixture(t *testing.T, e *connectionTestEnv, stubURL, secret, label string) intranetExecFixture {
	t.Helper()
	taskID := e.makeTask(t, "intranet exec "+label)
	name := fmt.Sprintf("intranet-%s-%d", label, time.Now().UnixNano())
	adapter := e.createAdapter(t, map[string]any{
		"name": name, "kind": "http_phpcmd", "base_url": stubURL, "secret": secret,
		"secret_ref": label + "-key", "timeout_seconds": 5, "heartbeat_ttl_seconds": 120,
		"task_id": taskID,
	})
	adapterID := int64(adapter["id"].(float64))
	code, synced := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/sync", adapterID), nil, true)
	if code != 200 {
		t.Fatalf("sync=%d %v", code, synced)
	}
	sessionID := int64(synced["session"].(map[string]any)["id"].(float64))
	// A live credential reference is part of the #10 availability rule.
	code, node := e.call(t, "POST", "/api/session-inventory/nodes", map[string]any{
		"kind": "credential_ref", "external_ref": name + "-cred", "label": "ops account",
		"scope": "host", "state": "active", "task_id": taskID,
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}, true)
	if code < 200 || code >= 300 {
		t.Fatalf("credential node=%d %v", code, node)
	}
	code, ictx := e.call(t, "GET", fmt.Sprintf("/api/tasks/%d/intranet-context", taskID), nil, true)
	if code != 200 {
		t.Fatalf("intranet context=%d %v", code, ictx)
	}
	if ictx["available"] != true || ictx["variant"] != "worker_intranet" {
		t.Fatalf("context not available: %v", ictx)
	}
	sessions, _ := ictx["sessions"].([]any)
	if len(sessions) != 1 || int64(sessions[0].(map[string]any)["id"].(float64)) != sessionID {
		t.Fatalf("context sessions=%v", ictx["sessions"])
	}
	return intranetExecFixture{e: e, taskID: taskID, adapterID: adapterID, sessionID: sessionID}
}

// TestIntranetExecRunsThroughAdapterSession is the #9/#10 seam test: the
// intranet context becomes available from a real adapter session, and
// intranet_exec produces real command output through that session while
// refusing cross-task and stale sessions. The database legs always run; the PHP
// leg additionally proves it against the real fixture when it is configured.
func TestIntranetExecRunsThroughAdapterSession(t *testing.T) {
	e := newConnectionTestEnv(t)
	secret := "fixture-key-material-9001-0123456789"
	stub := newShellStub(t, secret)
	f := newIntranetExecFixture(t, e, stub.url(), secret, "stub")

	out, err := f.exec(t, f.taskID, f.sessionID, "id")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !strings.Contains(out, "uid=") {
		t.Fatalf("exec output=%q", out)
	}

	// A non-zero exit is a real outcome, not a success with empty output: the
	// error must carry the exit code and the adapter's stderr.
	if _, err := f.exec(t, f.taskID, f.sessionID, "exit 7"); err == nil {
		t.Fatal("non-zero exit reported as success")
	} else if !strings.Contains(err.Error(), "exit 7") {
		t.Fatalf("failure does not carry the exit code: %v", err)
	}

	// Operations are recorded for the worker's calls too, with the intranet
	// request id prefix so they are distinguishable from operator actions.
	var recorded int
	if err := e.m.pg.QueryRowContext(context.Background(), `SELECT count(*) FROM connection_operations WHERE session_id=$1 AND request_id LIKE 'intranet-%'`, f.sessionID).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != 2 {
		t.Fatalf("recorded intranet operations=%d", recorded)
	}

	// Unknown, empty and cross-task calls never reach the network.
	calls := stub.calls.Load()
	if _, err := f.exec(t, f.taskID+1000, f.sessionID, "id"); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Fatalf("cross-task session accepted: %v", err)
	}
	if _, err := f.exec(t, 0, f.sessionID, "id"); err == nil {
		t.Fatal("missing task accepted")
	}
	if _, err := f.exec(t, f.taskID, f.sessionID, "   "); err == nil {
		t.Fatal("empty command accepted")
	}
	if _, err := f.exec(t, f.taskID, 922337203685477000, "id"); err == nil {
		t.Fatal("unknown session accepted")
	}
	if stub.calls.Load() != calls {
		t.Fatalf("refused calls still performed %d requests", stub.calls.Load()-calls)
	}

	// A session that goes stale mid-run is refused even though the same request
	// succeeded a moment ago.
	if _, err := e.m.pg.ExecContext(context.Background(), `UPDATE session_inventory SET heartbeat_at=now()-interval '5 minutes' WHERE id=$1`, f.sessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.exec(t, f.taskID, f.sessionID, "id"); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale session accepted: %v", err)
	}
	// Staleness also removes the task's intranet context, so the worker stops
	// offering the tool at all rather than failing per call.
	code, ictx := e.call(t, "GET", fmt.Sprintf("/api/tasks/%d/intranet-context", f.taskID), nil, true)
	if code != 200 || ictx["available"] != false || ictx["reason"] != "session_stale" {
		t.Fatalf("stale context=%d %v", code, ictx)
	}
	// Re-sync restores both the session and the availability.
	if code, synced := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/sync", f.adapterID), nil, true); code != 200 || synced["session"].(map[string]any)["effective_state"] != "connected" {
		t.Fatalf("resync=%d %v", code, synced)
	}
	if _, err := f.exec(t, f.taskID, f.sessionID, "id"); err != nil {
		t.Fatalf("exec after resync: %v", err)
	}

	// An adapter that belongs to another task must not lend its session to this
	// task's context: association is per task, not per host.
	otherTask := e.makeTask(t, "intranet exec outsider")
	name := fmt.Sprintf("outsider-%d", time.Now().UnixNano())
	outsider := e.createAdapter(t, map[string]any{"name": name, "kind": "http_phpcmd", "base_url": stub.url(), "secret": secret, "secret_ref": "outsider-key", "timeout_seconds": 5, "task_id": otherTask})
	code, outsiderSync := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/sync", int64(outsider["id"].(float64))), nil, true)
	if code != 200 {
		t.Fatalf("outsider sync=%d %v", code, outsiderSync)
	}
	outsiderSession := int64(outsiderSync["session"].(map[string]any)["id"].(float64))
	if _, err := f.exec(t, f.taskID, outsiderSession, "id"); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Fatalf("other task's session accepted: %v", err)
	}
}

// TestIntranetExecUsesRealPHPSession runs the same seam against the real PHP
// fixture. It is skipped only when the fixture is not configured; every database
// assertion in the sibling test still runs without it.
func TestIntranetExecUsesRealPHPSession(t *testing.T) {
	base := strings.TrimSpace(os.Getenv("ARTEX_TEST_PHP_URL"))
	if base == "" {
		t.Skip("ARTEX_TEST_PHP_URL not set; the PHP leg runs on the Linux host")
	}
	key := strings.TrimSpace(os.Getenv("ARTEX_TEST_PHP_KEY"))
	if key == "" {
		t.Fatal("ARTEX_TEST_PHP_KEY is required with ARTEX_TEST_PHP_URL")
	}
	e := newConnectionTestEnv(t)
	f := newIntranetExecFixture(t, e, base, key, "php")

	out, err := f.exec(t, f.taskID, f.sessionID, "id")
	if err != nil {
		t.Fatalf("real PHP exec: %v", err)
	}
	if !strings.Contains(out, "uid=") {
		t.Fatalf("real PHP output=%q", out)
	}
	if _, err := f.exec(t, f.taskID, f.sessionID, "exit 7"); err == nil || !strings.Contains(err.Error(), "exit 7") {
		t.Fatalf("real PHP failure not surfaced: %v", err)
	}
	// The bounded-timeout path must surface as a timeout, not as silence.
	started := time.Now()
	if _, err := f.exec(t, f.taskID, f.sessionID, "sleep 30"); err == nil {
		t.Fatal("real PHP sleeping command reported success")
	} else if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("real PHP timeout not surfaced: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 20*time.Second {
		t.Fatalf("timeout took %s; the adapter bound is not applying", elapsed)
	}
	// The stored record carries the real outcome for the operator's history.
	var status string
	var exitCode *int
	if err := e.m.pg.QueryRowContext(context.Background(), `SELECT status,exit_code FROM connection_operations WHERE session_id=$1 AND request_id LIKE 'intranet-%' ORDER BY id DESC LIMIT 1`, f.sessionID).Scan(&status, &exitCode); err != nil {
		t.Fatal(err)
	}
	if status != "timeout" {
		t.Fatalf("last stored status=%q", status)
	}
	var failedStatus string
	if err := e.m.pg.QueryRowContext(context.Background(), `SELECT status FROM connection_operations WHERE session_id=$1 AND request_id LIKE 'intranet-%' ORDER BY id DESC OFFSET 1 LIMIT 1`, f.sessionID).Scan(&failedStatus); err != nil {
		t.Fatal(err)
	}
	if failedStatus != "failed" {
		t.Fatalf("exit-7 status=%q", failedStatus)
	}
}
