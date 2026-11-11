package server

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestIntranetContextIsGatedBySessionsNotCredentials pins the corrected rule: a
// task's valid session is what makes its intranet usable. The http_phpcmd
// adapter needs no credential_ref node at all, so requiring one made every
// session-only task permanently unusable. Credentials are enrichment: included
// when live, silently excluded when expired.
func TestIntranetContextIsGatedBySessionsNotCredentials(t *testing.T) {
	h := newIntranetHarness(t)

	// Live session, no credential node: available, with an empty credential list.
	sessionOnly := h.task("session without credential")
	sessionID := h.session(sessionOnly, "session-only", "connected", 3600)
	got := h.intranet(sessionOnly)
	if !got.Available || got.Reason != "" || got.Variant != "worker_intranet" {
		t.Fatalf("session-only context=%+v", got)
	}
	if len(got.Sessions) != 1 || got.Sessions[0].ID != sessionID {
		t.Fatalf("session-only sessions=%+v", got.Sessions)
	}
	if len(got.Credentials) != 0 {
		t.Fatalf("session-only credentials=%+v, want none", got.Credentials)
	}

	// No session at all stays unavailable for the honest reason.
	if blank := h.intranet(h.task("no session")); blank.Available || blank.Reason != "no_session" {
		t.Fatalf("blank context=%+v", blank)
	}

	// An expired credential is excluded from the list and does NOT gate the
	// context: the session is still usable, so the answer is available.
	withExpired := h.task("expired credential only")
	expiredSession := h.session(withExpired, "expired-cred", "connected", 3600)
	h.node(withExpired, map[string]any{
		"kind": "credential_ref", "external_ref": h.prefix + "-exp-only", "label": "old account", "scope": "host",
		"expires_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
	})
	expired := h.intranet(withExpired)
	if !expired.Available || expired.Reason != "" {
		t.Fatalf("expired-credential context=%+v", expired)
	}
	if len(expired.Sessions) != 1 || expired.Sessions[0].ID != expiredSession {
		t.Fatalf("expired-credential sessions=%+v", expired.Sessions)
	}
	if len(expired.Credentials) != 0 {
		t.Fatalf("expired credential was returned: %+v", expired.Credentials)
	}

	// A live credential and an expired one together: only the live one travels.
	mixed := h.task("mixed credentials")
	h.session(mixed, "mixed-svc", "connected", 3600)
	liveCred := h.node(mixed, map[string]any{
		"kind": "credential_ref", "external_ref": h.prefix + "-mixed-live", "label": "ops account", "scope": "host",
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	h.node(mixed, map[string]any{
		"kind": "credential_ref", "external_ref": h.prefix + "-mixed-dead", "label": "stale account", "scope": "host",
		"expires_at": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	})
	mixedCtx := h.intranet(mixed)
	if !mixedCtx.Available || len(mixedCtx.Credentials) != 1 {
		t.Fatalf("mixed credentials=%+v", mixedCtx)
	}
	if want := fmt.Sprintf("node:%d", liveCred); mixedCtx.Credentials[0].Ref != want {
		t.Fatalf("mixed credential ref=%q want %q", mixedCtx.Credentials[0].Ref, want)
	}

	// A stale-only task still reports the heartbeat reason rather than no_session.
	staleTask := h.task("stale only")
	h.session(staleTask, "stale-only", "connected", 1)
	time.Sleep(1100 * time.Millisecond)
	if stale := h.intranet(staleTask); stale.Available || stale.Reason != "session_stale" {
		t.Fatalf("stale context=%+v", stale)
	}
}

// TestIntranetContextExcludesUnusableAdapterSessions covers the second half of
// the gate: an adapter-backed session whose adapter is disabled, rejected the
// credential or is unreachable cannot execute anything, so advertising it would
// hand the worker a session that fails on first use. When that is the only
// reason nothing is available the reason says so.
func TestIntranetContextExcludesUnusableAdapterSessions(t *testing.T) {
	e := newConnectionTestEnv(t)
	const secret = "{{SECRET_kq7vm2xa9dtn5ph1y8rw4uzc}}"
	stub := newShellStub(t, secret)
	suffix := time.Now().UnixNano()
	taskID := e.makeTask(t, fmt.Sprintf("adapter intranet %d", suffix))

	intranet := func() map[string]any {
		t.Helper()
		code, body := e.call(t, "GET", fmt.Sprintf("/api/tasks/%d/intranet-context", taskID), nil, true)
		if code != 200 {
			t.Fatalf("intranet-context=%d %v", code, body)
		}
		return body
	}

	adapter := e.createAdapter(t, map[string]any{
		"name": fmt.Sprintf("intranet-%d", suffix), "kind": "http_phpcmd", "base_url": stub.url(),
		"secret": secret, "secret_ref": "intranet-key", "timeout_seconds": 5,
		"heartbeat_ttl_seconds": 60, "task_id": taskID,
	})
	adapterID := int64(adapter["id"].(float64))
	code, synced := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/sync", adapterID), nil, true)
	if code != 200 {
		t.Fatalf("sync=%d %v", code, synced)
	}
	sessionID := int64(synced["session"].(map[string]any)["id"].(float64))

	// Healthy adapter: the session is advertised (and needs no credential node).
	healthy := intranet()
	if healthy["available"] != true {
		t.Fatalf("healthy adapter context=%v", healthy)
	}
	sessions, _ := healthy["sessions"].([]any)
	if len(sessions) != 1 || int64(sessions[0].(map[string]any)["id"].(float64)) != sessionID {
		t.Fatalf("healthy sessions=%v", sessions)
	}
	if creds, _ := healthy["credentials"].([]any); len(creds) != 0 {
		t.Fatalf("adapter context invented credentials: %v", creds)
	}

	// Disabled adapter: its connected session is excluded, and the reason names
	// the integration rather than pretending the task never had a session.
	code, _ = e.call(t, "PUT", fmt.Sprintf("/api/connections/adapters/%d", adapterID), map[string]any{
		"name": fmt.Sprintf("intranet-%d", suffix), "kind": "http_phpcmd", "base_url": stub.url(),
		"secret_ref": "intranet-key", "timeout_seconds": 5, "heartbeat_ttl_seconds": 60,
		"task_id": taskID, "enabled": false,
	}, true)
	if code != 200 {
		t.Fatalf("disable=%d", code)
	}
	disabled := intranet()
	if disabled["available"] != false || disabled["reason"] != "integration_unreachable" {
		t.Fatalf("disabled adapter context=%v", disabled)
	}
	if sessions, _ := disabled["sessions"].([]any); len(sessions) != 0 {
		t.Fatalf("disabled adapter session was advertised: %v", sessions)
	}

	// Re-enabled but the credential is rejected: still excluded.
	code, _ = e.call(t, "PUT", fmt.Sprintf("/api/connections/adapters/%d", adapterID), map[string]any{
		"name": fmt.Sprintf("intranet-%d", suffix), "kind": "http_phpcmd", "base_url": stub.url(),
		"secret_ref": "intranet-key", "timeout_seconds": 5, "heartbeat_ttl_seconds": 60,
		"task_id": taskID, "enabled": true,
	}, true)
	if code != 200 {
		t.Fatalf("re-enable=%d", code)
	}
	if _, err := e.m.pg.SetConnectionAdapterState(context.Background(), adapterID, "auth_failed", "key rejected"); err != nil {
		t.Fatal(err)
	}
	if got := intranet(); got["available"] != false || got["reason"] != "integration_unreachable" {
		t.Fatalf("auth_failed adapter context=%v", got)
	}

	// An unreachable adapter is excluded the same way.
	if _, err := e.m.pg.SetConnectionAdapterState(context.Background(), adapterID, "unreachable", "connection refused"); err != nil {
		t.Fatal(err)
	}
	if got := intranet(); got["available"] != false || got["reason"] != "integration_unreachable" {
		t.Fatalf("unreachable adapter context=%v", got)
	}

	// Back to reachable: the same session is advertised again, unchanged.
	if _, err := e.m.pg.SetConnectionAdapterState(context.Background(), adapterID, "reachable", ""); err != nil {
		t.Fatal(err)
	}
	restored := intranet()
	if restored["available"] != true {
		t.Fatalf("restored context=%v", restored)
	}
	restoredSessions, _ := restored["sessions"].([]any)
	if len(restoredSessions) != 1 || int64(restoredSessions[0].(map[string]any)["id"].(float64)) != sessionID {
		t.Fatalf("restored sessions=%v", restoredSessions)
	}
	// The reason field is empty when available, never a leftover code.
	if reason, _ := restored["reason"].(string); reason != "" {
		t.Fatalf("available context kept reason %q", reason)
	}
	if restored["variant"] != "worker_intranet" {
		t.Fatalf("variant=%v", restored["variant"])
	}
}
