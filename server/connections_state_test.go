package server

import (
	"fmt"
	"testing"
	"time"
)

// TestConnectionAdapterEditKeepsStateUnlessEndpointChanges: editing an adapter's
// name, enabled flag, timeout, TTL or task/asset association must not wipe the
// observed health. Only a new base_url or a new secret invalidates the previous
// probe, because only those two change what "reachable" means.
func TestConnectionAdapterEditKeepsStateUnlessEndpointChanges(t *testing.T) {
	e := newConnectionTestEnv(t)
	const secret = "{{SECRET_oq3lytdpq7w1zx9km2v4nb8r}}"
	stub := newShellStub(t, secret)
	name := fmt.Sprintf("state-%d", time.Now().UnixNano())
	adapter := e.createAdapter(t, map[string]any{
		"name": name, "kind": "http_phpcmd", "base_url": stub.url(), "secret": secret,
		"secret_ref": "state-key", "timeout_seconds": 5, "heartbeat_ttl_seconds": 60,
	})
	id := int64(adapter["id"].(float64))

	code, checked := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/check", id), nil, true)
	if code != 200 || checked["state"] != "reachable" || checked["checked_at"] == nil {
		t.Fatalf("check=%d %v", code, checked)
	}

	// Cosmetic/behavioural edits keep the recorded state and its timestamp.
	code, edited := e.call(t, "PUT", fmt.Sprintf("/api/connections/adapters/%d", id), map[string]any{
		"name": name + "-renamed", "kind": "http_phpcmd", "base_url": stub.url(), "secret_ref": "state-key",
		"timeout_seconds": 9, "heartbeat_ttl_seconds": 120, "enabled": true,
	}, true)
	if code != 200 {
		t.Fatalf("edit=%d %v", code, edited)
	}
	if edited["state"] != "reachable" {
		t.Fatalf("name/timeout edit reset state: %v", edited)
	}
	if edited["checked_at"] == nil {
		t.Fatalf("name/timeout edit cleared checked_at: %v", edited)
	}
	if edited["timeout_seconds"] != float64(9) || edited["heartbeat_ttl_seconds"] != float64(120) {
		t.Fatalf("edit did not apply fields: %v", edited)
	}

	// Disabling is an edit too: the health observation stays as recorded.
	code, disabled := e.call(t, "PUT", fmt.Sprintf("/api/connections/adapters/%d", id), map[string]any{
		"name": name + "-renamed", "kind": "http_phpcmd", "base_url": stub.url(), "secret_ref": "state-key",
		"timeout_seconds": 9, "heartbeat_ttl_seconds": 120, "enabled": false,
	}, true)
	if code != 200 || disabled["state"] != "reachable" || disabled["checked_at"] == nil {
		t.Fatalf("enable toggle reset state: %d %v", code, disabled)
	}

	// A new base_url changes the endpoint, so the old observation is void.
	other := newShellStub(t, secret)
	code, moved := e.call(t, "PUT", fmt.Sprintf("/api/connections/adapters/%d", id), map[string]any{
		"name": name + "-renamed", "kind": "http_phpcmd", "base_url": other.url(), "secret_ref": "state-key",
		"timeout_seconds": 9, "heartbeat_ttl_seconds": 120, "enabled": true,
	}, true)
	if code != 200 {
		t.Fatalf("move=%d %v", code, moved)
	}
	if moved["state"] != "unconfigured" || moved["last_error"] != "" || moved["checked_at"] != nil {
		t.Fatalf("base_url change kept stale state: %v", moved)
	}

	// A new secret invalidates the credential the probe used, so it resets too.
	code, rechecked := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/check", id), nil, true)
	if code != 200 || rechecked["state"] != "reachable" {
		t.Fatalf("recheck=%d %v", code, rechecked)
	}
	code, resealed := e.call(t, "PUT", fmt.Sprintf("/api/connections/adapters/%d", id), map[string]any{
		"name": name + "-renamed", "kind": "http_phpcmd", "base_url": other.url(),
		"secret": "{{SECRET_1t9s2dw0fa5hj6pc3uy8ze}}", "secret_ref": "state-key",
		"timeout_seconds": 9, "heartbeat_ttl_seconds": 120, "enabled": true,
	}, true)
	if code != 200 {
		t.Fatalf("reseal=%d %v", code, resealed)
	}
	if resealed["state"] != "unconfigured" {
		t.Fatalf("secret change kept stale state: %v", resealed)
	}
	// And the new credential is the one now used.
	code, wrong := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/check", id), nil, true)
	if code != 200 || wrong["state"] != "auth_failed" {
		t.Fatalf("resealed check=%d %v", code, wrong)
	}
}
