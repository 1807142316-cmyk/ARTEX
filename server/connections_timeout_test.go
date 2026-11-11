package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// TestConnectionTimeoutRangeAgreesAcrossValidationSchemaAndDeadline pins the
// three places the adapter timeout is expressed: the documented/accepted range
// (1-120), the schema CHECK (1-120), and the deadline the exchange actually uses
// (min(configured, 120s)). Before this the validation accepted 120s but every
// exchange was silently clamped to 30s, so the configured value was a lie.
func TestConnectionTimeoutRangeAgreesAcrossValidationSchemaAndDeadline(t *testing.T) {
	e := newConnectionTestEnv(t)
	const secret = "{{SECRET_5pqn0w8rvh2tmz6ck4ya7us}}"
	stub := newShellStub(t, secret)

	// The documented bounds are the accepted ones.
	if connectionExchangeDeadline != 120*time.Second {
		t.Fatalf("exchange deadline constant=%s, want 120s", connectionExchangeDeadline)
	}
	if connectionOperationTimeoutCap != 30*time.Second {
		t.Fatalf("per-operation cap=%s, want 30s", connectionOperationTimeoutCap)
	}

	code, created := e.call(t, "POST", "/api/connections/adapters", map[string]any{
		"name": fmt.Sprintf("timeout-max-%d", time.Now().UnixNano()), "kind": "http_phpcmd",
		"base_url": stub.url(), "secret": secret, "secret_ref": "timeout-key", "timeout_seconds": 120,
	}, true)
	if code != 201 {
		t.Fatalf("120s adapter rejected=%d %v", code, created)
	}
	if created["timeout_seconds"] != float64(120) {
		t.Fatalf("120s stored as %v", created["timeout_seconds"])
	}
	if code, _ := e.call(t, "POST", "/api/connections/adapters", map[string]any{
		"name": fmt.Sprintf("timeout-over-%d", time.Now().UnixNano()), "kind": "http_phpcmd",
		"base_url": stub.url(), "secret": secret, "secret_ref": "timeout-key", "timeout_seconds": 121,
	}, true); code != 400 {
		t.Fatalf("121s accepted=%d", code)
	}
	if code, _ := e.call(t, "POST", "/api/connections/adapters", map[string]any{
		"name": fmt.Sprintf("timeout-zero-%d", time.Now().UnixNano()), "kind": "http_phpcmd",
		"base_url": stub.url(), "secret": secret, "secret_ref": "timeout-key", "timeout_seconds": -1,
	}, true); code != 400 {
		t.Fatalf("negative timeout accepted=%d", code)
	}

	// A 120s adapter is bounded by 120s, not by the old 30s clamp, and a
	// per-operation timeout still cannot exceed its own 30s cap.
	if got := connectionExchangeTimeout(&db.ConnectionAdapter{TimeoutSeconds: 120}, 0); got != 120*time.Second {
		t.Fatalf("120s adapter deadline=%s", got)
	}
	if got := connectionExchangeTimeout(&db.ConnectionAdapter{TimeoutSeconds: 600}, 0); got != 120*time.Second {
		t.Fatalf("oversized adapter deadline=%s, want the 120s ceiling", got)
	}
	if got := connectionExchangeTimeout(&db.ConnectionAdapter{TimeoutSeconds: 120}, 500); got != 500*time.Millisecond {
		t.Fatalf("per-operation bound=%s", got)
	}
	if got := connectionExchangeTimeout(&db.ConnectionAdapter{TimeoutSeconds: 120}, 90000); got != 30*time.Second {
		t.Fatalf("per-operation ceiling=%s, want 30s", got)
	}
	if got := connectionExchangeTimeout(&db.ConnectionAdapter{TimeoutSeconds: 0}, 0); got != 10*time.Second {
		t.Fatalf("unset adapter default=%s", got)
	}
	if code, _ := e.call(t, "POST", "/api/connections/sessions/1/operations", map[string]any{
		"action": "exec", "cmd": "id", "request_id": "cap", "timeout_ms": 31000,
	}, true); code == 200 || code == 422 {
		t.Fatalf("timeout_ms above the per-operation cap was accepted: %d", code)
	}
}
