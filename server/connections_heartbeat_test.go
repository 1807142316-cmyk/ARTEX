package server

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestConnectionHeartbeatSweepRefreshesEnabledAdaptersOnly drives the background
// sweep directly (no ticker, no sleeps beyond what the refresh needs): an enabled
// adapter's session heartbeat advances and stays connected, a disabled adapter's
// session is left exactly as it was and is not even probed.
func TestConnectionHeartbeatSweepRefreshesEnabledAdaptersOnly(t *testing.T) {
	e := newConnectionTestEnv(t)
	const secret = "{{SECRET_hb4mzx9q2wv7tn5ry1ke83dp}}"
	enabledStub := newShellStub(t, secret)
	disabledStub := newShellStub(t, secret)
	suffix := time.Now().UnixNano()

	enabled := e.createAdapter(t, map[string]any{
		"name": fmt.Sprintf("hb-on-%d", suffix), "kind": "http_phpcmd", "base_url": enabledStub.url(),
		"secret": secret, "secret_ref": "hb-on", "timeout_seconds": 5, "heartbeat_ttl_seconds": 60,
	})
	disabled := e.createAdapter(t, map[string]any{
		"name": fmt.Sprintf("hb-off-%d", suffix), "kind": "http_phpcmd", "base_url": disabledStub.url(),
		"secret": secret, "secret_ref": "hb-off", "timeout_seconds": 5, "heartbeat_ttl_seconds": 60,
	})

	// Both start connected, then the second one is disabled (it keeps its session
	// row — that is the point: the sweep must skip it, not delete it).
	var enabledSession, disabledSession int64
	for _, pair := range []struct {
		id  int64
		out *int64
	}{{int64(enabled["id"].(float64)), &enabledSession}, {int64(disabled["id"].(float64)), &disabledSession}} {
		code, synced := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/sync", pair.id), nil, true)
		if code != 200 {
			t.Fatalf("sync=%d %v", code, synced)
		}
		*pair.out = int64(synced["session"].(map[string]any)["id"].(float64))
	}
	code, _ := e.call(t, "PUT", fmt.Sprintf("/api/connections/adapters/%d", int64(disabled["id"].(float64))), map[string]any{
		"name": fmt.Sprintf("hb-off-%d", suffix), "kind": "http_phpcmd", "base_url": disabledStub.url(),
		"secret_ref": "hb-off", "timeout_seconds": 5, "heartbeat_ttl_seconds": 60, "enabled": false,
	}, true)
	if code != 200 {
		t.Fatalf("disable=%d", code)
	}

	// Age both heartbeats so a refresh is observable rather than a same-second
	// no-op.
	if _, err := e.m.pg.ExecContext(context.Background(), `UPDATE session_inventory SET heartbeat_at=now()-interval '20 seconds' WHERE id = ANY($1)`, []int64{enabledSession, disabledSession}); err != nil {
		t.Fatal(err)
	}
	readHeartbeat := func(id int64) time.Time {
		t.Helper()
		var at time.Time
		if err := e.m.pg.QueryRowContext(context.Background(), `SELECT heartbeat_at FROM session_inventory WHERE id=$1`, id).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	beforeEnabled, beforeDisabled := readHeartbeat(enabledSession), readHeartbeat(disabledSession)
	enabledCalls, disabledCalls := enabledStub.calls.Load(), disabledStub.calls.Load()

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.s.connectionHeartbeatSweep(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("heartbeat sweep did not finish")
	}

	if got := readHeartbeat(enabledSession); !got.After(beforeEnabled) {
		t.Fatalf("enabled adapter heartbeat not refreshed: before=%s after=%s", beforeEnabled, got)
	}
	if got := readHeartbeat(disabledSession); !got.Equal(beforeDisabled) {
		t.Fatalf("disabled adapter session was touched: before=%s after=%s", beforeDisabled, got)
	}
	if enabledStub.calls.Load() <= enabledCalls {
		t.Fatal("enabled adapter was not probed")
	}
	if disabledStub.calls.Load() != disabledCalls {
		t.Fatalf("disabled adapter was probed %d times", disabledStub.calls.Load()-disabledCalls)
	}

	// The refreshed session is still connected, with no synthetic disconnect.
	var state, reason string
	if err := e.m.pg.QueryRowContext(context.Background(), `SELECT state,disconnect_reason FROM session_inventory WHERE id=$1`, enabledSession).Scan(&state, &reason); err != nil {
		t.Fatal(err)
	}
	if state != "connected" || reason != "" {
		t.Fatalf("swept session state=%q reason=%q", state, reason)
	}

	// A sweep that observes a dead shell records the disconnect through the same
	// inventory path the manual sync uses.
	enabledStub.deny.Store(true)
	e.s.connectionHeartbeatSweep(context.Background())
	if err := e.m.pg.QueryRowContext(context.Background(), `SELECT state,disconnect_reason FROM session_inventory WHERE id=$1`, enabledSession).Scan(&state, &reason); err != nil {
		t.Fatal(err)
	}
	if state != "disconnected" || reason == "" {
		t.Fatalf("failed sweep state=%q reason=%q", state, reason)
	}

	// The sweep must never overlap itself: while one sweep holds the guard, a
	// second call returns without probing anything.
	callsBefore := enabledStub.calls.Load()
	e.s.connections.heartbeatActive.Store(true)
	e.s.connectionHeartbeatSweep(context.Background())
	e.s.connections.heartbeatActive.Store(false)
	if enabledStub.calls.Load() != callsBefore {
		t.Fatal("an overlapping sweep ran while another was in flight")
	}
}

// TestConnectionHeartbeatIntervalHonoursSettingAndMinimum covers the schedule:
// the default is 60s and a configured value below 15s is raised to 15s.
func TestConnectionHeartbeatIntervalHonoursSettingAndMinimum(t *testing.T) {
	e := newConnectionTestEnv(t)
	if got := e.s.connectionHeartbeatInterval(); got != 60*time.Second {
		t.Fatalf("default interval=%s", got)
	}
	if err := e.m.pg.SetSetting(settingConnectionHeartbeat, "30"); err != nil {
		t.Fatal(err)
	}
	if got := e.s.connectionHeartbeatInterval(); got != 30*time.Second {
		t.Fatalf("configured interval=%s", got)
	}
	if err := e.m.pg.SetSetting(settingConnectionHeartbeat, "5"); err != nil {
		t.Fatal(err)
	}
	if got := e.s.connectionHeartbeatInterval(); got != 15*time.Second {
		t.Fatalf("interval below the floor=%s, want 15s", got)
	}
	if err := e.m.pg.SetSetting(settingConnectionHeartbeat, "not-a-number"); err != nil {
		t.Fatal(err)
	}
	if got := e.s.connectionHeartbeatInterval(); got != 60*time.Second {
		t.Fatalf("unparseable interval=%s, want the 60s default", got)
	}
}
