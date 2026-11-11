package server

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// probeSignalStub answers a ping however the test asks: with a well-formed
// protocol error, with a bare HTTP rejection, or with nothing at all.
type probeSignalStub struct {
	key    string
	status int
	body   string
	calls  atomic.Int64
	server *httptest.Server
}

func newProbeSignalStub(t *testing.T, key string, status int, body string) *probeSignalStub {
	t.Helper()
	s := &probeSignalStub{key: key, status: status, body: body}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		if r.Header.Get("X-Shell-Key") != s.key {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"ok":false,"error":{"code":"unauthorized","message":"key rejected"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.body))
	}))
	t.Cleanup(s.server.Close)
	return s
}

// TestProbeConnectionDistinguishesTransportAuthAndProtocolFailure pins the state
// mapping: a shell that answers the protocol but refuses the action is REACHABLE
// (it answered!), only a transport/deadline failure is unreachable, and 401/403
// stays auth_failed. Before this the ok:false case collapsed into unreachable,
// which told the operator the host was down when it was answering fine.
func TestProbeConnectionDistinguishesTransportAuthAndProtocolFailure(t *testing.T) {
	e := newConnectionTestEnv(t)
	const secret = "{{SECRET_9frm2vqa4dh7kc1px8sy03ze}}"

	cases := []struct {
		name      string
		status    int
		body      string
		wantState string
		wantError string // substring of last_error, "" = must be empty
	}{
		{
			name:      "protocol error is reachable",
			status:    http.StatusOK,
			body:      `{"v":1,"ok":false,"action":"ping","error":{"code":"disabled","message":"exec is disabled by policy"}}`,
			wantState: "reachable",
			wantError: "exec is disabled by policy",
		},
		{
			name:      "protocol unauthorized is auth_failed",
			status:    http.StatusOK,
			body:      `{"ok":false,"error":{"code":"unauthorized","message":"bad key"}}`,
			wantState: "auth_failed",
			wantError: "bad key",
		},
		{
			name:      "http 403 is auth_failed",
			status:    http.StatusForbidden,
			body:      `{"ok":false,"error":{"code":"denied","message":"forbidden"}}`,
			wantState: "auth_failed",
			wantError: "forbidden",
		},
		{
			name:      "non-protocol error body is unreachable",
			status:    http.StatusServiceUnavailable,
			body:      `unavailable`,
			wantState: "unreachable",
			wantError: "503",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newProbeSignalStub(t, secret, tc.status, tc.body)
			adapter := e.createAdapter(t, map[string]any{
				"name": fmt.Sprintf("probe-%d-%d", tc.status, time.Now().UnixNano()), "kind": "http_phpcmd",
				"base_url": stub.server.URL + "/shell.php", "secret": secret, "secret_ref": "probe-key", "timeout_seconds": 2,
			})
			id := int64(adapter["id"].(float64))
			code, checked := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/check", id), nil, true)
			if code != 200 {
				t.Fatalf("check=%d %v", code, checked)
			}
			if checked["state"] != tc.wantState {
				t.Fatalf("state=%v want %s (%v)", checked["state"], tc.wantState, checked)
			}
			message, _ := checked["last_error"].(string)
			if tc.wantError == "" && message != "" {
				t.Fatalf("unexpected last_error %q", message)
			}
			if tc.wantError != "" && !strings.Contains(strings.ToLower(message), strings.ToLower(tc.wantError)) {
				t.Fatalf("last_error=%q missing %q", message, tc.wantError)
			}
			if stub.calls.Load() == 0 {
				t.Fatal("no probe request was sent")
			}
		})
	}

	// A closed port is a transport failure: unreachable, with a stated reason.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "http://" + listener.Addr().String() + "/shell.php"
	listener.Close()
	dead := e.createAdapter(t, map[string]any{
		"name": fmt.Sprintf("probe-dead-%d", time.Now().UnixNano()), "kind": "http_phpcmd",
		"base_url": closed, "secret": secret, "secret_ref": "probe-dead", "timeout_seconds": 1,
	})
	code, checked := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/check", int64(dead["id"].(float64))), nil, true)
	if code != 200 || checked["state"] != "unreachable" {
		t.Fatalf("dead adapter=%d %v", code, checked)
	}
	if message, _ := checked["last_error"].(string); message == "" {
		t.Fatalf("transport failure has no reason: %v", checked)
	}
}
