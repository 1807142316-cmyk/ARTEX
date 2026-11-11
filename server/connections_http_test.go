package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// shellStub is a Go implementation of the same http_phpcmd wire protocol the
// PHP fixture speaks. Windows can run it; the Linux acceptance run additionally
// exercises the real PHP container through TestConnectionAdapterRealPHPFixture.
type shellStub struct {
	key     string
	calls   atomic.Int64
	deny    atomic.Bool
	server  *httptest.Server
	delay   time.Duration
	maxBody int64
}

func newShellStub(t *testing.T, key string) *shellStub {
	t.Helper()
	s := &shellStub{key: key, maxBody: 16 << 10}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		if s.deny.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.URL.RawQuery != "" || r.URL.Fragment != "" {
			writeStubError(w, 400, "query_not_allowed", "query strings are not accepted")
			return
		}
		presented := r.Header.Get("X-Artex-Key")
		if presented == "" {
			presented = r.Header.Get("X-Shell-Key")
		}
		if !equalKey(s.key, presented) {
			writeStubError(w, 401, "unauthorized", "key rejected")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, s.maxBody+1))
		if err != nil || int64(len(body)) > s.maxBody {
			writeStubError(w, 413, "too_large", "body too large")
			return
		}
		var request struct {
			V      int    `json:"v"`
			ID     string `json:"id"`
			Action string `json:"action"`
			Nonce  string `json:"nonce"`
			Cmd    string `json:"cmd"`
			Args   struct {
				Argv      []string `json:"argv"`
				Cmd       string   `json:"cmd,omitempty"`
				Cwd       string   `json:"cwd"`
				TimeoutMS int      `json:"timeout_ms"`
			} `json:"args"`
		}
		if err := json.Unmarshal(body, &request); err != nil {
			writeStubError(w, 400, "bad_json", "invalid request body")
			return
		}
		if request.Args.Cmd != "" && request.Cmd == "" {
			request.Cmd = request.Args.Cmd
		}
		switch request.Action {
		case "ping":
			writeStubJSON(w, 200, map[string]any{"v": 1, "id": request.ID, "ok": true, "action": "ping", "pong": true, "server_time": time.Now().Unix()})
		case "info":
			writeStubJSON(w, 200, map[string]any{"v": 1, "id": request.ID, "ok": true, "action": "info", "php_version": "stub", "sapi": "cli-server", "user": "stub", "can_exec": true})
		case "exec":
			if s.delay > 0 {
				select {
				case <-time.After(s.delay):
				case <-r.Context().Done():
					return
				}
			}
			argv := request.Args.Argv
			if len(argv) == 0 && request.Cmd != "" {
				argv = []string{"/bin/sh", "-lc", request.Cmd}
			}
			if len(argv) == 0 {
				writeStubError(w, 400, "bad_argv", "argv is required")
				return
			}
			out, code, timedOut := stubRun(r.Context(), argv, request.Args.TimeoutMS)
			writeStubJSON(w, 200, map[string]any{"v": 1, "id": request.ID, "ok": true, "action": "exec", "exit_code": code, "timed_out": timedOut, "truncated": false, "stdout_b64": base64.StdEncoding.EncodeToString([]byte(out)), "stderr_b64": "", "duration_ms": 1})
		default:
			writeStubError(w, 400, "bad_json", "unsupported action")
		}
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *shellStub) url() string { return s.server.URL + "/shell.php" }

func stubRun(ctx context.Context, argv []string, timeoutMS int) (string, int, bool) {
	switch strings.Join(argv, " ") {
	case "/bin/echo artex-ok", "/bin/echo artex-ok ":
		return "artex-ok\n", 0, false
	case "/bin/sh -c exit 7", "/bin/sh -lc exit 7":
		return "", 7, false
	case "id":
		return "uid=1000(artex)\n", 0, false
	}
	if argv[0] == "/bin/sh" && len(argv) == 3 && argv[2] == "id" {
		return "uid=1000(artex)\n", 0, false
	}
	if argv[0] == "/bin/sh" && len(argv) == 3 && argv[2] == "exit 7" {
		return "", 7, false
	}
	if argv[0] == "/bin/sh" && len(argv) == 3 && strings.HasPrefix(argv[2], "printf ") {
		return strings.TrimPrefix(argv[2], "printf ") + "\n", 0, false
	}
	if argv[0] == "/bin/sh" && len(argv) == 3 && strings.HasPrefix(argv[2], "head -c ") {
		// "head -c N /dev/zero | tr '\0' 'x'" — the remote side caps its own
		// stream exactly as the PHP fixture does (48 KiB per stream).
		var n int
		_, _ = fmt.Sscanf(argv[2], "head -c %d", &n)
		if n > 48<<10 {
			n = 48 << 10
		}
		return strings.Repeat("x", n), 0, false
	}
	if argv[0] == "/bin/echo" && len(argv) == 2 {
		return argv[1] + "\n", 0, false
	}
	if argv[0] == "/bin/sleep" {
		// Honour the server-side deadline so a slow request cannot pin the test.
		wait := time.Hour
		if timeoutMS > 0 {
			wait = time.Duration(timeoutMS) * time.Millisecond
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
		}
		return "", 0, true
	}
	return strings.Join(argv, " ") + "\n", 0, false
}

func equalKey(expected, presented string) bool {
	a := sha256.Sum256([]byte(expected))
	b := sha256.Sum256([]byte(presented))
	return presented != "" && string(a[:]) == string(b[:])
}

func writeStubJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}

func writeStubError(w http.ResponseWriter, code int, kind, message string) {
	writeStubJSON(w, code, map[string]any{"ok": false, "error": map[string]string{"code": kind, "message": message}})
}

type connectionTestEnv struct {
	s      *Server
	m      *Manager
	api    *httptest.Server
	token  string
	client *http.Client
}

func newConnectionTestEnv(t *testing.T) *connectionTestEnv {
	t.Helper()
	m := newParityTestManager(t)
	t.Cleanup(func() { _ = m.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(s.Handler())
	t.Cleanup(api.Close)
	return &connectionTestEnv{s: s, m: m, api: api, token: token, client: api.Client()}
}

func (e *connectionTestEnv) call(t *testing.T, method, path string, input any, auth bool) (int, map[string]any) {
	t.Helper()
	var body io.Reader
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(raw)
	}
	r, err := http.NewRequest(method, e.api.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if input != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if auth {
		r.Header.Set("Authorization", "Bearer "+e.token)
	}
	w, err := e.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Body.Close()
	raw, _ := io.ReadAll(w.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return w.StatusCode, out
}

func (e *connectionTestEnv) makeTask(t *testing.T, name string) int64 {
	t.Helper()
	code, result := e.call(t, "POST", "/api/tasks", map[string]any{"name": name, "description": "c2 adapter association", "goal": "link a session"}, true)
	if code != 201 {
		t.Fatalf("task=%d %v", code, result)
	}
	switch v := result["id"].(type) {
	case string:
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return id
	case float64:
		return int64(v)
	}
	t.Fatalf("unexpected task id %#v", result["id"])
	return 0
}

func (e *connectionTestEnv) makeAsset(t *testing.T, taskID int64, ip string) int64 {
	t.Helper()
	code, result := e.call(t, "POST", "/api/assets", map[string]any{"task_id": taskID, "assets": []any{map[string]any{"type": "ip", "ip": ip}}}, true)
	if code != 200 {
		t.Fatalf("asset=%d %v", code, result)
	}
	results, _ := result["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("asset result=%v", result)
	}
	return int64(results[0].(map[string]any)["id"].(float64))
}

func (e *connectionTestEnv) createAdapter(t *testing.T, input map[string]any) map[string]any {
	t.Helper()
	code, result := e.call(t, "POST", "/api/connections/adapters", input, true)
	if code != 201 {
		t.Fatalf("adapter create=%d %v", code, result)
	}
	return result
}

func secretOf(input map[string]any) string {
	if v, ok := input["secret"].(string); ok {
		return v
	}
	return ""
}

func TestConnectionAdaptersNeverExposeSecretsAndRejectUnknownFields(t *testing.T) {
	e := newConnectionTestEnv(t)
	const secret = "fixture-key-material-0001-0123456789"
	stub := newShellStub(t, secret)
	name := fmt.Sprintf("adapter-%d", time.Now().UnixNano())
	code, created := e.call(t, "POST", "/api/connections/adapters", map[string]any{
		"name": name, "kind": "http_phpcmd", "base_url": stub.url(), "secret": secret,
		"secret_ref": "fixture-key-v1", "timeout_seconds": 5, "heartbeat_ttl_seconds": 60, "enabled": true,
	}, true)
	if code != 201 {
		t.Fatalf("create=%d %v", code, created)
	}
	id := int64(created["id"].(float64))
	for _, raw := range []string{connectionJSON(created), connectionJSONCall(e.call(t, "GET", "/api/connections/adapters", nil, true)), connectionJSONCall(e.call(t, "GET", fmt.Sprintf("/api/connections/adapters/%d", id), nil, true))} {
		if strings.Contains(raw, secret) || strings.Contains(raw, "sealed_secret") {
			t.Fatalf("secret leaked: %s", raw)
		}
		if !strings.Contains(raw, "fixture-key-v1") {
			t.Fatalf("secret_ref missing: %s", raw)
		}
	}
	if code, _ := e.call(t, "POST", "/api/connections/adapters", map[string]any{"name": name + "-unauth", "kind": "http_phpcmd", "base_url": stub.url(), "secret": secret}, false); code != 401 {
		t.Fatalf("unauthorized create=%d", code)
	}
	if code, _ := e.call(t, "POST", "/api/connections/adapters", map[string]any{"name": name + "-ssh", "kind": "ssh", "base_url": stub.url(), "secret": secret}, true); code != 400 {
		t.Fatalf("unsupported kind=%d", code)
	}
	if code, _ := e.call(t, "POST", "/api/connections/adapters", map[string]any{"name": name + "-extra", "kind": "http_phpcmd", "base_url": stub.url(), "secret": secret, "password": "should not be accepted"}, true); code != 400 {
		t.Fatalf("unknown field=%d", code)
	}
	if code, _ := e.call(t, "POST", "/api/connections/adapters", map[string]any{"name": name + "-query", "kind": "http_phpcmd", "base_url": stub.url() + "?key=plaintext", "secret": secret}, true); code != 400 {
		t.Fatalf("credentials in query accepted=%d", code)
	}
	if code, _ := e.call(t, "POST", "/api/connections/adapters", map[string]any{"name": name + "-short", "kind": "http_phpcmd", "base_url": stub.url(), "secret": "short"}, true); code != 400 {
		t.Fatalf("short key accepted=%d", code)
	}
	// Update without a new secret keeps the sealed material usable.
	code, updated := e.call(t, "PUT", fmt.Sprintf("/api/connections/adapters/%d", id), map[string]any{
		"name": name + "-renamed", "kind": "http_phpcmd", "base_url": stub.url(), "secret_ref": "fixture-key-v1",
		"timeout_seconds": 7, "heartbeat_ttl_seconds": 60, "enabled": true,
	}, true)
	if code != 200 || updated["name"] != name+"-renamed" || updated["timeout_seconds"] != float64(7) {
		t.Fatalf("update=%d %v", code, updated)
	}
	if strings.Contains(connectionJSON(updated), secret) {
		t.Fatalf("update exposed secret: %v", updated)
	}
	code, checked := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/check", id), nil, true)
	if code != 200 || checked["state"] != "reachable" {
		t.Fatalf("check after secret-preserving update=%d %v", code, checked)
	}
	if code, _ := e.call(t, "DELETE", fmt.Sprintf("/api/connections/adapters/%d", id), nil, false); code != 401 {
		t.Fatalf("unauthorized delete=%d", code)
	}
	if code, _ := e.call(t, "DELETE", fmt.Sprintf("/api/connections/adapters/%d", id), nil, true); code != 204 {
		t.Fatalf("delete=%d", code)
	}
	if code, _ := e.call(t, "GET", fmt.Sprintf("/api/connections/adapters/%d", id), nil, true); code != 404 {
		t.Fatalf("deleted adapter still readable=%d", code)
	}
}

func connectionJSON(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

func connectionJSONCall(code int, v map[string]any) string {
	if code != 200 {
		return fmt.Sprintf(`{"status":%d}`, code)
	}
	return connectionJSON(v)
}

func TestConnectionAdapterCheckDistinguishesAuthUnreachableAndReachable(t *testing.T) {
	e := newConnectionTestEnv(t)
	const secret = "fixture-key-material-0002-0123456789"
	stub := newShellStub(t, secret)
	good := e.createAdapter(t, map[string]any{"name": fmt.Sprintf("good-%d", time.Now().UnixNano()), "kind": "http_phpcmd", "base_url": stub.url(), "secret": secret, "secret_ref": "good-key", "timeout_seconds": 5})
	goodID := int64(good["id"].(float64))

	code, result := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/check", goodID), nil, true)
	if code != 200 {
		t.Fatalf("check=%d %v", code, result)
	}
	if result["state"] != "reachable" || result["last_error"] != "" {
		t.Fatalf("reachable state=%v", result)
	}
	if result["checked_at"] == nil {
		t.Fatalf("check did not record checked_at: %v", result)
	}

	wrong := e.createAdapter(t, map[string]any{"name": fmt.Sprintf("wrong-%d", time.Now().UnixNano()), "kind": "http_phpcmd", "base_url": stub.url(), "secret": "fixture-key-material-wrong-0123456789", "secret_ref": "wrong-key", "timeout_seconds": 5})
	wrongID := int64(wrong["id"].(float64))
	code, result = e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/check", wrongID), nil, true)
	if code != 200 || result["state"] != "auth_failed" {
		t.Fatalf("auth_failed=%d %v", code, result)
	}
	if message, _ := result["last_error"].(string); !strings.Contains(message, "401") && !strings.Contains(message, "rejected") {
		t.Fatalf("auth failure not explained: %v", result)
	}
	if strings.Contains(connectionJSON(result), "wrong-key-material") {
		t.Fatalf("check echoed the secret: %v", result)
	}

	// Reserve and immediately close a port so the adapter target is unreachable.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedURL := "http://" + listener.Addr().String() + "/shell.php"
	listener.Close()
	dead := e.createAdapter(t, map[string]any{"name": fmt.Sprintf("dead-%d", time.Now().UnixNano()), "kind": "http_phpcmd", "base_url": closedURL, "secret": secret, "secret_ref": "dead-key", "timeout_seconds": 2})
	deadID := int64(dead["id"].(float64))
	code, result = e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/check", deadID), nil, true)
	if code != 200 || result["state"] != "unreachable" || result["last_error"] == "" {
		t.Fatalf("unreachable=%d %v", code, result)
	}
	// A disabled adapter does not reach the network.
	stub.calls.Store(0)
	code, result = e.call(t, "PUT", fmt.Sprintf("/api/connections/adapters/%d", goodID), map[string]any{"name": good["name"], "kind": "http_phpcmd", "base_url": stub.url(), "secret_ref": "good-key", "timeout_seconds": 5, "enabled": false}, true)
	if code != 200 {
		t.Fatalf("disable=%d %v", code, result)
	}
	code, result = e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/check", goodID), nil, true)
	if code != 409 {
		t.Fatalf("disabled check=%d %v", code, result)
	}
	if stub.calls.Load() != 0 {
		t.Fatalf("disabled adapter still performed %d requests", stub.calls.Load())
	}
}

func TestConnectionSyncUpsertsOneInventorySessionWithAssociation(t *testing.T) {
	e := newConnectionTestEnv(t)
	const secret = "fixture-key-material-0003-0123456789"
	stub := newShellStub(t, secret)
	taskID := e.makeTask(t, "c2 association")
	assetID := e.makeAsset(t, taskID, fmt.Sprintf("192.0.2.%d", 100+time.Now().UnixNano()%100))
	otherTask := e.makeTask(t, "c2 other")
	otherAsset := e.makeAsset(t, otherTask, fmt.Sprintf("198.51.100.%d", 10+time.Now().UnixNano()%200))
	name := fmt.Sprintf("sync-%d", time.Now().UnixNano())
	adapter := e.createAdapter(t, map[string]any{"name": name, "kind": "http_phpcmd", "base_url": stub.url(), "secret": secret, "secret_ref": "sync-key", "timeout_seconds": 5, "heartbeat_ttl_seconds": 30, "task_id": taskID, "asset_id": assetID})
	adapterID := int64(adapter["id"].(float64))

	code, result := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/sync", adapterID), nil, true)
	if code != 200 {
		t.Fatalf("sync=%d %v", code, result)
	}
	session, _ := result["session"].(map[string]any)
	if session == nil {
		t.Fatalf("sync returned no session: %v", result)
	}
	sessionID := int64(session["id"].(float64))
	if session["kind"] != "webshell" || session["protocol_label"] != "http_phpcmd" || session["mode"] != "adapter" {
		t.Fatalf("session shape=%v", session)
	}
	if session["effective_state"] != "connected" || session["host"] == "" || session["url"] == "" {
		t.Fatalf("session state=%v", session)
	}
	if int64(session["task_id"].(float64)) != taskID || int64(session["asset_id"].(float64)) != assetID {
		t.Fatalf("association lost: %v", session)
	}
	if !strings.HasPrefix(session["source"].(string), "connection:") {
		t.Fatalf("source=%v", session["source"])
	}
	code, again := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/sync", adapterID), nil, true)
	if code != 200 {
		t.Fatalf("resync=%d %v", code, again)
	}
	if int64(again["session"].(map[string]any)["id"].(float64)) != sessionID {
		t.Fatalf("sync created a second session: %v", again)
	}
	code, list := e.call(t, "GET", "/api/connections/sessions", nil, true)
	if code != 200 {
		t.Fatalf("list=%d %v", code, list)
	}
	items, _ := list["items"].([]any)
	found := 0
	for _, raw := range items {
		item := raw.(map[string]any)
		if int64(item["id"].(float64)) == sessionID {
			found++
			caps, _ := item["capabilities"].([]any)
			if len(caps) != 3 {
				t.Fatalf("capabilities=%v", item)
			}
			if strings.Contains(connectionJSON(item), secret) {
				t.Fatalf("session list leaked key: %v", item)
			}
		}
	}
	if found != 1 {
		t.Fatalf("adapter session missing from list: %v", list)
	}
	// Unauthenticated reads are refused like every other management endpoint.
	if code, _ := e.call(t, "GET", "/api/connections/adapters", nil, false); code != 401 {
		t.Fatalf("unauthorized adapter list=%d", code)
	}
	if code, _ := e.call(t, "GET", "/api/connections/sessions", nil, false); code != 401 {
		t.Fatalf("unauthorized session list=%d", code)
	}
	if code, _ := e.call(t, "GET", fmt.Sprintf("/api/connections/sessions/%d/operations", sessionID), nil, false); code != 401 {
		t.Fatalf("unauthorized operation list=%d", code)
	}
	// Missing or cross-task references are rejected before anything is written.
	code, rejected := e.call(t, "PUT", fmt.Sprintf("/api/connections/adapters/%d", adapterID), map[string]any{"name": name, "kind": "http_phpcmd", "base_url": stub.url(), "secret_ref": "sync-key", "timeout_seconds": 5, "task_id": taskID, "asset_id": otherAsset}, true)
	if code != 400 {
		t.Fatalf("cross-task asset accepted=%d %v", code, rejected)
	}
	if code, _ := e.call(t, "PUT", fmt.Sprintf("/api/connections/adapters/%d", adapterID), map[string]any{"name": name, "kind": "http_phpcmd", "base_url": stub.url(), "secret_ref": "sync-key", "timeout_seconds": 5, "task_id": int64(922337203685477000)}, true); code != 400 {
		t.Fatalf("unknown task accepted=%d", code)
	}
	if code, _ := e.call(t, "PUT", fmt.Sprintf("/api/connections/adapters/%d", adapterID), map[string]any{"name": name, "kind": "http_phpcmd", "base_url": stub.url(), "secret_ref": "sync-key", "timeout_seconds": 5, "asset_id": int64(922337203685477000)}, true); code != 400 {
		t.Fatalf("unknown asset accepted=%d", code)
	}
	// The adapter's session can be disconnected through the existing inventory path
	// and a later sync reports the source back online.
	code, _ = e.call(t, "POST", fmt.Sprintf("/api/session-inventory/sessions/%d/disconnect", sessionID), map[string]string{"detail": "operator closed the shell"}, true)
	if code != 200 {
		t.Fatalf("disconnect=%d", code)
	}
	code, reconnected := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/sync", adapterID), nil, true)
	if code != 200 || reconnected["session"].(map[string]any)["effective_state"] != "connected" {
		t.Fatalf("reconnect=%d %v", code, reconnected)
	}
	// Staleness follows the adapter TTL; the API computes it without a page open.
	_, err := e.m.pg.ExecContext(context.Background(), `UPDATE session_inventory SET heartbeat_at=now()-interval '2 minutes' WHERE id=$1`, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	code, detail := e.call(t, "GET", fmt.Sprintf("/api/session-inventory/sessions/%d", sessionID), nil, true)
	if code != 200 || detail["session"].(map[string]any)["effective_state"] != "stale" {
		t.Fatalf("stale=%d %v", code, detail)
	}
	code, result = e.call(t, "POST", fmt.Sprintf("/api/connections/sessions/%d/operations", sessionID), map[string]any{"action": "exec", "cmd": "id", "request_id": fmt.Sprintf("stale-%d", time.Now().UnixNano())}, true)
	if code != 409 {
		t.Fatalf("stale session executed=%d %v", code, result)
	}
}

// TestConnectionSyncRecordsOfflineStateWithReason covers the online/offline
// transition: a failed check must show as disconnected with a concrete reason,
// and the same inventory row must come back online once the shell answers again.
func TestConnectionSyncRecordsOfflineStateWithReason(t *testing.T) {
	e := newConnectionTestEnv(t)
	const secret = "fixture-key-material-offline-0123456789"
	stub := newShellStub(t, secret)
	name := fmt.Sprintf("offline-%d", time.Now().UnixNano())
	adapter := e.createAdapter(t, map[string]any{"name": name, "kind": "http_phpcmd", "base_url": stub.url(), "secret": secret, "secret_ref": "offline-key", "timeout_seconds": 2, "heartbeat_ttl_seconds": 60})
	adapterID := int64(adapter["id"].(float64))
	code, online := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/sync", adapterID), nil, true)
	if code != 200 || online["session"].(map[string]any)["effective_state"] != "connected" {
		t.Fatalf("online sync=%d %v", code, online)
	}
	sessionID := int64(online["session"].(map[string]any)["id"].(float64))

	stub.deny.Store(true)
	code, offline := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/sync", adapterID), nil, true)
	if code != 200 {
		t.Fatalf("offline sync=%d %v", code, offline)
	}
	if offline["state"] != "unreachable" {
		t.Fatalf("offline adapter state=%v", offline)
	}
	session := offline["session"].(map[string]any)
	if int64(session["id"].(float64)) != sessionID {
		t.Fatalf("offline sync created a second session: %v", session)
	}
	if session["effective_state"] != "disconnected" {
		t.Fatalf("offline session state=%v", session)
	}
	if reason, _ := session["disconnect_reason"].(string); !strings.Contains(reason, "unreachable") {
		t.Fatalf("offline reason=%q", reason)
	}
	// The adapter state is persisted, and executing against the offline session
	// is refused rather than attempted.
	code, detail := e.call(t, "GET", fmt.Sprintf("/api/connections/adapters/%d", adapterID), nil, true)
	if code != 200 || detail["state"] != "unreachable" || detail["last_error"] == "" {
		t.Fatalf("persisted adapter state=%d %v", code, detail)
	}
	code, refused := e.call(t, "POST", fmt.Sprintf("/api/connections/sessions/%d/operations", sessionID), map[string]any{"action": "exec", "cmd": "id", "request_id": fmt.Sprintf("offline-%d", time.Now().UnixNano())}, true)
	if code != 409 {
		t.Fatalf("offline session executed=%d %v", code, refused)
	}

	stub.deny.Store(false)
	code, recovered := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/sync", adapterID), nil, true)
	if code != 200 || recovered["session"].(map[string]any)["effective_state"] != "connected" {
		t.Fatalf("recovered sync=%d %v", code, recovered)
	}
	if int64(recovered["session"].(map[string]any)["id"].(float64)) != sessionID {
		t.Fatalf("recovery created a second session: %v", recovered)
	}
	if recovered["session"].(map[string]any)["disconnect_reason"] != "" {
		t.Fatalf("recovered session kept a disconnect reason: %v", recovered)
	}
}

func TestConnectionOperationsRecordSuccessFailureTimeoutAndUnsupported(t *testing.T) {
	e := newConnectionTestEnv(t)
	const secret = "fixture-key-material-0004-0123456789"
	stub := newShellStub(t, secret)
	name := fmt.Sprintf("ops-%d", time.Now().UnixNano())
	adapter := e.createAdapter(t, map[string]any{"name": name, "kind": "http_phpcmd", "base_url": stub.url(), "secret": secret, "secret_ref": "ops-key", "timeout_seconds": 2, "heartbeat_ttl_seconds": 60})
	adapterID := int64(adapter["id"].(float64))
	code, synced := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/sync", adapterID), nil, true)
	if code != 200 {
		t.Fatalf("sync=%d %v", code, synced)
	}
	sessionID := int64(synced["session"].(map[string]any)["id"].(float64))
	execPath := fmt.Sprintf("/api/connections/sessions/%d/operations", sessionID)

	// success
	requestID := fmt.Sprintf("req-%d-1", time.Now().UnixNano())
	code, result := e.call(t, "POST", execPath, map[string]any{"action": "exec", "argv": []string{"/bin/echo", "artex-ok"}, "request_id": requestID}, true)
	if code != 200 {
		t.Fatalf("exec=%d %v", code, result)
	}
	if result["status"] != "succeeded" || result["output"] != "artex-ok\n" || result["exit_code"] != float64(0) {
		t.Fatalf("exec result=%v", result)
	}
	if result["finished_at"] == nil || result["request_id"] != requestID || result["action"] != "exec" {
		t.Fatalf("operation record incomplete=%v", result)
	}
	// idempotent replay: same request_id does not send a second request
	calls := stub.calls.Load()
	code, replay := e.call(t, "POST", execPath, map[string]any{"action": "exec", "argv": []string{"/bin/echo", "artex-ok"}, "request_id": requestID}, true)
	if code != 200 || replay["id"] != result["id"] {
		t.Fatalf("replay=%d %v", code, replay)
	}
	if stub.calls.Load() != calls {
		t.Fatalf("replay performed a second network call")
	}
	// failure: non-zero exit is a completed exchange with a failed status
	code, failed := e.call(t, "POST", execPath, map[string]any{"action": "exec", "cmd": "exit 7", "request_id": fmt.Sprintf("req-%d-2", time.Now().UnixNano())}, true)
	if code != 200 || failed["status"] != "failed" || failed["exit_code"] != float64(7) {
		t.Fatalf("failure=%d %v", code, failed)
	}
	// timeout: fixture sleeps past the adapter bound
	stub.delay = 3 * time.Second
	code, timedOut := e.call(t, "POST", execPath, map[string]any{"action": "exec", "argv": []string{"/bin/sleep", "30"}, "timeout_ms": 500, "request_id": fmt.Sprintf("req-%d-3", time.Now().UnixNano())}, true)
	stub.delay = 0
	if code != 200 || timedOut["status"] != "timeout" {
		t.Fatalf("timeout=%d %v", code, timedOut)
	}
	if timedOut["error"] == "" {
		t.Fatalf("timeout has no error text: %v", timedOut)
	}
	// output is bounded
	code, bounded := e.call(t, "POST", execPath, map[string]any{"action": "exec", "argv": []string{"/bin/sh", "-c", "head -c 200000 /dev/zero | tr '\\0' 'x'"}, "request_id": fmt.Sprintf("req-%d-4", time.Now().UnixNano())}, true)
	if code != 200 {
		t.Fatalf("bounded=%d %v", code, bounded)
	}
	if output, _ := bounded["output"].(string); len(output) > 64<<10 {
		t.Fatalf("output not bounded: %d bytes", len(output))
	}
	// unsupported action is refused without a network call
	calls = stub.calls.Load()
	code, unsupported := e.call(t, "POST", execPath, map[string]any{"action": "upload", "request_id": fmt.Sprintf("req-%d-5", time.Now().UnixNano())}, true)
	if code != 422 || unsupported["status"] != "unsupported" {
		t.Fatalf("unsupported=%d %v", code, unsupported)
	}
	if stub.calls.Load() != calls {
		t.Fatalf("unsupported action reached the remote shell")
	}
	// history retains every record with its explicit outcome
	code, history := e.call(t, "GET", execPath, nil, true)
	if code != 200 {
		t.Fatalf("history=%d %v", code, history)
	}
	rows, _ := history["items"].([]any)
	if len(rows) != 5 {
		t.Fatalf("history=%d %v", len(rows), history)
	}
	statuses := map[string]int{}
	for _, raw := range rows {
		row := raw.(map[string]any)
		statuses[row["status"].(string)]++
		if strings.Contains(connectionJSON(row), secret) {
			t.Fatalf("operation leaked the key: %v", row)
		}
	}
	// success + bounded-output exec both completed; failure, timeout and the
	// rejected capability each have exactly one record.
	for want, count := range map[string]int{"succeeded": 2, "failed": 1, "timeout": 1, "unsupported": 1} {
		if statuses[want] != count {
			t.Fatalf("status %s count=%d (%v)", want, statuses[want], statuses)
		}
	}
	// ping/info are supported operations too
	code, pinged := e.call(t, "POST", execPath, map[string]any{"action": "ping", "request_id": fmt.Sprintf("req-%d-6", time.Now().UnixNano())}, true)
	if code != 200 || pinged["status"] != "succeeded" {
		t.Fatalf("ping=%d %v", code, pinged)
	}
}

type operationRow struct {
	ID              int64
	AdapterID       int64
	SessionID       int64
	RequestID       string
	Action          string
	Status          string
	Output          string
	Error           string
	ExitCode        *int
	FinishedAt      *time.Time
	SessionSequence *int64
	OutputRef       *string
}

func readOperation(t *testing.T, e *connectionTestEnv, sessionID int64, requestID string) (operationRow, bool) {
	t.Helper()
	var row operationRow
	err := e.m.pg.QueryRowContext(context.Background(), `SELECT id,adapter_id,session_id,request_id,action,status,output,error,exit_code,finished_at,session_sequence,output_ref FROM connection_operations WHERE session_id=$1 AND request_id=$2`, sessionID, requestID).Scan(&row.ID, &row.AdapterID, &row.SessionID, &row.RequestID, &row.Action, &row.Status, &row.Output, &row.Error, &row.ExitCode, &row.FinishedAt, &row.SessionSequence, &row.OutputRef)
	if err != nil {
		if err == sql.ErrNoRows {
			return row, false
		}
		t.Fatal(err)
	}
	return row, true
}

// TestConnectionSyncUsesTheExistingInventoryObservation confirms the adapter
// writes through db.ObserveSession rather than a parallel session table.
func TestConnectionSyncUsesTheExistingInventoryObservation(t *testing.T) {
	e := newConnectionTestEnv(t)
	const secret = "fixture-key-material-0005-0123456789"
	stub := newShellStub(t, secret)
	name := fmt.Sprintf("inventory-%d", time.Now().UnixNano())
	adapter := e.createAdapter(t, map[string]any{"name": name, "kind": "http_phpcmd", "base_url": stub.url(), "secret": secret, "secret_ref": "inv-key", "timeout_seconds": 5})
	adapterID := int64(adapter["id"].(float64))
	code, synced := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/sync", adapterID), nil, true)
	if code != 200 {
		t.Fatalf("sync=%d %v", code, synced)
	}
	sessionID := int64(synced["session"].(map[string]any)["id"].(float64))
	var source, sourceID string
	var sequence int64
	if err := e.m.pg.QueryRowContext(context.Background(), `SELECT source,source_id,sequence FROM session_inventory WHERE id=$1`, sessionID).Scan(&source, &sourceID, &sequence); err != nil {
		t.Fatal(err)
	}
	if source != fmt.Sprintf("connection:%d", adapterID) || sourceID == "" || sequence < 1 {
		t.Fatalf("inventory identity=%q/%q/%d", source, sourceID, sequence)
	}
	// Observations are visible through the authenticated inventory endpoint.
	code, detail := e.call(t, "GET", fmt.Sprintf("/api/session-inventory/sessions/%d", sessionID), nil, true)
	if code != 200 {
		t.Fatalf("inventory detail=%d %v", code, detail)
	}
	if detail["session"].(map[string]any)["protocol_label"] != "http_phpcmd" {
		t.Fatalf("inventory protocol=%v", detail["session"])
	}
	// Operations belong to the adapter that owns the session.
	otherName := fmt.Sprintf("other-%d", time.Now().UnixNano())
	other := e.createAdapter(t, map[string]any{"name": otherName, "kind": "http_phpcmd", "base_url": stub.url(), "secret": secret, "secret_ref": "other-key", "timeout_seconds": 5})
	_ = other
	// The request body takes no adapter identifier: the session in the path is the
	// only authority, so an unknown field is refused outright instead of being
	// silently ignored.
	if code, body := e.call(t, "POST", fmt.Sprintf("/api/connections/sessions/%d/operations", sessionID), map[string]any{"action": "exec", "cmd": "id", "adapter_id": int64(adapterID) + 1, "request_id": "mismatch"}, true); code != 400 {
		t.Fatalf("adapter_id in body accepted (%d): %v", code, body)
	}
	// A session that no adapter owns is refused explicitly.
	code, manual := e.call(t, "POST", "/api/session-inventory/observations", map[string]any{"source": fmt.Sprintf("observer-manual-%d", time.Now().UnixNano()), "source_id": "manual", "sequence": 1, "kind": "c2", "state": "connected", "host": "manual.internal", "url": "http://manual.internal/status", "heartbeat_ttl_seconds": 60}, true)
	if code != 201 {
		t.Fatalf("manual observation=%d %v", code, manual)
	}
	manualID := int64(manual["session"].(map[string]any)["id"].(float64))
	code, rejected := e.call(t, "POST", fmt.Sprintf("/api/connections/sessions/%d/operations", manualID), map[string]any{"action": "exec", "cmd": "id", "request_id": "no-adapter"}, true)
	if code != 409 {
		t.Fatalf("non-adapter session executed=%d %v", code, rejected)
	}
}

func TestConnectionOperationRequiresRequestIDAndValidInput(t *testing.T) {
	e := newConnectionTestEnv(t)
	const secret = "fixture-key-material-0006-0123456789"
	stub := newShellStub(t, secret)
	adapter := e.createAdapter(t, map[string]any{"name": fmt.Sprintf("input-%d", time.Now().UnixNano()), "kind": "http_phpcmd", "base_url": stub.url(), "secret": secret, "secret_ref": "input-key", "timeout_seconds": 5})
	adapterID := int64(adapter["id"].(float64))
	code, synced := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/sync", adapterID), nil, true)
	if code != 200 {
		t.Fatalf("sync=%d %v", code, synced)
	}
	sessionID := int64(synced["session"].(map[string]any)["id"].(float64))
	path := fmt.Sprintf("/api/connections/sessions/%d/operations", sessionID)
	if code, _ := e.call(t, "POST", path, map[string]any{"action": "exec", "cmd": "id"}, true); code != 400 {
		t.Fatalf("missing request_id=%d", code)
	}
	if code, _ := e.call(t, "POST", path, map[string]any{"action": "exec", "cmd": "id", "request_id": "x", "argv": []string{"/bin/id"}}, true); code != 400 {
		t.Fatalf("cmd+argv accepted=%d", code)
	}
	if code, _ := e.call(t, "POST", path, map[string]any{"action": "exec", "request_id": "y"}, true); code != 400 {
		t.Fatalf("empty command accepted=%d", code)
	}
	if code, _ := e.call(t, "POST", path, map[string]any{"action": "exec", "cmd": "id", "request_id": "z"}, false); code != 401 {
		t.Fatalf("unauthorized operation=%d", code)
	}
	if code, _ := e.call(t, "GET", "/api/connections/sessions/999999999/operations", nil, true); code != 404 {
		t.Fatalf("unknown session=%d", code)
	}
}

// TestConnectionAdapterRealPHPFixture is the Linux acceptance run: it speaks to
// the actual PHP fixture container. It is skipped only when ARTEX_TEST_PHP_URL is
// unset, which the contract permits for hosts without the fixture.
func TestConnectionAdapterRealPHPFixture(t *testing.T) {
	base := strings.TrimSpace(os.Getenv("ARTEX_TEST_PHP_URL"))
	if base == "" {
		t.Skip("ARTEX_TEST_PHP_URL not set; PHP fixture acceptance runs on the Linux host")
	}
	key := strings.TrimSpace(os.Getenv("ARTEX_TEST_PHP_KEY"))
	if key == "" {
		t.Fatal("ARTEX_TEST_PHP_KEY is required with ARTEX_TEST_PHP_URL")
	}
	e := newConnectionTestEnv(t)
	adapter := e.createAdapter(t, map[string]any{"name": fmt.Sprintf("php-%d", time.Now().UnixNano()), "kind": "http_phpcmd", "base_url": base, "secret": key, "secret_ref": "php-fixture", "timeout_seconds": 10, "heartbeat_ttl_seconds": 60})
	adapterID := int64(adapter["id"].(float64))

	code, checked := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/check", adapterID), nil, true)
	if code != 200 || checked["state"] != "reachable" {
		t.Fatalf("real PHP check=%d %v", code, checked)
	}
	code, synced := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/sync", adapterID), nil, true)
	if code != 200 {
		t.Fatalf("real PHP sync=%d %v", code, synced)
	}
	sessionID := int64(synced["session"].(map[string]any)["id"].(float64))
	path := fmt.Sprintf("/api/connections/sessions/%d/operations", sessionID)
	code, result := e.call(t, "POST", path, map[string]any{"action": "exec", "cmd": "id", "request_id": fmt.Sprintf("php-%d-1", time.Now().UnixNano())}, true)
	if code != 200 || result["status"] != "succeeded" {
		t.Fatalf("real PHP exec=%d %v", code, result)
	}
	if output, _ := result["output"].(string); !strings.Contains(output, "uid=") {
		t.Fatalf("real PHP output=%q", output)
	}
	code, failed := e.call(t, "POST", path, map[string]any{"action": "exec", "cmd": "exit 7", "request_id": fmt.Sprintf("php-%d-2", time.Now().UnixNano())}, true)
	if code != 200 || failed["status"] != "failed" || failed["exit_code"] != float64(7) {
		t.Fatalf("real PHP failure=%d %v", code, failed)
	}
	code, timedOut := e.call(t, "POST", path, map[string]any{"action": "exec", "cmd": "sleep 5", "timeout_ms": 600, "request_id": fmt.Sprintf("php-%d-3", time.Now().UnixNano())}, true)
	if code != 200 || timedOut["status"] != "timeout" {
		t.Fatalf("real PHP timeout=%d %v", code, timedOut)
	}
	code, pinged := e.call(t, "POST", path, map[string]any{"action": "ping", "request_id": fmt.Sprintf("php-%d-4", time.Now().UnixNano())}, true)
	if code != 200 || pinged["status"] != "succeeded" {
		t.Fatalf("real PHP ping=%d %v", code, pinged)
	}
	code, bounded := e.call(t, "POST", path, map[string]any{"action": "exec", "cmd": "head -c 200000 /dev/zero | tr '\\0' 'x'", "request_id": fmt.Sprintf("php-%d-5", time.Now().UnixNano())}, true)
	if code != 200 {
		t.Fatalf("real PHP bounded=%d %v", code, bounded)
	}
	if output, _ := bounded["output"].(string); len(output) > 64<<10 {
		t.Fatalf("real PHP output not bounded: %d bytes", len(output))
	}
	// Wrong key through the same real fixture reports auth_failed, not reachable.
	wrong := e.createAdapter(t, map[string]any{"name": fmt.Sprintf("php-wrong-%d", time.Now().UnixNano()), "kind": "http_phpcmd", "base_url": base, "secret": "fixture-key-material-wrong-0123456789", "secret_ref": "php-wrong", "timeout_seconds": 5})
	code, state := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/check", int64(wrong["id"].(float64))), nil, true)
	if code != 200 || state["state"] != "auth_failed" {
		t.Fatalf("real PHP wrong key=%d %v", code, state)
	}
	requestRows(t, e, sessionID)
}

func requestRows(t *testing.T, e *connectionTestEnv, sessionID int64) int {
	t.Helper()
	var n int
	if err := e.m.pg.QueryRowContext(context.Background(), `SELECT count(*) FROM connection_operations WHERE session_id=$1`, sessionID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 5 {
		t.Fatalf("expected at least five recorded operations, got %d", n)
	}
	return n
}
