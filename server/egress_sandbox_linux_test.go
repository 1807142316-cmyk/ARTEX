//go:build linux

package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	actool "github.com/Autumn-27/norma/tool"
)

// These are the #8 Linux acceptance tests. They need a real PostgreSQL
// (ARTEX_PG_DSN) and a root/CAP_SYS_ADMIN host with nftables, iproute2,
// util-linux and python3, so they are gated behind ARTEX_EGRESS_SANDBOX=1.
func requireEgressSandbox(t *testing.T) {
	t.Helper()
	if os.Getenv("ARTEX_EGRESS_SANDBOX") != "1" {
		t.Skip("set ARTEX_EGRESS_SANDBOX=1 on a Linux host with CLONE_NEWNET, nftables and nsenter")
	}
	for _, tool := range []string{"nft", "nsenter", "ip", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is required: %v", tool, err)
		}
	}
}

// fakeExitProxy is one task's upstream proxy. It answers health checks, replies
// to every CONNECT with the task marker, and speaks DNS-over-TCP on the resolver
// port so the DNS path can be observed through the same proxy.
type fakeExitProxy struct {
	marker   string
	exitIP   string
	dnsIP    net.IP
	server   *httptest.Server
	connect  chan string
	resolved chan string
}

func newFakeExitProxy(t *testing.T, marker, exitIP string, dnsIP net.IP) *fakeExitProxy {
	t.Helper()
	proxy := &fakeExitProxy{marker: marker, exitIP: exitIP, dnsIP: dnsIP, connect: make(chan string, 32), resolved: make(chan string, 32)}
	proxy.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/exit" {
			fmt.Fprintf(w, `{"ip":%q}`, proxy.exitIP)
			return
		}
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		select {
		case proxy.connect <- r.Host:
		default:
		}
		local, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer local.Close()
		_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buffered.Flush()
		_, port, _ := net.SplitHostPort(r.Host)
		if port == "53" {
			serveFakeDNS(local, proxy, t)
			return
		}
		fmt.Fprint(local, proxy.marker+"\n")
	}))
	t.Cleanup(proxy.server.Close)
	return proxy
}

// serveFakeDNS answers DNS-over-TCP with the task's marker address.
func serveFakeDNS(conn net.Conn, proxy *fakeExitProxy, t *testing.T) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	for {
		head := make([]byte, 2)
		if _, err := io.ReadFull(conn, head); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(head))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		if len(query) < 12 {
			return
		}
		i := 12
		for i < len(query) && query[i] != 0 {
			i += int(query[i]) + 1
		}
		i++
		if i+4 > len(query) {
			return
		}
		reply := make([]byte, 12)
		copy(reply[0:2], query[0:2])
		reply[2], reply[3] = 0x81, 0x80
		binary.BigEndian.PutUint16(reply[4:6], 1)
		binary.BigEndian.PutUint16(reply[6:8], 1)
		reply = append(reply, query[12:i+4]...)
		reply = append(reply, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04)
		reply = append(reply, proxy.dnsIP.To4()...)
		framed := make([]byte, 2+len(reply))
		binary.BigEndian.PutUint16(framed, uint16(len(reply)))
		copy(framed[2:], reply)
		if _, err := conn.Write(framed); err != nil {
			return
		}
		select {
		case proxy.resolved <- proxy.dnsIP.String():
		default:
		}
	}
}

type sandboxTask struct {
	id      string
	taskID  int64
	proxy   *fakeExitProxy
	cleanup func()
}

// newSandboxTask creates a task, registers a fake proxy, health-checks it and
// assigns the task its own lease.
func newSandboxTask(t *testing.T, s *Server, api func(string, string, any) map[string]any, marker string, index int) *sandboxTask {
	t.Helper()
	proxy := newFakeExitProxy(t, marker, fmt.Sprintf("192.0.2.%d", 60+index), net.IPv4(192, 0, 2, byte(60+index)))
	endpoint := api("POST", "/api/proxies", map[string]any{
		"name": marker, "url": proxy.server.URL, "check_url": "http://proxy-check.test/exit", "enabled": true,
	})
	api("POST", fmt.Sprintf("/api/proxies/%.0f/check", endpoint["id"]), nil)
	task, err := s.m.CreateTask(marker, "egress acceptance", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	lease := api("POST", "/api/tasks/"+task.ID+"/egress", map[string]any{"proxy_id": endpoint["id"]})
	if lease["proxy_url"] == nil {
		t.Fatalf("task %s lease missing proxy_url: %v", task.ID, lease)
	}
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	return &sandboxTask{id: task.ID, taskID: id, proxy: proxy, cleanup: func() { api("DELETE", "/api/tasks/"+task.ID, nil) }}
}

// bashFor runs the real assembled Bash tool with RunInfo for the task.
func bashFor(t *testing.T, s *Server, taskID int64, env []string, script string) string {
	t.Helper()
	ctx := context.Background()
	ctx = agent.WithRunInfo(ctx, agent.RunInfo{TaskID: taskID})
	tools, _, cleanup := agent.AugmentTools(ctx, "worker", []actool.CoreTool{actool.NewBash()})
	defer cleanup()
	var bash actool.CoreTool
	for _, tool := range tools {
		if tool.Name() == "Bash" {
			bash = tool
		}
	}
	if bash == nil {
		t.Fatal("assembled Bash absent")
	}
	input, _ := json.Marshal(map[string]any{"command": script, "timeout_ms": 20000})
	result, err := bash.Call(ctx, input, &actool.ToolContext{WorkingDir: t.TempDir(), Env: env})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	return string(encoded)
}

// TestEgressSandboxTwoTasksKeepSeparateExitsAndDNS is the primary acceptance
// case: the real Bash tool, two tasks, two fake upstream proxies, NO_PROXY=* and
// a proxy-ignoring python client; plus a DNS query through the same lease.
func TestEgressSandboxTwoTasksKeepSeparateExitsAndDNS(t *testing.T) {
	requireEgressSandbox(t)
	m := newProxyPoolTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	t.Cleanup(func() { s.proxyPool.egress.close() })
	api := newEgressAPI(t, s)
	api("PUT", "/api/proxies/settings", map[string]any{"enabled": true})
	api("PUT", "/api/egress/settings", map[string]any{"enabled": true})
	defer api("PUT", "/api/egress/settings", map[string]any{"enabled": false})
	defer api("PUT", "/api/proxies/settings", map[string]any{"enabled": false})

	var tasks []*sandboxTask
	for i := 1; i <= 2; i++ {
		tasks = append(tasks, newSandboxTask(t, s, api, fmt.Sprintf("exit-%d", i), i))
	}
	defer func() {
		for _, task := range tasks {
			task.cleanup()
		}
	}()

	rawTCP := `python3 -I -c 'import socket; s=socket.create_connection(("203.0.113.9",8080),8); print(s.recv(256).decode().strip())'`
	dnsQuery := `python3 -I -c '
import socket,struct
q=struct.pack(">HHHHHH",0x2222,0x0100,1,0,0,0)
for part in "egress.example".split("."):
    q+=bytes([len(part)])+part.encode()
q+=b"\x00"+struct.pack(">HH",1,1)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(8)
s.sendto(q,("8.8.8.8",53))
data,_=s.recvfrom(2048)
print(".".join(str(b) for b in data[-4:]))
'`
	env := []string{"NO_PROXY=*", "no_proxy=*", "HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "PATH=" + os.Getenv("PATH")}
	for _, task := range tasks {
		out := bashFor(t, s, task.taskID, env, rawTCP)
		if !strings.Contains(out, task.proxy.marker) {
			t.Fatalf("task %s raw TCP did not use its own exit: %s", task.id, out)
		}
		out = bashFor(t, s, task.taskID, env, dnsQuery)
		want := task.proxy.dnsIP.String()
		if !strings.Contains(out, want) {
			t.Fatalf("task %s DNS did not use its own exit (want %s): %s", task.id, want, out)
		}
		select {
		case <-task.proxy.resolved:
		case <-time.After(5 * time.Second):
			t.Fatalf("task %s resolver never saw the DNS query", task.id)
		}
	}
	// The two tasks must not have shared a proxy.
	if tasks[0].proxy.marker == tasks[1].proxy.marker {
		t.Fatal("fixtures are not distinct")
	}
}

// TestEgressSandboxSetupFailurePausesTask proves a relay that cannot start stops
// the command and pauses the task with an audit event instead of running direct.
func TestEgressSandboxSetupFailurePausesTask(t *testing.T) {
	requireEgressSandbox(t)
	m := newProxyPoolTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	t.Cleanup(func() { s.proxyPool.egress.close() })
	api := newEgressAPI(t, s)
	api("PUT", "/api/proxies/settings", map[string]any{"enabled": true})
	api("PUT", "/api/egress/settings", map[string]any{"enabled": true})
	defer api("PUT", "/api/egress/settings", map[string]any{"enabled": false})
	defer api("PUT", "/api/proxies/settings", map[string]any{"enabled": false})

	task := newSandboxTask(t, s, api, "setup-fail", 1)
	defer task.cleanup()
	previous := egressRelayBinary
	egressRelayBinary = "/bin/false"
	defer func() { egressRelayBinary = previous }()

	out := bashFor(t, s, task.taskID, nil, "echo leaked-direct")
	if !strings.Contains(out, "沙箱建立失败") {
		t.Fatalf("sandbox setup failure was not surfaced: %s", out)
	}
	if strings.Contains(out, "leaked-direct") {
		t.Fatalf("command ran outside the sandbox: %s", out)
	}
	lease := api("GET", "/api/tasks/"+task.id+"/egress", nil)
	states, _ := json.Marshal(lease)
	if !strings.Contains(string(states), "paused") {
		t.Fatalf("task egress was not paused: %s", states)
	}
	events, _ := json.Marshal(lease["events"])
	if !strings.Contains(string(events), "sandbox") {
		t.Fatalf("no audit event recorded: %s", events)
	}
}

// TestEgressSandboxFailureAppliesPausePolicy kills a live relay and checks the
// default pause policy records an event and stops the lease.
func TestEgressSandboxFailureAppliesPausePolicy(t *testing.T) {
	requireEgressSandbox(t)
	m := newProxyPoolTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	t.Cleanup(func() { s.proxyPool.egress.close() })
	api := newEgressAPI(t, s)
	api("PUT", "/api/proxies/settings", map[string]any{"enabled": true})
	api("PUT", "/api/egress/settings", map[string]any{"enabled": true})
	defer api("PUT", "/api/egress/settings", map[string]any{"enabled": false})
	defer api("PUT", "/api/proxies/settings", map[string]any{"enabled": false})

	task := newSandboxTask(t, s, api, "death-1", 2)
	defer task.cleanup()
	if out := bashFor(t, s, task.taskID, nil, "true"); strings.Contains(out, "沙箱建立失败") {
		t.Fatalf("sandbox did not start: %s", out)
	}
	sandbox, err := s.egress.forTask(ctx, task.taskID)
	if err != nil || sandbox == nil {
		t.Fatalf("sandbox missing: %v", err)
	}
	if err := exec.Command("kill", "-9", strconv.Itoa(sandbox.PID)).Run(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		lease := api("GET", "/api/tasks/"+task.id+"/egress", nil)
		encoded, _ := json.Marshal(lease)
		if strings.Contains(string(encoded), "sandbox_failed") && strings.Contains(string(encoded), `"state":"paused"`) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	lease := api("GET", "/api/tasks/"+task.id+"/egress", nil)
	encoded, _ := json.Marshal(lease)
	t.Fatalf("default pause policy was not applied after relay death: %s", encoded)
}

// TestEgressSandboxExplicitDirectFallbackIsRecorded proves an explicit direct
// policy is honoured after the relay dies: traffic leaves directly and the
// transition is audited.
func TestEgressSandboxExplicitDirectFallbackIsRecorded(t *testing.T) {
	requireEgressSandbox(t)
	m := newProxyPoolTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	t.Cleanup(func() { s.proxyPool.egress.close() })
	api := newEgressAPI(t, s)
	api("PUT", "/api/proxies/settings", map[string]any{"enabled": true})
	api("PUT", "/api/egress/settings", map[string]any{"enabled": true})
	defer api("PUT", "/api/egress/settings", map[string]any{"enabled": false})
	defer api("PUT", "/api/proxies/settings", map[string]any{"enabled": false})

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "system-default-exit")
	}))
	defer target.Close()
	task := newSandboxTask(t, s, api, "direct-1", 3)
	defer task.cleanup()
	lease := api("POST", "/api/tasks/"+task.id+"/egress", map[string]any{"policy": "direct"})
	if lease["policy"] != "direct" {
		t.Fatalf("policy not applied: %v", lease)
	}
	sandbox, err := s.egress.forTask(ctx, task.taskID)
	if err != nil || sandbox == nil {
		t.Fatalf("sandbox missing: %v", err)
	}
	_ = exec.Command("kill", "-9", strconv.Itoa(sandbox.PID)).Run()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		current := api("GET", "/api/tasks/"+task.id+"/egress", nil)
		encoded, _ := json.Marshal(current)
		if strings.Contains(string(encoded), "sandbox_failed") {
			if !strings.Contains(string(encoded), `"state":"direct"`) {
				t.Fatalf("direct policy was not kept: %s", encoded)
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("relay death never produced an audit event")
}

// newEgressAPI builds the authenticated API helper shared by these tests.
func newEgressAPI(t *testing.T, s *Server) func(string, string, any) map[string]any {
	t.Helper()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	handler := s.Handler()
	return func(method, path string, payload any) map[string]any {
		t.Helper()
		var body io.Reader = http.NoBody
		if payload != nil {
			encoded, _ := json.Marshal(payload)
			body = bytes.NewReader(encoded)
		}
		r := httptest.NewRequest(method, path, body)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code < 200 || w.Code >= 300 {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body)
		}
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
}
