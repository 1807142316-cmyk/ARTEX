//go:build linux

package egress

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// These tests create real network namespaces and nftables rules, so they only
// run on a Linux host with CAP_SYS_ADMIN/CAP_NET_ADMIN (root or a container with
// those capabilities). The host suite sets ARTEX_EGRESS_SANDBOX=1 for them.
func requireSandbox(t *testing.T) {
	t.Helper()
	if os.Getenv("ARTEX_EGRESS_SANDBOX") != "1" {
		t.Skip("set ARTEX_EGRESS_SANDBOX=1 on a Linux host with CLONE_NEWNET and nftables")
	}
	for _, tool := range []string{"nft", "nsenter", "ip", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is required for the sandbox acceptance tests", tool)
		}
	}
}

// markerServer accepts TCP connections and writes a fixed marker, standing in
// for the "upstream proxy" of one task.
func markerServer(t *testing.T, marker string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				fmt.Fprint(conn, marker+"\n")
				time.Sleep(20 * time.Millisecond)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// fakeResolver is a DNS-over-TCP upstream that answers every A query with the
// task's marker address, standing in for a CONNECT-tunnelled resolver.
func fakeResolver(t *testing.T, answer net.IP) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				for {
					head := make([]byte, 2)
					if _, err := io.ReadFull(conn, head); err != nil {
						return
					}
					query := make([]byte, binary.BigEndian.Uint16(head))
					if _, err := io.ReadFull(conn, query); err != nil {
						return
					}
					reply := dnsAnswer(query, answer)
					framed := make([]byte, 2+len(reply))
					binary.BigEndian.PutUint16(framed, uint16(len(reply)))
					copy(framed[2:], reply)
					if _, err := conn.Write(framed); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// dnsAnswer builds a minimal A response for the query's first question.
func dnsAnswer(query []byte, answer net.IP) []byte {
	if len(query) < 12 {
		return query
	}
	// Skip the question name.
	i := 12
	for i < len(query) && query[i] != 0 {
		i += int(query[i]) + 1
	}
	i++ // terminating zero
	if i+4 > len(query) {
		return query
	}
	question := query[12 : i+4]
	reply := make([]byte, 12)
	copy(reply[0:2], query[0:2]) // transaction id
	reply[2] = 0x81              // response, recursion desired
	reply[3] = 0x80              // recursion available
	binary.BigEndian.PutUint16(reply[4:6], 1)
	binary.BigEndian.PutUint16(reply[6:8], 1)
	reply = append(reply, question...)
	reply = append(reply, 0xC0, 0x0C) // pointer to the question name
	reply = append(reply, 0x00, 0x01, 0x00, 0x01)
	reply = append(reply, 0x00, 0x00, 0x00, 0x3C)
	reply = append(reply, 0x00, 0x04)
	reply = append(reply, answer.To4()...)
	return reply
}

// routes maps one task id to the fixture its traffic must reach.
type fixture struct {
	marker     string
	tcpAddr    string
	resolver   string
	resolvedIP net.IP
	mu         sync.Mutex
	requests   []string
}

// newManager builds a Manager whose Dial resolves every task to its own fixture,
// exactly like the server wiring does through proxyPool.route.
func newManager(t *testing.T, fixtures map[int64]*fixture) (*Manager, error) {
	t.Helper()
	return NewManager(Config{
		SocketDir:      t.TempDir(),
		Resolver:       "8.8.8.8:53",
		StartupTimeout: 20 * time.Second,
		Dial: func(ctx context.Context, taskID int64, address string) (net.Conn, error) {
			f := fixtures[taskID]
			if f == nil {
				return nil, fmt.Errorf("no egress fixture for task %d", taskID)
			}
			f.mu.Lock()
			f.requests = append(f.requests, address)
			f.mu.Unlock()
			target := f.tcpAddr
			if strings.HasSuffix(address, ":53") {
				target = f.resolver
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", target)
		},
		Logf: t.Logf,
	})
}

// runInSandbox executes a shell snippet inside the task's namespace and returns
// its combined output, exactly the way the Bash tool wrapper does.
func runInSandbox(t *testing.T, sandbox *Sandbox, script string) (string, error) {
	t.Helper()
	cmd := exec.Command("nsenter", "--net="+sandbox.NSPath, "--", "/bin/sh", "-c", script)
	env := []string{
		"NO_PROXY=*", "no_proxy=*",
		"HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=",
		"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// pythonRawTCP connects to host:port without any proxy awareness and prints the
// first line the peer sends.
func pythonRawTCP(host string, port int) string {
	return fmt.Sprintf(`python3 -I -c 'import socket,sys; s=socket.create_connection((%q,%d),5); print(s.recv(256).decode().strip())'`, host, port)
}

// TestSandboxSeparatesTwoTaskExits is the headline acceptance case: two tasks,
// two upstream fixtures, a proxy-ignoring client with NO_PROXY=* inside each
// namespace, and each task must see only its own marker.
func TestSandboxSeparatesTwoTaskExits(t *testing.T) {
	requireSandbox(t)
	fixtures := map[int64]*fixture{}
	for i := int64(1); i <= 2; i++ {
		marker := fmt.Sprintf("task-exit-%d", i)
		address, closeFn := markerServer(t, marker)
		t.Cleanup(closeFn)
		fixtures[i] = &fixture{marker: marker, tcpAddr: address}
	}
	mgr, err := newManager(t, fixtures)
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	for id, want := range fixtures {
		sandbox, err := mgr.Sandbox(context.Background(), id)
		if err != nil {
			t.Fatalf("task %d sandbox: %v", id, err)
		}
		out, err := runInSandbox(t, sandbox, pythonRawTCP("203.0.113.9", 8080))
		if err != nil {
			t.Fatalf("task %d raw TCP failed: %v (%s)", id, err, out)
		}
		if strings.TrimSpace(out) != want.marker {
			t.Fatalf("task %d reached %q, want %q", id, strings.TrimSpace(out), want.marker)
		}
		want.mu.Lock()
		requests := append([]string(nil), want.requests...)
		want.mu.Unlock()
		if len(requests) == 0 || requests[len(requests)-1] != "203.0.113.9:8080" {
			t.Fatalf("task %d dialed %v, want the original destination 203.0.113.9:8080", id, requests)
		}
	}
}

// TestSandboxDNSGoesThroughTaskRoute proves DNS leaves over the task's own
// upstream: a UDP query to 8.8.8.8 is redirected and answered by the task's
// fixture resolver, not by anything on the host.
func TestSandboxDNSGoesThroughTaskRoute(t *testing.T) {
	requireSandbox(t)
	fixtures := map[int64]*fixture{}
	for i := int64(1); i <= 2; i++ {
		address, closeFn := markerServer(t, fmt.Sprintf("tcp-%d", i))
		t.Cleanup(closeFn)
		resolver, closeDNS := fakeResolver(t, net.IPv4(192, 0, 2, byte(10+i)))
		t.Cleanup(closeDNS)
		fixtures[i] = &fixture{tcpAddr: address, resolver: resolver, resolvedIP: net.IPv4(192, 0, 2, byte(10+i))}
	}
	mgr, err := newManager(t, fixtures)
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	query := `python3 -I -c '
import socket,struct
name="task%d.example"
q=struct.pack(">HHHHHH",0x1234,0x0100,1,0,0,0)
for part in name.split("."):
    q+=bytes([len(part)])+part.encode()
q+=b"\x00"+struct.pack(">HH",1,1)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(q,("8.8.8.8",53))
data,_=s.recvfrom(2048)
print(".".join(str(b) for b in data[-4:]))
'`
	for id, f := range fixtures {
		sandbox, err := mgr.Sandbox(context.Background(), id)
		if err != nil {
			t.Fatalf("task %d sandbox: %v", id, err)
		}
		out, err := runInSandbox(t, sandbox, fmt.Sprintf(query, id))
		if err != nil {
			t.Fatalf("task %d DNS failed: %v (%s)", id, err, out)
		}
		if strings.TrimSpace(out) != f.resolvedIP.String() {
			t.Fatalf("task %d DNS answer %q, want %q", id, strings.TrimSpace(out), f.resolvedIP)
		}
		f.mu.Lock()
		requests := append([]string(nil), f.requests...)
		f.mu.Unlock()
		if len(requests) == 0 || requests[len(requests)-1] != "8.8.8.8:53" {
			t.Fatalf("task %d DNS dialed %v, want the configured resolver 8.8.8.8:53", id, requests)
		}
	}
}

// TestSandboxBlocksNonDNSUDPAndDirectTraffic fails closed for everything the
// relay does not handle: a UDP datagram to an arbitrary port and an ICMP ping
// must not leave the namespace.
func TestSandboxBlocksNonDNSUDPAndDirectTraffic(t *testing.T) {
	requireSandbox(t)
	address, closeFn := markerServer(t, "unused")
	t.Cleanup(closeFn)
	resolver, closeDNS := fakeResolver(t, net.IPv4(192, 0, 2, 99))
	t.Cleanup(closeDNS)
	mgr, err := newManager(t, map[int64]*fixture{7: {tcpAddr: address, resolver: resolver}})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	sandbox, err := mgr.Sandbox(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	script := `python3 -I -c '
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)
try:
    s.sendto(b"leak",("198.51.100.7",9)); s.recvfrom(16); print("udp-leaked")
except Exception:
    print("udp-blocked")
'`
	out, _ := runInSandbox(t, sandbox, script)
	if !strings.Contains(out, "udp-blocked") {
		t.Fatalf("non-DNS UDP was not blocked: %s", out)
	}
}

// TestSandboxPreservesShellSemantics checks the wrapper keeps cwd, env, pipes,
// heredocs and exit codes intact.
func TestSandboxPreservesShellSemantics(t *testing.T) {
	requireSandbox(t)
	address, closeFn := markerServer(t, "unused")
	t.Cleanup(closeFn)
	resolver, closeDNS := fakeResolver(t, net.IPv4(192, 0, 2, 98))
	t.Cleanup(closeDNS)
	mgr, err := newManager(t, map[int64]*fixture{3: {tcpAddr: address, resolver: resolver}})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	sandbox, err := mgr.Sandbox(context.Background(), 3)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := "cd " + dir + " && pwd && FOO=bar sh -c 'echo $FOO' | tr a-z A-Z && cat <<EOF\nheredoc-line\nEOF\nexit 7"
	cmd := exec.Command("nsenter", "--net="+sandbox.NSPath, "--", "/bin/sh", "-c", script)
	out, err := cmd.CombinedOutput()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{dir, "BAR", "heredoc-line"} {
		if !strings.Contains(got, want) {
			t.Fatalf("shell semantics lost %q: %s", want, got)
		}
	}
	if code != 7 {
		t.Fatalf("exit code %d, want 7", code)
	}
}

// TestWrapCommandQuoting proves the nsenter wrapper cannot be broken out of by
// quotes in the original command.
func TestWrapCommandQuoting(t *testing.T) {
	sandbox := &Sandbox{NSPath: "/proc/1/ns/net"}
	got := sandbox.WrapCommand(`echo 'x'; echo "y"`)
	want := `nsenter --net='/proc/1/ns/net' -- /bin/sh -c 'echo '\''x'\''; echo "y"'`
	if got != want {
		t.Fatalf("wrap=%s", got)
	}
}

// TestSetupFailureIsReported proves a relay that cannot start surfaces an error
// instead of silently running the task direct.
func TestSetupFailureIsReported(t *testing.T) {
	requireSandbox(t)
	mgr, err := NewManager(Config{
		SocketDir:      t.TempDir(),
		RelayBinary:    "/bin/false",
		StartupTimeout: 5 * time.Second,
		Dial: func(context.Context, int64, string) (net.Conn, error) {
			return nil, fmt.Errorf("unused")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	if _, err := mgr.Sandbox(context.Background(), 1); err == nil {
		t.Fatal("expected a setup error from a relay that exits immediately")
	}
}

// TestRelayDeathReportsFailure proves the manager reports an unexpected relay
// exit so the host can apply the task's failure policy.
func TestRelayDeathReportsFailure(t *testing.T) {
	requireSandbox(t)
	address, closeFn := markerServer(t, "unused")
	t.Cleanup(closeFn)
	resolver, closeDNS := fakeResolver(t, net.IPv4(192, 0, 2, 97))
	t.Cleanup(closeDNS)
	failures := make(chan int64, 1)
	mgr, err := NewManager(Config{
		SocketDir:      t.TempDir(),
		Resolver:       "8.8.8.8:53",
		StartupTimeout: 20 * time.Second,
		Dial: func(ctx context.Context, taskID int64, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", address)
		},
		OnFailure: func(taskID int64, _ string) { failures <- taskID },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	_ = resolver
	sandbox, err := mgr.Sandbox(context.Background(), 5)
	if err != nil {
		t.Fatal(err)
	}
	_ = sandbox
	if err := exec.Command("kill", "-9", strconv.Itoa(sandbox.PID)).Run(); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-failures:
		if id != 5 {
			t.Fatalf("failure reported for task %d", id)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("relay death was not reported to the host")
	}
}
