//go:build linux

package egress

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const platformAvailable = true

// soOriginalDst is the socket option that reports the pre-NAT destination of a
// redirected connection (SOL_IP / SOL_IPV6 level 80).
const soOriginalDst = 80

func sandboxAlive(s *Sandbox) bool {
	if s == nil || s.PID <= 0 {
		return false
	}
	if err := syscall.Kill(s.PID, 0); err != nil {
		return false
	}
	_, err := os.Stat(s.NSPath)
	return err == nil
}

// markStopped records an intentional shutdown so the reaper stays quiet.
func (s *Sandbox) markStopped() {
	s.stopOnce.Do(func() { close(s.stopped) })
}

// writeControl sends one response, optionally with a connected socket attached
// via SCM_RIGHTS.
func writeControl(conn net.Conn, resp controlResponse, fd net.Conn) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("egress: control connection is %T, not unix", conn)
	}
	payload, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	if fd == nil {
		_, _, err = uc.WriteMsgUnix(payload, nil, nil)
		return err
	}
	sc, ok := fd.(syscall.Conn)
	if !ok {
		return fmt.Errorf("egress: connection %T has no raw syscall handle", fd)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var writeErr error
	if err := rc.Control(func(raw uintptr) {
		_, _, writeErr = uc.WriteMsgUnix(payload, unix.UnixRights(int(raw)), nil)
	}); err != nil {
		return err
	}
	return writeErr
}

// startSandbox spawns the relay child, waits for it to become ready and starts
// its control loop.
func (m *Manager) startSandbox(taskID int64, sockPath string) (*Sandbox, error) {
	_ = os.Remove(sockPath)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("egress: control socket: %w", err)
	}
	_ = os.Chmod(sockPath, 0o600)

	bin, prefixArgs, err := relayExecutable(&m.cfg)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("egress: locate relay: %w", err)
	}
	cmd := exec.Command(bin, prefixArgs...)
	cmd.Env = append(os.Environ(),
		relayEnvVar+"=1",
		"ARTEX_EGRESS_SOCK="+sockPath,
		"ARTEX_EGRESS_RESOLVER="+m.cfg.Resolver,
		"ARTEX_EGRESS_TASK="+strconv.FormatInt(taskID, 10),
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		ln.Close()
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		ln.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		ln.Close()
		return nil, fmt.Errorf("egress: start relay (needs CAP_SYS_ADMIN/CLONE_NEWNET): %w", err)
	}
	job := &Sandbox{
		TaskID: taskID, PID: cmd.Process.Pid,
		NSPath:   "/proc/" + strconv.Itoa(cmd.Process.Pid) + "/ns/net",
		sockPath: sockPath, listener: ln, stopped: make(chan struct{}),
	}
	job.stop = func() { m.stopSandbox(job) }
	go func() {
		reader := newLineReader(stderr)
		for {
			line, ok := reader.next()
			if !ok {
				return
			}
			if strings.TrimSpace(line) != "" {
				m.cfg.Logf("[egress] task %d relay: %s", taskID, line)
			}
		}
	}()
	port, err := readReady(stdout, m.cfg.StartupTimeout)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		ln.Close()
		_ = os.Remove(sockPath)
		return nil, fmt.Errorf("egress: relay setup failed: %w", err)
	}
	job.Bridge = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	go m.serveControl(ln, taskID)
	go func() {
		werr := cmd.Wait()
		ln.Close()
		_ = os.Remove(sockPath)
		select {
		case <-job.stopped:
			return // intentional shutdown, not a failure
		default:
		}
		reason := "egress relay exited"
		if werr != nil {
			reason += ": " + werr.Error()
		}
		m.cfg.Logf("[egress] task %d %s", taskID, reason)
		if m.cfg.OnFailure != nil {
			m.cfg.OnFailure(taskID, reason)
		}
	}()
	return job, nil
}

// stopSandbox kills the relay, which tears its namespace down with it.
func (m *Manager) stopSandbox(job *Sandbox) {
	if job == nil {
		return
	}
	job.markStopped()
	job.listener.Close()
	if job.PID > 0 {
		_ = syscall.Kill(job.PID, syscall.SIGKILL)
	}
	_ = os.Remove(job.sockPath)
}

// readReady waits for the relay's "ready <port>" line.
func readReady(r io.Reader, timeout time.Duration) (int, error) {
	type result struct {
		port int
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		reader := newLineReader(r)
		for {
			line, ok := reader.next()
			if !ok {
				ch <- result{err: fmt.Errorf("relay exited before reporting readiness")}
				return
			}
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "ready" {
				port, err := strconv.Atoi(fields[1])
				ch <- result{port: port, err: err}
				return
			}
			if rest, ok := strings.CutPrefix(line, "error "); ok {
				ch <- result{err: fmt.Errorf("%s", rest)}
				return
			}
		}
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			return 0, res.err
		}
		return res.port, nil
	case <-time.After(timeout):
		return 0, fmt.Errorf("timed out after %s waiting for relay readiness", timeout)
	}
}

// lineReader is a minimal buffered line reader; bufio.Scanner caps line length
// and relay errors can carry long nft output.
type lineReader struct {
	r   io.Reader
	buf []byte
}

func newLineReader(r io.Reader) *lineReader { return &lineReader{r: r} }

func (l *lineReader) next() (string, bool) {
	tmp := make([]byte, 4096)
	for {
		if i := strings.IndexByte(string(l.buf), '\n'); i >= 0 {
			line := string(l.buf[:i])
			l.buf = l.buf[i+1:]
			return strings.TrimRight(line, "\r"), true
		}
		n, err := l.r.Read(tmp)
		if n > 0 {
			l.buf = append(l.buf, tmp[:n]...)
			continue
		}
		if err != nil {
			if len(l.buf) > 0 {
				line := string(l.buf)
				l.buf = nil
				return strings.TrimRight(line, "\r"), true
			}
			return "", false
		}
	}
}

// ---- relay child ----

// RelayMain runs the relay child. It is invoked from the package init when the
// parent sets ARTEX_EGRESS_RELAY=1, so the server binary, the egress-relay
// command and `go test` binaries all serve as their own relay.
func RelayMain() {
	os.Exit(runRelay())
}

func runRelay() int {
	sock := os.Getenv("ARTEX_EGRESS_SOCK")
	resolver := os.Getenv("ARTEX_EGRESS_RESOLVER")
	if sock == "" {
		fmt.Println("error ARTEX_EGRESS_SOCK is required")
		return 2
	}
	if resolver == "" {
		resolver = "1.1.1.1:53"
	}
	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
	if err := bringUpLoopback(); err != nil {
		fmt.Println("error " + err.Error())
		return 1
	}
	tcpLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		fmt.Println("error listen tcp: " + err.Error())
		return 1
	}
	tcpPort := tcpLn.Addr().(*net.TCPAddr).Port
	var tcp6Ln net.Listener
	if ln6, err := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(tcpPort))); err == nil {
		tcp6Ln = ln6
	}
	if err := installRules(tcpPort, tcp6Ln != nil); err != nil {
		fmt.Println("error " + err.Error())
		return 1
	}
	// The task's HTTP gateway address is mirrored inside the namespace so a
	// proxy-aware client keeps the same proxy URL it got on the host. The relay
	// forwards those connections to the real gateway, which applies the lease.
	bridgeAddr := os.Getenv("ARTEX_EGRESS_GATEWAY")
	var bridgeLn net.Listener
	if bridgeAddr != "" {
		bridgeLn, err = net.Listen("tcp4", bridgeAddr)
		if err != nil {
			fmt.Println("error listen gateway bridge: " + err.Error())
			return 1
		}
	}
	dnsUDP, err := net.ListenPacket("udp4", "127.0.0.1:53")
	if err != nil {
		fmt.Println("error listen dns/udp: " + err.Error())
		return 1
	}
	dnsTCP, err := net.Listen("tcp4", "127.0.0.1:53")
	if err != nil {
		fmt.Println("error listen dns/tcp: " + err.Error())
		return 1
	}
	readyPort := 0
	if bridgeLn != nil {
		readyPort = bridgeLn.Addr().(*net.TCPAddr).Port
	}
	fmt.Printf("ready %d\n", readyPort)

	client := &relayClient{sock: sock, resolver: resolver, logf: logf}
	go serveTCP(tcpLn, client, true)
	if tcp6Ln != nil {
		go serveTCP(tcp6Ln, client, true)
	}
	if bridgeLn != nil {
		go serveTCP(bridgeLn, client, false)
	}
	go serveDNS(dnsTCP, dnsUDP, client)
	select {}
}

func bringUpLoopback() error {
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		return fmt.Errorf("bring up loopback: %v: %s", err, strings.TrimSpace(string(out)))
	}
	// A default route keeps connect() from failing before the nat OUTPUT hook
	// rewrites the destination. Nothing can actually leave: the filter chain
	// only accepts loopback.
	// The source address must be a real local address: with an address-less
	// default route the kernel selects 0.0.0.0 and the reverse NAT reply is never
	// delivered back to the client.
	if out, err := exec.Command("ip", "route", "add", "default", "dev", "lo", "src", "127.0.0.1").CombinedOutput(); err != nil {
		if !strings.Contains(string(out), "File exists") {
			return fmt.Errorf("default route: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// installRules writes the namespace's policy: every outbound TCP connection is
// redirected to the relay, DNS (UDP+TCP 53) is redirected to the relay's
// resolver bridge, and everything that is not loopback is dropped. A
// proxy-ignoring program therefore cannot leak direct.
func installRules(tcpPort int, ipv6 bool) error {
	v4 := fmt.Sprintf(`
add table ip artex_egress
add chain ip artex_egress out { type nat hook output priority -100 ; policy accept ; }
add rule ip artex_egress out ip daddr 127.0.0.0/8 accept
add rule ip artex_egress out meta l4proto tcp redirect to :%[1]d
add rule ip artex_egress out meta l4proto udp udp dport 53 redirect to :53
add chain ip artex_egress filter { type filter hook output priority 0 ; policy drop ; }
add rule ip artex_egress filter oifname "lo" accept
`, tcpPort)
	script := v4
	if ipv6 {
		script += fmt.Sprintf(`
add table ip6 artex_egress
add chain ip6 artex_egress out { type nat hook output priority -100 ; policy accept ; }
add rule ip6 artex_egress out ip6 daddr ::1 accept
add rule ip6 artex_egress out meta l4proto tcp redirect to :%[1]d
add rule ip6 artex_egress out meta l4proto udp udp dport 53 redirect to :53
add chain ip6 artex_egress filter { type filter hook output priority 0 ; policy drop ; }
add rule ip6 artex_egress filter oifname "lo" accept
`, tcpPort)
	}
	err := runNFT(script)
	if err == nil {
		return nil
	}
	if !ipv6 {
		return err
	}
	// Some kernels reject nat redirection for IPv6. Fall back to IPv4-only with
	// all IPv6 egress dropped, which still fails closed.
	if err2 := runNFT(v4); err2 != nil {
		return fmt.Errorf("nftables install failed: %v (ipv4-only retry: %v)", err, err2)
	}
	return nil
}

func runNFT(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// relayClient talks to the parent over the control socket. Each request opens
// its own connection and blocks until the parent has handed back a connected
// fd, so a slow upstream dial never stalls other task traffic.
type relayClient struct {
	sock     string
	resolver string
	logf     func(string, ...any)
	prefix   []byte
}

// prefixedConn replays buffered bytes before reading from the real connection.
type prefixedConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixedConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *relayClient) dial(op, address string) (net.Conn, error) {
	conn, err := net.DialTimeout("unix", c.sock, 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	uc := conn.(*net.UnixConn)
	_ = uc.SetDeadline(time.Now().Add(60 * time.Second))
	payload, _ := json.Marshal(controlRequest{Op: op, Address: address})
	payload = append(payload, '\n')
	if _, err := uc.Write(payload); err != nil {
		return nil, err
	}
	buf := make([]byte, 8192)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := uc.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, err
	}
	var resp controlResponse
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		return nil, fmt.Errorf("egress relay: bad control response: %w", err)
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "task egress refused the connection"
		}
		return nil, fmt.Errorf("%s", resp.Error)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) == 0 {
		return nil, fmt.Errorf("egress relay: parent sent no socket: %v", err)
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) == 0 {
		return nil, fmt.Errorf("egress relay: cannot read passed socket: %v", err)
	}
	if len(resp.Prefix) > 0 {
		c.prefix = resp.Prefix
	}
	file := os.NewFile(uintptr(fds[0]), "egress-upstream")
	up, err := net.FileConn(file)
	file.Close()
	if err != nil {
		return nil, err
	}
	if c.prefix == nil {
		return up, nil
	}
	// The parent consumed the first tunneled bytes while reading the proxy
	// handshake; hand them to the caller before the live connection.
	prefix := c.prefix
	c.prefix = nil
	return &prefixedConn{Conn: up, prefix: prefix}, nil
}

func serveTCP(ln net.Listener, client *relayClient, transparent bool) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleTCP(conn, client, transparent)
	}
}

func handleTCP(conn net.Conn, client *relayClient, transparent bool) {
	defer conn.Close()
	address := conn.LocalAddr().String()
	op := "gateway"
	if transparent {
		op = "dial"
		dst, err := originalDestination(conn)
		if err != nil {
			client.logf("task egress: original destination unavailable: %v", err)
			return
		}
		address = dst
	}
	up, err := client.dial(op, address)
	if err != nil {
		client.logf("task egress: %s %s: %v", op, address, err)
		return
	}
	defer up.Close()
	bridge(conn, up)
}

func bridge(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	<-done
}

// originalDestination reads IP_ORIGDSTADDR / IPV6_ORIGDSTADDR off the socket.
func originalDestination(conn net.Conn) (string, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return "", fmt.Errorf("connection %T has no raw handle", conn)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return "", err
	}
	var (
		out    string
		outErr error
	)
	if err := rc.Control(func(fd uintptr) {
		if addr, err := originalDst4(fd); err == nil {
			out = addr
			return
		}
		addr, err := originalDst6(fd)
		if err != nil {
			outErr = err
			return
		}
		out = addr
	}); err != nil {
		return "", err
	}
	return out, outErr
}

func originalDst4(fd uintptr) (string, error) {
	var addr syscall.RawSockaddrInet4
	size := uint32(unsafe.Sizeof(addr))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.SOL_IP, soOriginalDst,
		uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return "", errno
	}
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr.Port))[:])
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), nil
}

func originalDst6(fd uintptr) (string, error) {
	var addr syscall.RawSockaddrInet6
	size := uint32(unsafe.Sizeof(addr))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.SOL_IPV6, soOriginalDst,
		uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return "", errno
	}
	ip := make(net.IP, 16)
	for i := range 16 {
		ip[i] = addr.Addr[i]
	}
	port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr.Port))[:])
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), nil
}

// serveDNS answers redirected DNS: UDP queries are resolved over TCP through the
// task route (never sent direct) and TCP queries are spliced straight through.
func serveDNS(dnsTCP net.Listener, udp net.PacketConn, client *relayClient) {
	go func() {
		for {
			conn, err := dnsTCP.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				up, err := client.dial("dns", client.resolver)
				if err != nil {
					client.logf("task egress: dns/tcp: %v", err)
					return
				}
				defer up.Close()
				bridge(conn, up)
			}(conn)
		}
	}()
	buf := make([]byte, 65535)
	for {
		n, from, err := udp.ReadFrom(buf)
		if err != nil {
			return
		}
		query := append([]byte(nil), buf[:n]...)
		go func(query []byte, from net.Addr) {
			answer, err := exchangeTCP(client, query)
			if err != nil {
				client.logf("task egress: dns/udp: %v", err)
				return
			}
			if len(answer) > 512 && len(query) < 12+11 {
				// The query carried no EDNS0 buffer, so the client only accepts
				// 512 bytes over UDP; truncate and let it retry over TCP, which
				// is spliced through the same route.
				answer = answer[:512]
				answer[2] |= 0x02
			}
			_, _ = udp.WriteTo(answer, from)
		}(query, from)
	}
}

// exchangeTCP performs one DNS-over-TCP exchange through the parent.
func exchangeTCP(client *relayClient, query []byte) ([]byte, error) {
	if len(query) > 65535 {
		return nil, fmt.Errorf("query too large")
	}
	conn, err := client.dial("dns", client.resolver)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed, uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, err
	}
	answer := make([]byte, int(binary.BigEndian.Uint16(head)))
	if _, err := io.ReadFull(conn, answer); err != nil {
		return nil, err
	}
	return answer, nil
}
