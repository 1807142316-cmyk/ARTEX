package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// controlRequest is one line of the relay→parent protocol. The relay opens a
// fresh connection per request so a slow dial can never block another one.
type controlRequest struct {
	Op      string `json:"op"`      // dial | dns | gateway
	Address string `json:"address"` // dial: destination; dns: resolver; gateway: host loopback
}

type controlResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Prefix carries bytes the parent already read past the proxy handshake
	// (e.g. the first bytes of a CONNECT tunnel). The relay replays them to the
	// client before splicing, because only the raw fd travels over SCM_RIGHTS.
	Prefix []byte `json:"prefix,omitempty"`
}

// Sandbox is one task's live network namespace and relay process.
type Sandbox struct {
	TaskID int64
	PID    int
	NSPath string
	// Bridge is the host-loopback address inside the sandbox that forwards to
	// the task's HTTP gateway; pooled proxy-aware clients can be pointed at it.
	Bridge string

	sockPath string
	listener *net.UnixListener
	stopped  chan struct{}
	stopOnce sync.Once
	stop     func()
}

// Close tears the sandbox down. Safe to call more than once.
func (s *Sandbox) Close() {
	if s != nil && s.stop != nil {
		s.stop()
	}
}

// WrapCommand returns the shell command that runs command inside the sandbox.
//
// nsenter enters the relay's network namespace and then runs /bin/sh -c with the
// original command as a single argument, so quoting, pipes, heredocs and exit
// codes are exactly what they were outside the sandbox. The process itself
// still lives in the host pid/mount/user namespaces, so cwd, files and output
// paths are unchanged.
func (s *Sandbox) WrapCommand(command string) string {
	return "nsenter --net=" + shellQuote(s.NSPath) + " -- /bin/sh -c " + shellQuote(command)
}

// shellQuote wraps s in single quotes, escaping embedded quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Manager owns the per-task sandboxes of one server process.
type Manager struct {
	cfg Config

	mu    sync.Mutex
	byID  map[int64]*Sandbox
	close bool
}

// NewManager validates cfg and prepares the socket directory.
func NewManager(cfg Config) (*Manager, error) {
	cfg.normalize()
	if cfg.Dial == nil {
		return nil, errors.New("egress: Dial is required")
	}
	if cfg.SocketDir == "" {
		return nil, errors.New("egress: SocketDir is required")
	}
	if err := os.MkdirAll(cfg.SocketDir, 0o700); err != nil {
		return nil, fmt.Errorf("egress: create socket dir: %w", err)
	}
	return &Manager{cfg: cfg, byID: map[int64]*Sandbox{}}, nil
}

// Available reports whether this platform can run the sandbox.
func Available() bool { return platformAvailable }

// Sandbox returns the task's running sandbox, starting the relay on first use.
func (m *Manager) Sandbox(ctx context.Context, taskID int64) (*Sandbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.close {
		return nil, errors.New("egress: manager is closed")
	}
	if s := m.byID[taskID]; s != nil && sandboxAlive(s) {
		return s, nil
	}
	s, err := m.startSandbox(taskID, filepath.Join(m.cfg.SocketDir, "task-"+strconv.FormatInt(taskID, 10)+".sock"))
	if err != nil {
		return nil, err
	}
	m.byID[taskID] = s
	return s, nil
}

// CloseTask tears the task's sandbox down (task finished, deleted, or paused by
// an egress failure). Idempotent.
func (m *Manager) CloseTask(taskID int64) {
	m.mu.Lock()
	s := m.byID[taskID]
	delete(m.byID, taskID)
	m.mu.Unlock()
	s.Close()
}

// Close tears every sandbox down.
func (m *Manager) Close() {
	m.mu.Lock()
	m.close = true
	all := m.byID
	m.byID = map[int64]*Sandbox{}
	m.mu.Unlock()
	for _, s := range all {
		s.Close()
	}
}

// serveControl accepts relay control connections until the listener closes.
// Each connection carries exactly one request and one response (plus an fd).
func (m *Manager) serveControl(ln net.Listener, taskID int64) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go m.handleControl(conn, taskID)
	}
}

func (m *Manager) handleControl(conn net.Conn, taskID int64) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	var req controlRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		_ = writeControl(conn, controlResponse{Error: "egress: bad control request"}, nil)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var (
		up  net.Conn
		err error
	)
	switch req.Op {
	case "dial":
		up, err = m.cfg.Dial(ctx, taskID, req.Address)
	case "dns":
		address := req.Address
		if address == "" {
			address = m.cfg.Resolver
		}
		up, err = m.cfg.Dial(ctx, taskID, address)
	case "gateway":
		// The task HTTP gateway lives on the host loopback and applies the lease
		// itself, so the relay only bridges the sandbox to it; proxy-aware
		// clients keep their recording and authentication path.
		var d net.Dialer
		up, err = d.DialContext(ctx, "tcp", req.Address)
	default:
		err = fmt.Errorf("egress: unknown control op %q", req.Op)
	}
	if err != nil {
		m.cfg.Logf("[egress] task %d %s %q: %v", taskID, req.Op, req.Address, err)
		_ = writeControl(conn, controlResponse{Error: err.Error()}, nil)
		return
	}
	resp := controlResponse{OK: true}
	if buffered, ok := up.(interface{ BufferedBytes() []byte }); ok {
		resp.Prefix = buffered.BufferedBytes()
	}
	// The fd is duplicated into the socket when the message is sent, so the
	// parent's copy can be dropped right after writeControl returns.
	if err := writeControl(conn, resp, up); err != nil {
		m.cfg.Logf("[egress] task %d hand fd to relay: %v", taskID, err)
	}
	up.Close()
}

// relayEnvVar marks the relay child. Empty RelayBinary re-executes the current
// binary with this variable set, so deployments and test binaries need no
// extra artifact.
const relayEnvVar = "ARTEX_EGRESS_RELAY"

func relayExecutable(cfg *Config) (string, []string, error) {
	if cfg.RelayBinary != "" {
		return cfg.RelayBinary, nil, nil
	}
	self, err := os.Executable()
	if err != nil {
		return "", nil, err
	}
	// A test binary cannot tell the two roles apart by argv[0], but the
	// environment flag is checked before TestMain runs anything.
	return self, []string{"-test.run=^$"}, nil
}

// platformName is used in setup error messages.
func platformName() string { return runtime.GOOS }
