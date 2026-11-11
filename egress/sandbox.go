// Package egress implements the transparent per-task egress sandbox.
//
// On Linux a task's shell tools are entered into a private network namespace
// whose only exit is a relay process. The relay accepts redirected TCP, asks
// the parent process for a connection resolved through the task's egress lease
// (the existing proxy pool route), and hands the connected file descriptor back
// over SCM_RIGHTS. DNS is forwarded the same way (TCP to the configured
// resolver). Anything else — plain UDP, ICMP, IPv6 — is dropped, so a task can
// never leak around its lease.
//
// On other platforms everything in this package is a stub that returns
// ErrUnsupported; the rest of the program keeps working unchanged.
package egress

import (
	"context"
	"errors"
	"net"
	"time"
)

// ErrUnsupported reports that the current platform has no task egress sandbox.
var ErrUnsupported = errors.New("task egress sandbox is not supported on this platform")

// DialFunc opens a connection to address on behalf of a task. The host supplies
// it so that the sandbox reuses the existing lease/route/failover code instead
// of duplicating proxy policy here.
type DialFunc func(ctx context.Context, taskID int64, address string) (net.Conn, error)

// Config configures a Manager.
type Config struct {
	// SocketDir holds the per-task unix sockets the relay dials. Created 0700.
	SocketDir string
	// Resolver is the TCP resolver address DNS queries are forwarded to through
	// the task route. Defaults to 1.1.1.1:53.
	Resolver string
	// RelayBinary overrides the egress-relay executable location.
	RelayBinary string
	// Dial opens task-scoped connections. Required.
	Dial DialFunc
	// Gateway returns the task's HTTP gateway address on the host loopback
	// (e.g. 127.0.0.1:41233). Inside the sandbox the relay listens on the same
	// port and bridges to it, so proxy-aware clients keep an unchanged proxy
	// URL while every connection is still forced out through the lease.
	Gateway func(taskID int64) (string, error)
	// StartupTimeout bounds how long a new relay may take to become ready.
	StartupTimeout time.Duration
	// Logf receives lifecycle messages; optional.
	Logf func(format string, args ...any)
	// OnFailure is called when a running relay dies unexpectedly (crash, OOM,
	// kill). The host uses it to apply the task's pause/failover/direct policy;
	// the sandbox itself is already gone at that point.
	OnFailure func(taskID int64, reason string)
}

func (c *Config) normalize() {
	if c.Resolver == "" {
		c.Resolver = "1.1.1.1:53"
	}
	if c.StartupTimeout <= 0 {
		c.StartupTimeout = 10 * time.Second
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
}
