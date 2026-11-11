//go:build !linux

package egress

import (
	"fmt"
	"net"
	"runtime"
)

const platformAvailable = false

func sandboxAlive(*Sandbox) bool { return false }

func writeControl(net.Conn, controlResponse, net.Conn) error { return ErrUnsupported }

func (m *Manager) startSandbox(int64, string) (*Sandbox, error) {
	return nil, fmt.Errorf("%w (%s)", ErrUnsupported, runtime.GOOS)
}

// RelayMain is the entry point of the hidden relay child. On non-Linux builds it
// is never reached — the parent cannot start a sandbox there — but the symbol
// exists so the shared startup path compiles everywhere.
func RelayMain() {
	fmt.Println("egress: relay is only implemented on Linux")
}
