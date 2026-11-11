// Command egress-relay is the sandbox relay child.
//
// Normally the server re-executes itself with ARTEX_EGRESS_RELAY=1 and never
// needs this binary. It exists for deployments that prefer a dedicated,
// separately-installed helper, and for debugging the relay in isolation.
package main

import (
	"fmt"
	"os"

	"github.com/Autumn-27/artex/egress"
)

func main() {
	if !egress.Available() {
		fmt.Fprintln(os.Stderr, "egress-relay: the task egress sandbox requires Linux")
		os.Exit(1)
	}
	egress.RelayMain()
}
