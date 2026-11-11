package egress

import "os"

// The server binary and test binaries both host the relay child: when the
// environment flag is set this process is a relay, not an application. Doing it
// in init means every entry point (cmd/artex, go test) gets it for free.
func init() {
	if os.Getenv(relayEnvVar) == "1" {
		RelayMain()
	}
}
