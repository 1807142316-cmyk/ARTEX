package server

import (
	"github.com/Autumn-27/artex/db"
	"testing"
)

// Missing configuration is optional locally; configured database failures are
// regressions and must never appear as passing/skipped integration acceptance.
func newParityTestManager(t *testing.T) *Manager {
	t.Helper()
	if _, _, err := db.DSN(); err != nil {
		t.Skipf("PostgreSQL DSN not configured: %v", err)
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatalf("configured PostgreSQL initialization failed: %v", err)
	}
	return m
}
