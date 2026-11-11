package server

import (
	"context"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

// settingConnectionHeartbeat is the sweep cadence in seconds. Unset means the
// 60s default; anything below the floor is raised to it so an operator cannot
// turn the sweep into a request flood by mistake.
const settingConnectionHeartbeat = "connection_heartbeat_seconds"

const (
	connectionHeartbeatDefault = 60 * time.Second
	connectionHeartbeatMinimum = 15 * time.Second
	// connectionHeartbeatWorkers bounds how many adapters are probed at once.
	// The sweep is background maintenance; it must not starve interactive use.
	connectionHeartbeatWorkers = 4
)

// connectionHeartbeatInterval resolves the configured cadence, clamped to the
// documented minimum.
func (s *Server) connectionHeartbeatInterval() time.Duration {
	raw, ok, err := s.m.pg.GetSetting(settingConnectionHeartbeat)
	if err != nil || !ok {
		return connectionHeartbeatDefault
	}
	seconds, convErr := strconv.Atoi(strings.TrimSpace(raw))
	if convErr != nil || seconds <= 0 {
		return connectionHeartbeatDefault
	}
	interval := time.Duration(seconds) * time.Second
	if interval < connectionHeartbeatMinimum {
		return connectionHeartbeatMinimum
	}
	return interval
}

// startConnectionHeartbeat launches the background sweep and returns when the
// server context ends. It re-reads the interval every tick so an operator can
// change the cadence without a restart.
func (s *Server) startConnectionHeartbeat() {
	go func() {
		timer := time.NewTimer(s.connectionHeartbeatInterval())
		defer timer.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-timer.C:
				s.connectionHeartbeatSweep(s.ctx)
				timer.Reset(s.connectionHeartbeatInterval())
			}
		}
	}()
}

// connectionHeartbeatSweep probes every enabled adapter and writes the
// observation through the same path the manual sync endpoint uses. Disabled
// adapters are skipped entirely (no request, no observation). Sweeps never
// overlap: if one is still running the call returns immediately.
//
// It is exported to tests only in the sense that tests live in this package; the
// point of the direct call is determinism — no ticker, no waiting for an
// interval to elapse.
func (s *Server) connectionHeartbeatSweep(ctx context.Context) {
	if s == nil || s.connections == nil || s.m == nil || s.m.pg == nil {
		return
	}
	if !s.connections.heartbeatActive.CompareAndSwap(false, true) {
		return
	}
	defer s.connections.heartbeatActive.Store(false)

	adapters, err := s.m.pg.ConnectionAdapters(ctx)
	if err != nil {
		log.Printf("[connections] heartbeat: list adapters failed: %v", err)
		return
	}
	enabled := make([]*db.ConnectionAdapter, 0, len(adapters))
	for _, a := range adapters {
		if a.Enabled {
			enabled = append(enabled, a)
		}
	}
	if len(enabled) == 0 {
		return
	}

	var wg sync.WaitGroup
	work := make(chan *db.ConnectionAdapter)
	for range connectionHeartbeatWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for adapter := range work {
				s.connectionHeartbeatOne(ctx, adapter)
			}
		}()
	}
	for _, a := range enabled {
		select {
		case <-ctx.Done():
			close(work)
			wg.Wait()
			return
		case work <- a:
		}
	}
	close(work)
	wg.Wait()
}

// connectionHeartbeatOne runs one adapter's probe+observation under the same
// per-adapter lock the manual sync uses, so a sweep and an operator sync cannot
// interleave their sequence numbers.
func (s *Server) connectionHeartbeatOne(ctx context.Context, a *db.ConnectionAdapter) {
	unlock := s.connections.lock(a.ID)
	defer unlock()
	if _, _, _, err := s.syncConnectionAdapterOnce(ctx, a); err != nil {
		log.Printf("[connections] heartbeat: adapter %d: %v", a.ID, err)
	}
}
