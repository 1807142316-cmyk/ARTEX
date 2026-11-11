//go:build linux

package server

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// Run in a dedicated Linux process, then in a container with independently set
// CPU and memory limits. This exercises the authenticated public response.
func TestLinuxMetricsMatchRuntimeScope(t *testing.T) {
	wantScope := os.Getenv("ARTEX_METRICS_ACCEPTANCE_SCOPE")
	if wantScope == "" {
		t.Skip("set ARTEX_METRICS_ACCEPTANCE_SCOPE to process or container")
	}
	s := &Server{jwtKey: []byte("linux-runtime-metrics-acceptance-32bytes")}
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func() resourceSample {
		t.Helper()
		r := httptest.NewRequest("GET", "/api/system/metrics", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		var out resourceSample
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatalf("metrics HTTP %d: %s", w.Code, w.Body)
		}
		if out.Scope != wantScope || out.Error != "" || out.Memory.Used == nil || *out.Memory.Used == 0 {
			t.Fatalf("runtime scope/usage: %s", w.Body)
		}
		return out
	}
	first := request()
	if first.CPU.Percent != nil {
		t.Fatal("first CPU sample must establish a baseline")
	}
	allocation := make([]byte, 16<<20)
	for i := 0; i < len(allocation); i += 4096 {
		allocation[i] = 1
	}
	// Keep a core busy long enough to establish an observable second sample.
	deadline := time.Now().Add(600 * time.Millisecond)
	for time.Now().Before(deadline) {
		for i := 0; i < len(allocation); i += 4096 {
			allocation[i]++
		}
	}
	second := request()
	runtime.KeepAlive(allocation)
	if second.CPU.Percent == nil || *second.CPU.Percent <= 0 || *second.CPU.Percent > 100 || second.CPU.WindowSeconds < 0.5 {
		t.Fatalf("busy CPU sample: %+v", second.CPU)
	}
	if wantScope == "container" {
		wantBytes, err := strconv.ParseUint(os.Getenv("ARTEX_METRICS_ACCEPTANCE_MEMORY"), 10, 64)
		if err != nil || second.Memory.Limit == nil || *second.Memory.Limit != wantBytes {
			t.Fatalf("container limit: got %v expected %d parse=%v", second.Memory.Limit, wantBytes, err)
		}
		wantCores, err := strconv.ParseFloat(os.Getenv("ARTEX_METRICS_ACCEPTANCE_CPU"), 64)
		if err != nil || second.CPU.LimitCores == nil || *second.CPU.LimitCores != wantCores {
			t.Fatalf("container CPU denominator: %v expected %v parse=%v", second.CPU.LimitCores, wantCores, err)
		}
	} else if second.Memory.Limit != nil {
		t.Fatal("binary process must not report a whole-host memory limit")
	}
	encoded, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual runtime metrics: %s", encoded)
}
