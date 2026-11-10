package server

import (
	"math"
	"net/http"
	"sync"
	"time"
)

type resourceSample struct {
	Scope     string    `json:"scope"`
	Source    string    `json:"source"`
	SampledAt time.Time `json:"sampled_at"`
	CPU       struct {
		Unit          string   `json:"unit"`
		Percent       *float64 `json:"percent"`
		LimitCores    *float64 `json:"limit_cores"`
		WindowSeconds float64  `json:"window_seconds"`
	} `json:"cpu"`
	Memory struct {
		Unit  string  `json:"unit"`
		Used  *uint64 `json:"used"`
		Limit *uint64 `json:"limit"`
	} `json:"memory"`
	Error string `json:"error,omitempty"`
}

type resourceReading struct {
	scope, source     string
	cpuSeconds, cores float64
	memory            uint64
	memoryLimit       *uint64
}

type resourceSampler struct {
	mu       sync.Mutex
	previous resourceReading
	at       time.Time
}

func (s *Server) systemMetrics(w http.ResponseWriter, _ *http.Request) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	now := time.Now().UTC()
	out := resourceSample{Scope: "unavailable", SampledAt: now}
	out.CPU.Unit = "percent"
	out.Memory.Unit = "bytes"
	current, err := readResourceUsage()
	if err != nil {
		out.Error = err.Error()
		writeJSON(w, http.StatusOK, out)
		return
	}
	out.Scope, out.Source = current.scope, current.source
	out.Memory.Used, out.Memory.Limit = &current.memory, current.memoryLimit
	out.CPU.LimitCores = &current.cores
	// The first response establishes a baseline. A CPU percentage needs two
	// counter readings and is deliberately null until a measurable interval.
	window := now.Sub(s.metrics.at).Seconds()
	if !s.metrics.at.IsZero() && window >= 0.1 && current.source == s.metrics.previous.source && current.cpuSeconds >= s.metrics.previous.cpuSeconds {
		percent := (current.cpuSeconds - s.metrics.previous.cpuSeconds) / window / current.cores * 100
		percent = math.Max(0, math.Min(100, percent))
		out.CPU.Percent = &percent
		out.CPU.WindowSeconds = window
	}
	if s.metrics.at.IsZero() || window >= 0.1 {
		s.metrics.previous, s.metrics.at = current, now
	}
	writeJSON(w, http.StatusOK, out)
}
