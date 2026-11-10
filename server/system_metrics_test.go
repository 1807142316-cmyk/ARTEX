package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSystemMetricsRequireAuthenticationAndExposeCollectionScope(t *testing.T) {
	s := &Server{jwtKey: []byte("metrics-http-test-signing-key-32bytes")}
	h := s.Handler()
	request := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/system/metrics", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := request(""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request = %d", rec.Code)
	}
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	rec := request(token)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics request = %d: %s", rec.Code, rec.Body.String())
	}
	var result struct {
		Scope     string    `json:"scope"`
		SampledAt time.Time `json:"sampled_at"`
		CPU       struct {
			Unit    string   `json:"unit"`
			Percent *float64 `json:"percent"`
		} `json:"cpu"`
		Memory struct {
			Unit string  `json:"unit"`
			Used *uint64 `json:"used"`
		} `json:"memory"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Scope != "container" && result.Scope != "process" && result.Scope != "unavailable" {
		t.Fatalf("unexpected collection scope %q", result.Scope)
	}
	if result.SampledAt.IsZero() || result.CPU.Unit != "percent" || result.Memory.Unit != "bytes" {
		t.Fatalf("missing timestamp or units: %s", rec.Body.String())
	}
	if result.Scope == "unavailable" && (result.CPU.Percent != nil || result.Memory.Used != nil) {
		t.Fatalf("unavailable collector returned usage: %s", rec.Body.String())
	}
}
