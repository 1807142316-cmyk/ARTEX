package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestTaskCreationRequestCanBeSafelyRetried(t *testing.T) {
	m := newParityTestManager(t)
	defer m.Close()

	td := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, td, td, td)
	h := s.Handler()
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}

	key := t.Name() + strconv.FormatInt(time.Now().UnixNano(), 10)
	create := func(goal string) (int, map[string]any) {
		payload, err := json.Marshal(map[string]any{"description": "dashboard retry", "goal": goal, "timeout_seconds": 120, "plan_heartbeat_seconds": 900})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/tasks", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Idempotency-Key", key)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var result map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatalf("decode response: %v (%s)", err, rec.Body.String())
		}
		return rec.Code, result
	}

	firstCode, first := create("verify retry handling")
	if firstCode != http.StatusCreated {
		t.Fatalf("first request status = %d, body=%v", firstCode, first)
	}
	if first["timeout_seconds"] != float64(120) || first["plan_heartbeat_seconds"] != float64(900) {
		t.Fatalf("effective limits were not returned: %v", first)
	}
	defer func() {
		req := httptest.NewRequest(http.MethodDelete, "/api/tasks/"+first["id"].(string), nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}()
	retryCode, retry := create("verify retry handling")
	if retryCode != http.StatusOK {
		t.Fatalf("retry status = %d, want %d; body=%v", retryCode, http.StatusOK, retry)
	}
	if first["id"] != retry["id"] {
		t.Fatalf("retry created a different task: first=%v retry=%v", first["id"], retry["id"])
	}
	thirdCode, third := create("verify retry handling")
	if thirdCode != http.StatusOK || third["id"] != first["id"] {
		t.Fatalf("subsequent retry = %d %v", thirdCode, third)
	}
	var requests sync.WaitGroup
	for range 6 {
		requests.Go(func() {
			code, result := create("verify retry handling")
			if code != http.StatusOK || result["id"] != first["id"] {
				t.Errorf("concurrent retry = %d %v", code, result)
			}
		})
	}
	requests.Wait()

	conflictCode, conflict := create("different payload")
	if conflictCode != http.StatusConflict {
		t.Fatalf("changed payload status = %d, want %d; body=%v", conflictCode, http.StatusConflict, conflict)
	}
}
