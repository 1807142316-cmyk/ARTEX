package server

import (
	"fmt"
	"testing"
	"time"
)

// TestConnectionListEndpointsArePaginated pins the pagination contract on both
// list endpoints: page/limit (limit capped at 100), total and truncated are
// always present, and items keeps its existing name.
func TestConnectionListEndpointsArePaginated(t *testing.T) {
	e := newConnectionTestEnv(t)
	const secret = "{{SECRET_pg7kw2md9xt4rn1vq5yz8hsc}}"

	// Three adapters, each with its own session, so the session list can be
	// sliced deterministically by paging through it.
	var sessionIDs []int64
	for i := range 3 {
		stub := newShellStub(t, secret)
		adapter := e.createAdapter(t, map[string]any{
			"name": fmt.Sprintf("page-%d-%d", i, time.Now().UnixNano()), "kind": "http_phpcmd",
			"base_url": stub.url(), "secret": secret, "secret_ref": "page-key", "timeout_seconds": 5,
		})
		id := int64(adapter["id"].(float64))
		code, synced := e.call(t, "POST", fmt.Sprintf("/api/connections/adapters/%d/sync", id), nil, true)
		if code != 200 {
			t.Fatalf("sync=%d %v", code, synced)
		}
		sessionIDs = append(sessionIDs, int64(synced["session"].(map[string]any)["id"].(float64)))
	}

	code, first := e.call(t, "GET", "/api/connections/sessions?page=1&limit=2", nil, true)
	if code != 200 {
		t.Fatalf("sessions=%d %v", code, first)
	}
	for _, key := range []string{"page", "limit", "total", "items"} {
		if _, ok := first[key]; !ok {
			t.Fatalf("session list missing %q: %v", key, first)
		}
	}
	if first["page"] != float64(1) || first["limit"] != float64(2) {
		t.Fatalf("session page echo=%v/%v", first["page"], first["limit"])
	}
	pageOne, _ := first["items"].([]any)
	if len(pageOne) != 2 {
		t.Fatalf("page 1 size=%d", len(pageOne))
	}
	total := int(first["total"].(float64))
	if total < 3 {
		t.Fatalf("total=%d, want at least the three fixtures", total)
	}
	if first["truncated"] != (total > 2) {
		t.Fatalf("truncated=%v with total=%d", first["truncated"], total)
	}

	// Page two must not repeat page one.
	code, second := e.call(t, "GET", "/api/connections/sessions?page=2&limit=2", nil, true)
	if code != 200 {
		t.Fatalf("sessions page 2=%d %v", code, second)
	}
	pageTwo, _ := second["items"].([]any)
	seen := map[float64]bool{}
	for _, raw := range pageOne {
		seen[raw.(map[string]any)["id"].(float64)] = true
	}
	for _, raw := range pageTwo {
		if id := raw.(map[string]any)["id"].(float64); seen[id] {
			t.Fatalf("page 2 repeated session %v", id)
		}
	}

	// limit is capped at 100 rather than rejected or honoured blindly.
	code, capped := e.call(t, "GET", "/api/connections/sessions?page=1&limit=5000", nil, true)
	if code != 200 || capped["limit"] != float64(100) {
		t.Fatalf("limit cap=%d %v", code, capped["limit"])
	}

	// Operations page the same way; the session carries its full history count.
	sessionID := sessionIDs[0]
	path := fmt.Sprintf("/api/connections/sessions/%d/operations", sessionID)
	for i := range 3 {
		if code, _ := e.call(t, "POST", path, map[string]any{
			"action": "ping", "request_id": fmt.Sprintf("page-%d-%d", i, time.Now().UnixNano()),
		}, true); code != 200 {
			t.Fatalf("ping %d failed with %d", i, code)
		}
	}
	code, ops := e.call(t, "GET", path+"?page=1&limit=2", nil, true)
	if code != 200 {
		t.Fatalf("operations=%d %v", code, ops)
	}
	for _, key := range []string{"page", "limit", "total", "items"} {
		if _, ok := ops[key]; !ok {
			t.Fatalf("operations missing %q: %v", key, ops)
		}
	}
	if ops["page"] != float64(1) || ops["limit"] != float64(2) {
		t.Fatalf("operations page echo=%v/%v", ops["page"], ops["limit"])
	}
	items, _ := ops["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("operations page size=%d", len(items))
	}
	if ops["total"].(float64) < 3 {
		t.Fatalf("operations total=%v", ops["total"])
	}
	if ops["truncated"] != true {
		t.Fatalf("operations truncated=%v", ops["truncated"])
	}

	// A page past the end is empty, not an error, and keeps the shape.
	code, past := e.call(t, "GET", path+"?page=99&limit=50", nil, true)
	if code != 200 {
		t.Fatalf("past end=%d %v", code, past)
	}
	if pastItems, _ := past["items"].([]any); len(pastItems) != 0 {
		t.Fatalf("past-the-end page returned %d items", len(pastItems))
	}
	if past["total"].(float64) < 3 {
		t.Fatalf("past-the-end total=%v", past["total"])
	}
	if past["truncated"] != false {
		t.Fatalf("past-the-end truncated=%v", past["truncated"])
	}

	// Adapters still return everything but now carry a total, and the list is
	// bounded at 200 with truncated=true.
	code, adapters := e.call(t, "GET", "/api/connections/adapters", nil, true)
	if code != 200 {
		t.Fatalf("adapters=%d %v", code, adapters)
	}
	adapterItems, _ := adapters["items"].([]any)
	if _, ok := adapters["total"]; !ok {
		t.Fatalf("adapter list missing total: %v", adapters)
	}
	if int(adapters["total"].(float64)) < len(adapterItems) {
		t.Fatalf("adapter total=%v < items=%d", adapters["total"], len(adapterItems))
	}
	// The shared test database may hold more than the 200 adapter bound from
	// earlier runs, so truncation is asserted against the actual total rather
	// than assumed to be false.
	if want := int(adapters["total"].(float64)) > 200; adapters["truncated"] != want {
		t.Fatalf("adapter truncated=%v with total=%v", adapters["truncated"], adapters["total"])
	}
	if len(adapterItems) > 200 {
		t.Fatalf("adapter list returned %d items without the 200 bound", len(adapterItems))
	}
	if limit, ok := adapters["limit"]; ok && limit != float64(200) {
		t.Fatalf("adapter list limit=%v", limit)
	}
}
