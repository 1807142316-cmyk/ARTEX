package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSessionInventoryAcceptsAuthenticatedObservationsAndRetainsHistory(t *testing.T) {
	m := newParityTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	handler := s.Handler()
	request := func(method, path string, input any, auth bool) (int, map[string]any) {
		t.Helper()
		var body bytes.Buffer
		if input != nil {
			if err := json.NewEncoder(&body).Encode(input); err != nil {
				t.Fatal(err)
			}
		}
		r := httptest.NewRequest(method, path, &body)
		if auth {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	source := fmt.Sprintf("observer-%d", time.Now().UnixNano())
	observation := map[string]any{"source": source, "source_id": "remote-1", "sequence": 1, "kind": "webshell", "protocol_label": "http_phpcmd", "state": "connected", "host": "app.internal", "url": "https://app.internal/status", "heartbeat_ttl_seconds": 60}
	if code, _ := request("POST", "/api/session-inventory/observations", observation, false); code != 401 {
		t.Fatalf("unauthorized=%d", code)
	}
	observation["task_id"] = int64(9223372036854770000)
	if code, _ := request("POST", "/api/session-inventory/observations", observation, true); code != 400 {
		t.Fatalf("unknown task=%d", code)
	}
	delete(observation, "task_id")
	code, created := request("POST", "/api/session-inventory/observations", observation, true)
	if code != 201 {
		t.Fatalf("create=%d %v", code, created)
	}
	session := created["session"].(map[string]any)
	id := int64(session["id"].(float64))
	if session["mode"] != "observer" || session["effective_state"] != "connected" {
		t.Fatalf("observer state=%v", session)
	}
	if code, replayed := request("POST", "/api/session-inventory/observations", observation, true); code != 200 || replayed["replayed"] != true {
		t.Fatalf("retry=%d %v", code, replayed)
	}
	observation["host"] = "changed.internal"
	if code, _ := request("POST", "/api/session-inventory/observations", observation, true); code != 409 {
		t.Fatalf("conflicting replay=%d", code)
	}
	observation["sequence"] = 2
	if code, _ := request("POST", "/api/session-inventory/observations", observation, true); code != 200 {
		t.Fatalf("new observation=%d", code)
	}
	code, detail := request("GET", fmt.Sprintf("/api/session-inventory/sessions/%d", id), nil, true)
	if code != 200 || len(detail["audit"].([]any)) != 2 {
		t.Fatalf("persisted detail=%d %v", code, detail)
	}
	if code, _ := request("POST", fmt.Sprintf("/api/session-inventory/sessions/%d/commands", id), map[string]string{"command": "anything"}, true); code != 404 {
		t.Fatalf("unexpected command channel=%d", code)
	}
	code, list := request("GET", "/api/session-inventory/sessions?source="+source, nil, true)
	if code != 200 || list["total"] != float64(1) {
		t.Fatalf("list=%d %v", code, list)
	}
}

func TestSessionInventoryExpiresAndDisconnectsWithoutChangingRemoteService(t *testing.T) {
	m := newParityTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, _ := signJWT(s.jwtKey)
	h := s.Handler()
	request := func(method, path string, input any) (int, map[string]any) {
		t.Helper()
		var b bytes.Buffer
		if input != nil {
			_ = json.NewEncoder(&b).Encode(input)
		}
		r := httptest.NewRequest(method, path, &b)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	code, task := request("POST", "/api/tasks", map[string]any{"name": "inventory reference", "description": "inventory metadata", "goal": "record relationships"})
	if code != 201 {
		t.Fatalf("task=%d %v", code, task)
	}
	taskID := task["id"]
	// Task DTO IDs are strings, while foreign keys in observation JSON are numeric.
	if text, ok := taskID.(string); ok {
		parsed, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		taskID = parsed
	}
	code, assets := request("POST", "/api/assets", map[string]any{"task_id": taskID, "assets": []any{map[string]any{"type": "ip", "ip": "192.0.2.193"}}})
	if code != 200 {
		t.Fatalf("asset=%d %v", code, assets)
	}
	assetID := assets["results"].([]any)[0].(map[string]any)["id"]
	source := fmt.Sprintf("expiry-%d", time.Now().UnixNano())
	old := time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339)
	input := map[string]any{"source": source, "source_id": "one", "sequence": 1, "kind": "c2", "state": "connected", "host": "192.0.2.193", "task_id": taskID, "asset_id": assetID, "heartbeat_at": old, "heartbeat_ttl_seconds": 1}
	code, result := request("POST", "/api/session-inventory/observations", input)
	if code != 201 {
		t.Fatalf("observation=%d %v", code, result)
	}
	item := result["session"].(map[string]any)
	id := int64(item["id"].(float64))
	if item["effective_state"] != "stale" {
		t.Fatalf("expiry=%v", item)
	}
	code, result = request("GET", "/api/session-inventory/sessions?source="+source+"&state=connected", nil)
	if code != 200 || result["total"] != float64(0) {
		t.Fatalf("expired filter=%v", result)
	}
	code, result = request("POST", fmt.Sprintf("/api/session-inventory/sessions/%d/annotate", id), map[string]string{"detail": "Investigating source heartbeat"})
	if code != 200 || result["annotation"] != "Investigating source heartbeat" {
		t.Fatalf("annotation=%d %v", code, result)
	}
	code, result = request("POST", fmt.Sprintf("/api/session-inventory/sessions/%d/disconnect", id), map[string]string{"detail": "Operator removed observation"})
	if code != 200 || result["effective_state"] != "disconnected" {
		t.Fatalf("disconnect=%d %v", code, result)
	}
	// A new observation can establish a new observed state; retrying an old event cannot.
	delete(input, "heartbeat_at")
	input["sequence"] = 2
	code, result = request("POST", "/api/session-inventory/observations", input)
	if code != 200 || result["session"].(map[string]any)["effective_state"] != "connected" {
		t.Fatalf("heartbeat=%d %v", code, result)
	}
	input["asset_id"] = 9223372036854770000
	if code, _ = request("POST", "/api/session-inventory/observations", input); code != 400 {
		t.Fatalf("unknown asset=%d", code)
	}
	input["password"] = "must not be accepted"
	if code, _ = request("POST", "/api/session-inventory/observations", input); code != 400 {
		t.Fatalf("secret field=%d", code)
	}
}

func TestSessionInventoryTopologyUsesOnlyExplicitValidRelationships(t *testing.T) {
	m := newParityTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, _ := signJWT(s.jwtKey)
	h := s.Handler()
	request := func(method, path string, input any) (int, map[string]any) {
		t.Helper()
		var b bytes.Buffer
		if input != nil {
			_ = json.NewEncoder(&b).Encode(input)
		}
		r := httptest.NewRequest(method, path, &b)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	prefix := fmt.Sprintf("topology-%d", time.Now().UnixNano())
	makeNode := func(kind, ref, label, address string) map[string]any {
		t.Helper()
		code, node := request("POST", "/api/session-inventory/nodes", map[string]any{"kind": kind, "external_ref": prefix + ref, "label": label, "address": address, "state": "active"})
		if code != 201 {
			t.Fatalf("node=%d %v", code, node)
		}
		return node
	}
	host := makeNode("host", "host", "web node", "192.0.2.20")
	subnet := makeNode("subnet", "subnet", "documentation network", "192.0.2.0/24")
	code, graph := request("GET", "/api/session-inventory/topology?q="+prefix, nil)
	if code != 200 || len(graph["edges"].([]any)) != 0 {
		t.Fatalf("inferred edge=%d %v", code, graph)
	}
	edge := map[string]any{"source_ref": host["ref"], "target_ref": subnet["ref"], "relation": "member_of", "state": "active", "note": "Explicit source observation"}
	code, result := request("POST", "/api/session-inventory/edges", edge)
	if code != 201 {
		t.Fatalf("edge=%d %v", code, result)
	}
	edgeID := int64(result["id"].(float64))
	code, history := request("GET", fmt.Sprintf("/api/session-inventory/edges/%d/audit", edgeID), nil)
	if code != 200 || len(history["items"].([]any)) != 1 {
		t.Fatalf("edge audit=%d %v", code, history)
	}
	edge["target_ref"] = "session:9223372036854770000"
	if code, _ = request("POST", "/api/session-inventory/edges", edge); code != 400 {
		t.Fatalf("unknown endpoint=%d", code)
	}
	host["state"] = "invalid"
	delete(host, "id")
	delete(host, "ref")
	delete(host, "effective_state")
	delete(host, "updated_at")
	code, result = request("POST", "/api/session-inventory/nodes", host)
	if code != 200 {
		t.Fatalf("invalidate=%d %v", code, result)
	}
	code, graph = request("GET", "/api/session-inventory/topology?q="+prefix, nil)
	if code != 200 || len(graph["edges"].([]any)) != 1 || graph["edges"].([]any)[0].(map[string]any)["effective_state"] != "inactive" {
		t.Fatalf("invalidated graph=%d %v", code, graph)
	}
	code, result = request("GET", "/api/session-inventory/nodes/"+strings.TrimPrefix(result["ref"].(string), "node:"), nil)
	if code != 200 || len(result["audit"].([]any)) != 2 {
		t.Fatalf("node audit=%d %v", code, result)
	}
}

func TestSessionInventoryReceivesActualReadOnlyHealthObserver(t *testing.T) {
	m := newParityTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, _ := signJWT(s.jwtKey)
	api := httptest.NewServer(s.Handler())
	defer api.Close()
	var requests atomic.Int64
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "GET" || r.URL.Path != "/health" || r.Header.Get("Authorization") != "" {
			t.Errorf("health request leaked API auth or changed method: %s %s", r.Method, r.URL)
		}
		w.WriteHeader(204)
	}))
	defer health.Close()
	python := os.Getenv("ARTEX_TEST_PYTHON")
	if python == "" {
		var err error
		python, err = exec.LookPath("python3")
		if err != nil {
			t.Skip("ARTEX_TEST_PYTHON or python3 required for actual observer CLI")
		}
	}
	source := fmt.Sprintf("health-cli-%d", time.Now().UnixNano())
	command := exec.CommandContext(ctx, python, "../scripts/session-inventory/observe_health.py", "--artex-url", api.URL, "--health-url", health.URL+"/health", "--source", source)
	command.Env = append(os.Environ(), "ARTEX_OBSERVER_TOKEN="+token)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("observer: %v %s", err, output)
	}
	if requests.Load() != 1 || !bytes.Contains(output, []byte(`"mode": "observer"`)) {
		t.Fatalf("observer output=%s requests=%d", output, requests.Load())
	}
	r := httptest.NewRequest("GET", "/api/session-inventory/sessions?source="+source, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var result struct {
		Items []struct {
			ProtocolLabel  string `json:"protocol_label"`
			EffectiveState string `json:"effective_state"`
		}
		Total int
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 || result.Items[0].ProtocolLabel != "http-health-observer" || result.Items[0].EffectiveState != "connected" {
		t.Fatalf("actual observer not retained: %s", w.Body)
	}
}

func TestSessionInventoryRejectsCrossTaskEdgesAndNodeTypeChanges(t *testing.T) {
	m := newParityTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, _ := signJWT(s.jwtKey)
	h := s.Handler()
	request := func(method, path string, input any) (int, map[string]any) {
		t.Helper()
		var b bytes.Buffer
		_ = json.NewEncoder(&b).Encode(input)
		r := httptest.NewRequest(method, path, &b)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	makeTask := func() int64 {
		code, task := request("POST", "/api/tasks", map[string]any{"description": "inventory ownership", "goal": "persist observation"})
		if code != 201 {
			t.Fatalf("task=%d %v", code, task)
		}
		switch id := task["id"].(type) {
		case string:
			n, _ := strconv.ParseInt(id, 10, 64)
			return n
		case float64:
			return int64(id)
		}
		t.Fatal("missing task id")
		return 0
	}
	taskOne, taskTwo := makeTask(), makeTask()
	prefix := fmt.Sprintf("ownership-%d", time.Now().UnixNano())
	code, session := request("POST", "/api/session-inventory/observations", map[string]any{"source": prefix, "source_id": "one", "sequence": 1, "kind": "c2", "state": "connected", "task_id": taskOne})
	if code != 201 {
		t.Fatalf("session=%d %v", code, session)
	}
	node := map[string]any{"kind": "host", "external_ref": prefix, "label": "owned host", "state": "active", "task_id": taskTwo}
	code, host := request("POST", "/api/session-inventory/nodes", node)
	if code != 201 {
		t.Fatalf("host=%d %v", code, host)
	}
	edge := map[string]any{"source_ref": fmt.Sprintf("session:%.0f", session["session"].(map[string]any)["id"]), "target_ref": host["ref"], "relation": "hosted_on", "state": "active"}
	if code, _ = request("POST", "/api/session-inventory/edges", edge); code != 400 {
		t.Fatalf("cross-task relation=%d", code)
	}
	node["kind"] = "credential_ref"
	if code, _ = request("POST", "/api/session-inventory/nodes", node); code != 409 {
		t.Fatalf("changing stable node kind=%d", code)
	}
}
