package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionInventoryTopologyRetainsLargeTaskIdentifiers(t *testing.T) {
	m := newParityTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path string, payload any, result any) {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code < 200 || w.Code >= 300 {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body)
		}
		if result != nil {
			if err := json.Unmarshal(w.Body.Bytes(), result); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A restored PostgreSQL database may use any valid bigint identifier.
	// Advance only the fixture sequence; observe all feature behavior via HTTP.
	var sequence int64
	var called bool
	if err := m.pg.QueryRow(`SELECT last_value,is_called FROM tasks_id_seq`).Scan(&sequence, &called); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := m.pg.Exec(`SELECT setval('tasks_id_seq',$1,$2)`, sequence, called); err != nil {
			t.Error(err)
		}
	}()
	const taskID int64 = 9007199254740993
	if _, err := m.pg.Exec(`SELECT setval('tasks_id_seq',$1,false)`, taskID); err != nil {
		t.Fatal(err)
	}
	var task struct {
		ID string `json:"id"`
	}
	request("POST", "/api/tasks", map[string]any{"description": "large identifier observation", "goal": "retain explicit relationship ownership"}, &task)
	if task.ID != "9007199254740993" {
		t.Fatalf("fixture task ID=%q", task.ID)
	}
	defer request("DELETE", "/api/tasks/"+task.ID, nil, nil)
	prefix := fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())
	var observation struct {
		Session struct {
			ID int64 `json:"id"`
		} `json:"session"`
	}
	request("POST", "/api/session-inventory/observations", map[string]any{"source": prefix, "source_id": "one", "sequence": 1, "kind": "c2", "state": "connected", "task_id": taskID}, &observation)
	var host struct {
		Ref string `json:"ref"`
	}
	request("POST", "/api/session-inventory/nodes", map[string]any{"kind": "host", "external_ref": prefix, "label": "observed host", "state": "active", "task_id": taskID}, &host)
	request("POST", "/api/session-inventory/edges", map[string]any{"source_ref": fmt.Sprintf("session:%d", observation.Session.ID), "target_ref": host.Ref, "relation": "hosted_on", "state": "active"}, nil)
	var graph struct {
		Nodes []struct {
			Ref    string `json:"ref"`
			TaskID *int64 `json:"task_id"`
		} `json:"nodes"`
		Edges []struct {
			EffectiveState string `json:"effective_state"`
		} `json:"edges"`
	}
	request("GET", "/api/session-inventory/topology?task_id="+task.ID, nil, &graph)
	if len(graph.Nodes) != 2 || len(graph.Edges) != 1 {
		t.Fatalf("topology=%+v", graph)
	}
	for _, node := range graph.Nodes {
		if node.TaskID == nil || *node.TaskID != taskID {
			t.Fatalf("task identifier changed for node %s: %v", node.Ref, node.TaskID)
		}
	}
	if graph.Edges[0].EffectiveState != "active" {
		t.Fatalf("matching task ownership became %q", graph.Edges[0].EffectiveState)
	}
}
