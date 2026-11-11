package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func TestSkillLoadHistoryRetainsTaskExecutionContext(t *testing.T) {
	m := newParityTestManager(t)
	t.Cleanup(func() { _ = m.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	previousAugment := agent.ToolAugment
	t.Cleanup(func() { agent.ToolAugment = previousAugment })
	skillRoot := t.TempDir()
	name := "evidence-inventory"
	if err := os.Mkdir(filepath.Join(skillRoot, name), 0755); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join("..", "skills", name, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillRoot, name, "SKILL.md"), content, 0644); err != nil {
		t.Fatal(err)
	}
	s := New(ctx, m, skillRoot, t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(path string, authenticated bool, out any) int {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		if authenticated {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if out != nil && w.Code == 200 {
			if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
				t.Fatal(err)
			}
		}
		return w.Code
	}
	task, err := m.CreateTask("skill trace", "review saved evidence", nil, 0, 300)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	intentID, err := task.Store.AddIntent(map[string]any{"goal": "read saved inventory"}, 1, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	activityID, err := task.Store.AppendActivity(db.Activity{NodeID: &intentID, Worker: "worker", Kind: "tool_result", Tool: "Read", Summary: "saved evidence reviewed", Detail: "recorded evidence output"})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := m.pg.GetAgentByKey("worker")
	if err != nil || worker == nil {
		t.Fatalf("worker: %v", err)
	}
	bindings, err := m.pg.AgentSkillNames(worker.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.SetAgentSkillVisibility(worker.ID, bindings) })
	if err := m.pg.SetAgentSkillVisibility(worker.ID, []string{name}); err != nil {
		t.Fatal(err)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	runCtx := agent.WithRunInfo(ctx, agent.RunInfo{TaskID: taskID, ExplorationID: task.ExpID, IntentID: intentID})
	tools, _, cleanup := agent.ToolAugment(runCtx, "worker")
	if cleanup != nil {
		defer cleanup()
	}
	loaded := false
	for _, tool := range tools {
		if tool.Name() == "Skill" {
			result, err := tool.Call(runCtx, json.RawMessage(`{"name":"evidence-inventory","args":"saved inventory"}`), &actool.ToolContext{})
			if err != nil || result.IsError {
				t.Fatalf("actual Skill load: %v %+v", err, result)
			}
			loaded = true
		}
	}
	if !loaded {
		t.Fatal("Skill not assembled")
	}
	path := "/api/skills/" + name + "/usage"
	if status := request(path, false, nil); status != 401 {
		t.Fatalf("unauthenticated history=%d", status)
	}
	var history struct {
		Calls []struct {
			TaskID        int64 `json:"task_id"`
			ExplorationID int64 `json:"exploration_id"`
			IntentID      int64 `json:"intent_id"`
		} `json:"calls"`
	}
	if status := request(path, true, &history); status != 200 || len(history.Calls) == 0 {
		t.Fatalf("history=%d %+v", status, history)
	}
	call := history.Calls[0]
	if call.TaskID != taskID || call.ExplorationID != task.ExpID || call.IntentID != intentID {
		t.Fatalf("lost execution context: %+v", call)
	}
	var intents struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if status := request(fmt.Sprintf("/api/exploration/intents?task=%s&before=%d&limit=1&page=1", task.ID, intentID+1), true, &intents); status != 200 || len(intents.Items) != 1 || intents.Items[0].ID != strconv.FormatInt(intentID, 10) {
		t.Fatalf("context intent lookup=%d %+v", status, intents)
	}
	var activity struct {
		Items []struct {
			Seq int64 `json:"seq"`
		} `json:"items"`
	}
	query := url.Values{"task": {task.ID}, "session": {fmt.Sprintf("intent:%d", call.IntentID)}}
	if status := request("/api/exploration/activity/history?"+query.Encode(), true, &activity); status != 200 || len(activity.Items) != 1 || activity.Items[0].Seq != activityID {
		t.Fatalf("context history=%d %+v", status, activity)
	}
	var detail struct {
		Detail string `json:"detail"`
	}
	if status := request(fmt.Sprintf("/api/exploration/activity/%d?task=%s", activityID, task.ID), true, &detail); status != 200 || !bytes.Equal([]byte(detail.Detail), []byte("recorded evidence output")) {
		t.Fatalf("existing context detail=%d %+v", status, detail)
	}
}
