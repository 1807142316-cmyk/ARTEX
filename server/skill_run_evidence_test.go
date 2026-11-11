package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSkillRunEvidenceIsAuthenticatedImmutableAndSeparateFromLoads(t *testing.T) {
	m := newParityTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root, err := filepath.Abs("../skills")
	if err != nil {
		t.Fatal(err)
	}
	s := New(ctx, m, root, t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path string, value any, auth bool) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		if auth {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	hash := func(relative string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, "saved-header-review", relative))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		return hex.EncodeToString(sum[:])
	}
	now := time.Now().UTC().Truncate(time.Second)
	payload := map[string]any{"client_run_id": "http-evidence-" + strconv.FormatInt(time.Now().UnixNano(), 10), "skill": "saved-header-review", "package_version": "artex-authored-1", "script_sha256": hash("scripts/run.py"), "instructions_sha256": hash("SKILL.md"), "input_label": "headers.json", "input_sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "input_kind": "file", "input_bytes": 5, "started_at": now.Add(-time.Second), "finished_at": now, "exit_code": 0, "outcome": "succeeded", "stdout": "private workflow result", "stderr": "", "truncated": false}
	beforeLoads := request("GET", "/api/skills/saved-header-review/usage", nil, true)
	for _, change := range []map[string]any{
		{"input_label": "line\nbreak.json"},
		{"input_label": ".."},
		{"input_label": "private\\headers.json"},
		{"task_id": int64(9223372036854770000)},
		{"outcome": "succeeded", "exit_code": 2},
		{"stdout": strings.Repeat("x", (64<<10)+1)},
		{"truncated": true},
	} {
		invalid := make(map[string]any, len(payload))
		for key, value := range payload {
			invalid[key] = value
		}
		for key, value := range change {
			invalid[key] = value
		}
		if w := request("POST", "/api/skill-runs", invalid, true); w.Code != 400 {
			t.Fatalf("invalid report accepted (%v)=%d %s", change, w.Code, w.Body)
		}
	}
	if w := request("POST", "/api/skill-runs", payload, false); w.Code != 401 {
		t.Fatalf("unauthenticated=%d", w.Code)
	}
	w := request("POST", "/api/skill-runs", payload, true)
	if w.Code != 201 {
		t.Fatalf("submit=%d %s", w.Code, w.Body)
	}
	var created struct {
		ID          int64  `json:"id"`
		Attestation string `json:"attestation"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ID < 1 || created.Attestation != "operator_reported" {
		t.Fatalf("record=%s", w.Body)
	}
	if w := request("POST", "/api/skill-runs", payload, true); w.Code != 200 {
		t.Fatalf("retry=%d %s", w.Code, w.Body)
	}
	payload["stdout"] = "changed"
	if w := request("POST", "/api/skill-runs", payload, true); w.Code != 409 {
		t.Fatalf("conflict=%d %s", w.Code, w.Body)
	}
	w = request("GET", "/api/skill-runs?skill=saved-header-review", nil, true)
	if w.Code != 200 || bytes.Contains(w.Body.Bytes(), []byte("private workflow result")) {
		t.Fatalf("list leaked output=%d %s", w.Code, w.Body)
	}
	w = request("GET", "/api/skill-runs/"+strconv.FormatInt(created.ID, 10), nil, true)
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte("private workflow result")) {
		t.Fatalf("detail=%d %s", w.Code, w.Body)
	}
	payload["client_run_id"] = "bad-hash-" + now.Format("150405")
	payload["script_sha256"] = payload["input_sha256"]
	if w := request("POST", "/api/skill-runs", payload, true); w.Code != 400 {
		t.Fatalf("bad package accepted=%d %s", w.Code, w.Body)
	}
	afterLoads := request("GET", "/api/skills/saved-header-review/usage", nil, true)
	if beforeLoads.Code != 200 || afterLoads.Code != 200 || !bytes.Equal(beforeLoads.Body.Bytes(), afterLoads.Body.Bytes()) {
		t.Fatalf("execution reports changed Skill loads: before=%d %s after=%d %s", beforeLoads.Code, beforeLoads.Body, afterLoads.Code, afterLoads.Body)
	}
	if w := request("GET", "/api/skill-runs/"+strconv.FormatInt(created.ID, 10), nil, false); w.Code != 401 {
		t.Fatalf("unauthenticated detail=%d", w.Code)
	}
	if w := request("PATCH", "/api/skill-runs/"+strconv.FormatInt(created.ID, 10), map[string]string{"stdout": "changed"}, true); w.Code != 405 {
		t.Fatalf("mutable report route=%d", w.Code)
	}
}

func TestSkillRunEvidenceSurvivesTaskDeletionAndServerRestart(t *testing.T) {
	m := newParityTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root, err := filepath.Abs("../skills")
	if err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	s := New(ctx, m, root, dataDir, t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path string, payload any) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	w := request("POST", "/api/tasks", map[string]string{"description": "skill evidence history", "goal": "retain offline report"})
	var task struct {
		ID string `json:"id"`
	}
	if w.Code != 201 {
		t.Fatalf("task=%d %s", w.Code, w.Body)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer request("DELETE", "/api/tasks/"+task.ID, nil)
	hashes := map[string]string{}
	for _, name := range []string{"scripts/run.py", "SKILL.md"} {
		raw, err := os.ReadFile(filepath.Join(root, "saved-header-review", name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		hashes[name] = hex.EncodeToString(sum[:])
	}
	now := time.Now().UTC()
	payload := map[string]any{"client_run_id": "task-evidence-" + strconv.FormatInt(now.UnixNano(), 10), "skill": "saved-header-review", "package_version": "artex-authored-1", "script_sha256": hashes["scripts/run.py"], "instructions_sha256": hashes["SKILL.md"], "input_label": "headers.json", "input_sha256": hashes["SKILL.md"], "input_kind": "file", "input_bytes": 1, "started_at": now.Add(-time.Second), "finished_at": now, "exit_code": 0, "outcome": "succeeded", "stdout": "historical result", "task_id": taskID}
	w = request("POST", "/api/skill-runs", payload)
	var created struct {
		ID int64 `json:"id"`
	}
	if w.Code != 201 {
		t.Fatalf("report=%d %s", w.Code, w.Body)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	w = request("DELETE", "/api/tasks/"+task.ID, nil)
	if w.Code != 200 {
		t.Fatalf("delete task=%d %s", w.Code, w.Body)
	}
	// Recreate the HTTP application against the same PostgreSQL storage and JWT key.
	s = New(ctx, m, root, dataDir, t.TempDir())
	token, err = signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	w = request("GET", "/api/skill-runs/"+strconv.FormatInt(created.ID, 10), nil)
	var retained struct {
		Stdout string `json:"stdout"`
		TaskID *int64 `json:"task_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &retained); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || retained.Stdout != "historical result" || retained.TaskID != nil {
		t.Fatalf("history=%d %s", w.Code, w.Body)
	}
	if w := request("POST", "/api/skill-runs", payload); w.Code != 200 {
		t.Fatalf("retry deleted task report=%d %s", w.Code, w.Body)
	}
}

func TestSkillRunEvidenceReceivesActualFixedWorkflowCLI(t *testing.T) {
	m := newParityTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root, err := filepath.Abs("../skills")
	if err != nil {
		t.Fatal(err)
	}
	s := New(ctx, m, root, t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(s.Handler())
	defer api.Close()
	python := os.Getenv("ARTEX_TEST_PYTHON")
	if python == "" {
		python, err = exec.LookPath("python3")
		if err != nil {
			t.Skip("set ARTEX_TEST_PYTHON for actual CLI")
		}
	}
	input := filepath.Join(t.TempDir(), "headers.json")
	if err := os.WriteFile(input, []byte(`{"url":"https://service.test/","headers":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, python, "../scripts/skills/run_workflow.py", "saved-header-review", input, "--skills-dir", root, "--artex-url", api.URL)
	command.Env = append(os.Environ(), "ARTEX_SKILL_RUN_TOKEN="+token)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("actual workflow submission: %v %s", err, output)
	}
	var emitted map[string]any
	first := bytes.SplitN(output, []byte("\n"), 2)[0]
	if err := json.Unmarshal(first, &emitted); err != nil {
		t.Fatalf("CLI evidence: %v %s", err, output)
	}
	r := httptest.NewRequest("GET", "/api/skill-runs?skill=saved-header-review&limit=100", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var list struct {
		Items []struct {
			ID          int64  `json:"id"`
			ClientRunID string `json:"client_run_id"`
			Outcome     string `json:"outcome"`
			Stdout      string `json:"stdout"`
		} `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	for _, item := range list.Items {
		if item.ClientRunID != emitted["client_run_id"] {
			continue
		}
		if item.Outcome != "succeeded" || item.Stdout != "" {
			t.Fatalf("list evidence: %+v", item)
		}
		r = httptest.NewRequest("GET", "/api/skill-runs/"+strconv.FormatInt(item.ID, 10), nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w = httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte("strict-transport-security")) || !bytes.Contains(w.Body.Bytes(), []byte("operator_reported")) {
			t.Fatalf("persisted actual result: %d %s", w.Code, w.Body)
		}
		return
	}
	t.Fatalf("actual report not found: %s", w.Body)
}
