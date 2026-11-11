package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
	"gopkg.in/yaml.v3"
)

func TestSkillCategoriesPreserveContentBindingsAndMeasureActualLoads(t *testing.T) {
	if _, _, err := db.DSN(); err != nil {
		t.Skip(err)
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	oldAugment := agent.ToolAugment
	t.Cleanup(func() { agent.ToolAugment = oldAugment })
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	h := s.Handler()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path string, body any, authenticated bool) *httptest.ResponseRecorder {
		t.Helper()
		var data []byte
		if body != nil {
			data, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(data))
		if authenticated {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if got := request("GET", "/api/skills", nil, false); got.Code != http.StatusUnauthorized {
		t.Fatalf("auth: %d", got.Code)
	}
	name := fmt.Sprintf("skill-categories-%d", time.Now().UnixNano())
	created := request("POST", "/api/skills", map[string]any{"name": name, "description": "Inspect saved evidence", "category": "证据整理", "instructions": "Run the local evidence workflow."}, true)
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body)
	}
	list := request("GET", "/api/skills?category="+"%E8%AF%81%E6%8D%AE%E6%95%B4%E7%90%86", nil, true)
	var catalog struct {
		Skills []struct {
			Name     string `json:"name"`
			Category string `json:"category"`
			Calls    int    `json:"calls"`
		} `json:"skills"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &catalog); err != nil {
		t.Fatal(err)
	}
	if len(catalog.Skills) != 1 || catalog.Skills[0].Category != "证据整理" || catalog.Skills[0].Calls != 0 {
		t.Fatalf("categorized list: %s", list.Body)
	}
	md := "---\nname: " + name + "\ndescription: Inspect saved evidence\ncategory: &kind 证据整理\nmetadata:\n  original: *kind\n  owner: local-team\n  labels: [offline, reproducible]\n---\nKeep this exact instruction body.\n"
	if got := request("PUT", "/api/skills/"+name+"/files/SKILL.md", map[string]string{"content": md}, true); got.Code != 200 {
		t.Fatalf("write: %s", got.Body)
	}
	if got := request("PUT", "/api/skills/"+name+"/meta", map[string]string{"category": "报告整理"}, true); got.Code != 200 {
		t.Fatalf("update: %s", got.Body)
	}
	file := request("GET", "/api/skills/"+name+"/files/SKILL.md", nil, true)
	var content struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(file.Body.Bytes(), &content); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(content.Content, "Keep this exact instruction body.\n") || !strings.Contains(content.Content, "owner: local-team") || !strings.Contains(content.Content, "offline") {
		t.Fatalf("metadata/body lost: %s", file.Body)
	}
	frontmatter, _, err := splitSkillFrontmatter([]byte(content.Content))
	if err != nil {
		t.Fatal(err)
	}
	var updatedMetadata struct {
		Category string         `yaml:"category"`
		Metadata map[string]any `yaml:"metadata"`
	}
	if err := yaml.Unmarshal(frontmatter, &updatedMetadata); err != nil {
		t.Fatalf("category update produced invalid alias: %v\n%s", err, content.Content)
	}
	if updatedMetadata.Category != "报告整理" || updatedMetadata.Metadata["original"] != "报告整理" {
		t.Fatalf("alias metadata no longer follows anchored field: %+v", updatedMetadata)
	}
	planner, err := m.pg.GetAgentByKey("planner")
	if err != nil || planner == nil {
		t.Fatalf("planner: %v", err)
	}
	bound := request("POST", "/api/visibility/skill/toggle", map[string]any{"agent_id": fmt.Sprint(planner.ID), "skill_name": name, "visible": true}, true)
	if bound.Code != 200 {
		t.Fatalf("binding: %s", bound.Body)
	}
	t.Cleanup(func() { _ = m.pg.ToggleSkillVisibility(planner.ID, name, false) })
	extra, _, cleanup := agent.ToolAugment(agent.WithRunInfo(ctx, agent.RunInfo{SessionID: "skill-category-test"}), "planner")
	if cleanup != nil {
		defer cleanup()
	}
	var tool actool.CoreTool
	for _, candidate := range extra {
		if candidate.Name() == "Skill" {
			tool = candidate
		}
	}
	if tool == nil {
		t.Fatal("bound skill not available to agent")
	}
	result, err := tool.Call(ctx, json.RawMessage(`{"name":"`+name+`","args":"saved evidence"}`), &actool.ToolContext{})
	if err != nil || result.IsError || len(result.Extra) == 0 {
		t.Fatalf("skill load: %+v %v", result, err)
	}
	list = request("GET", "/api/skills?q="+name, nil, true)
	if err := json.Unmarshal(list.Body.Bytes(), &catalog); err != nil {
		t.Fatal(err)
	}
	if len(catalog.Skills) != 1 || catalog.Skills[0].Category != "报告整理" || catalog.Skills[0].Calls != 1 {
		t.Fatalf("actual load stats/category: %s", list.Body)
	}
}

func TestAuthoredSkillPackageLoadsWithResolvedResourcesAndUsage(t *testing.T) {
	if _, _, err := db.DSN(); err != nil {
		t.Skip(err)
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	oldAugment := agent.ToolAugment
	t.Cleanup(func() { agent.ToolAugment = oldAugment })
	skillRoot := t.TempDir()
	packageNames := []string{
		"saved-header-review", "evidence-inventory", "cve-record-review", "scope-asset-inventory", "har-api-inventory", "knowledge-package-check", "report-evidence-index",
		"tls-observation-review", "cors-policy-review", "cookie-attribute-review", "sshd-effective-config-review", "container-inspect-review", "iam-policy-review", "sbom-inventory-review",
		"python-source-review",
	}
	for _, name := range packageNames {
		for _, relative := range []string{"SKILL.md", "scripts/run.py"} {
			content, err := os.ReadFile(filepath.Join("..", "skills", name, relative))
			if err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(skillRoot, name, relative)
			if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(destination, content, 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	s := New(ctx, m, skillRoot, t.TempDir(), t.TempDir())
	h := s.Handler()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := m.pg.GetAgentByKey("planner")
	if err != nil || planner == nil {
		t.Fatalf("planner: %v", err)
	}
	originalBindings, err := m.pg.AgentSkillNames(planner.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.SetAgentSkillVisibility(planner.ID, originalBindings) })
	for _, name := range packageNames {
		before := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/skills?q="+name, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		h.ServeHTTP(before, r)
		var old struct {
			Skills []struct {
				Calls int `json:"calls"`
			} `json:"skills"`
		}
		if err := json.Unmarshal(before.Body.Bytes(), &old); err != nil || len(old.Skills) != 1 {
			t.Fatalf("initial catalog: %s %v", before.Body, err)
		}
		if err := m.pg.ToggleSkillVisibility(planner.ID, name, true); err != nil {
			t.Fatal(err)
		}
		extra, _, cleanup := agent.ToolAugment(ctx, "planner")
		var result actool.Result
		found := false
		for _, tool := range extra {
			if tool.Name() != "Skill" {
				continue
			}
			found = true
			result, err = tool.Call(ctx, json.RawMessage(`{"name":"`+name+`"}`), &actool.ToolContext{})
		}
		if cleanup != nil {
			cleanup()
		}
		if !found || err != nil || result.IsError || len(result.Extra) == 0 {
			t.Fatalf("authored package %s load failed: %+v %v", name, result, err)
		}
		messages, err := json.Marshal(result.Extra)
		if err != nil || !bytes.Contains(messages, []byte("scripts/run.py")) || bytes.Contains(messages, []byte("${SKILL_DIR}")) {
			t.Fatalf("resource paths not resolved for %s: %s %v", name, messages, err)
		}
		after := httptest.NewRecorder()
		r = httptest.NewRequest("GET", "/api/skills?q="+name, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		h.ServeHTTP(after, r)
		var current struct {
			Skills []struct {
				Calls int `json:"calls"`
			} `json:"skills"`
		}
		if err := json.Unmarshal(after.Body.Bytes(), &current); err != nil || len(current.Skills) != 1 || current.Skills[0].Calls != old.Skills[0].Calls+1 {
			t.Fatalf("actual package usage: %s %v", after.Body, err)
		}
	}
}
