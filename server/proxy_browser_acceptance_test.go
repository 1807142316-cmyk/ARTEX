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
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// Opt in with the installed, pinned Playwright MCP CLI and Chromium paths. The
// test invokes the same assembled MCP tool a task Agent receives, without an LLM.
func TestProxyPoolRealAgentBrowserKeepsTaskExitsSeparate(t *testing.T) {
	cli := os.Getenv("ARTEX_BROWSER_ACCEPTANCE_CLI")
	executable := os.Getenv("ARTEX_BROWSER_ACCEPTANCE_EXECUTABLE")
	if cli == "" || executable == "" {
		t.Skip("set ARTEX_BROWSER_ACCEPTANCE_CLI and ARTEX_BROWSER_ACCEPTANCE_EXECUTABLE")
	}
	for _, path := range []string{cli, executable} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("NO_PROXY", "*")
	t.Setenv("no_proxy", "*")
	m := newProxyPoolTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	oldAugment := agent.ToolAugment
	t.Cleanup(func() { agent.ToolAugment = oldAugment })
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	handler := s.Handler()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	api := func(method, path string, value any) map[string]json.RawMessage {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code < 200 || w.Code >= 300 {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body)
		}
		out := map[string]json.RawMessage{}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	servers, err := m.pg.ListMCP()
	if err != nil {
		t.Fatal(err)
	}
	var browser *db.MCPServer
	for _, config := range servers {
		if config.Name == browserMCPName {
			browser = config
			break
		}
	}
	if browser == nil {
		t.Fatal("seeded browser MCP absent")
	}
	original := *browser
	t.Cleanup(func() { _, _ = m.pg.SaveMCP(&original) })
	browser.Command = "node"
	if node := os.Getenv("ARTEX_BROWSER_ACCEPTANCE_NODE"); node != "" {
		browser.Command = node
	}
	browser.Transport, browser.Enabled = "stdio", true
	browser.Args = encodeJSON([]string{cli, "--headless", "--isolated", "--browser", "chromium", "--executable-path", executable, "--no-sandbox", "--output-dir", filepath.Join(t.TempDir(), "browser-output")})
	browser.Env = encodeJSON(map[string]string{})
	if _, err := m.pg.SaveMCP(browser); err != nil {
		t.Fatal(err)
	}
	worker, err := m.pg.GetAgentByKey("worker")
	if err != nil || worker == nil {
		t.Fatalf("worker absent: %v", err)
	}
	visibility, err := m.pg.AgentVisible(worker.ID, "mcp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.SetAgentVisibilityKind(worker.ID, "mcp", visibility) })
	if err := m.pg.SetAgentVisibilityKind(worker.ID, "mcp", []int64{browser.ID}); err != nil {
		t.Fatal(err)
	}
	api("PUT", "/api/proxies/settings", map[string]any{"enabled": true})
	defer api("PUT", "/api/proxies/settings", map[string]any{"enabled": false})
	type browserRoute struct {
		taskID string
		marker string
		hits   *atomic.Int32
	}
	var routes []browserRoute
	for i := 1; i <= 2; i++ {
		marker := fmt.Sprintf("TASK_BROWSER_EXIT_%d", i)
		hits := &atomic.Int32{}
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/exit" {
				fmt.Fprintf(w, `{"ip":%q}`, fmt.Sprintf("192.0.2.%d", i))
				return
			}
			if r.Header.Get("Proxy-Authorization") != "" {
				t.Error("task gateway credentials reached upstream")
			}
			if r.URL.Hostname() == "task-browser.invalid" && r.URL.Path == "/route" {
				hits.Add(1)
			}
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<!doctype html><title>%s</title><h1>%s</h1>", marker, marker)
		}))
		defer proxy.Close()
		created := api("POST", "/api/proxies", map[string]any{"name": marker, "url": proxy.URL, "check_url": "http://browser-check.invalid/exit", "enabled": true})
		var endpointID int64
		if err := json.Unmarshal(created["id"], &endpointID); err != nil {
			t.Fatal(err)
		}
		api("POST", fmt.Sprintf("/api/proxies/%d/check", endpointID), nil)
		task, err := m.CreateTask("Browser exit acceptance", "Read the local task exit marker", nil, 0, 300)
		if err != nil {
			t.Fatal(err)
		}
		defer api("DELETE", "/api/tasks/"+task.ID, nil)
		api("POST", "/api/tasks/"+task.ID+"/egress", map[string]any{"proxy_id": endpointID})
		routes = append(routes, browserRoute{task.ID, marker, hits})
	}
	for _, route := range routes {
		func() {
			taskID, _ := strconv.ParseInt(route.taskID, 10, 64)
			runCtx := agent.WithRunInfo(ctx, agent.RunInfo{TaskID: taskID})
			tools, _, cleanup := agent.ToolAugment(runCtx, "worker")
			if cleanup != nil {
				defer cleanup()
			}
			var navigate actool.CoreTool
			for _, candidate := range tools {
				if strings.HasSuffix(candidate.Name(), "browser_navigate") {
					navigate = candidate
				}
			}
			if navigate == nil {
				t.Fatal("actual browser MCP navigate tool not assembled for worker")
			}
			result, err := navigate.Call(runCtx, json.RawMessage(`{"url":"http://task-browser.invalid/route"}`), &actool.ToolContext{})
			if err != nil || result.IsError || !strings.Contains(result.Flatten(), route.marker) || route.hits.Load() == 0 {
				t.Fatalf("task %s browser route: hits=%d error=%v result=%s", route.taskID, route.hits.Load(), err, result.Flatten())
			}
		}()
	}
	stored, err := m.pg.ListMCP()
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range stored {
		if config.ID == browser.ID && !slices.Equal(decodeStrSlice(config.Args), decodeStrSlice(browser.Args)) {
			t.Fatal("task-specific gateway overwrote persisted browser configuration")
		}
	}
}
