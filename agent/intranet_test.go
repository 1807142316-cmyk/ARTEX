package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

func sampleIntranetContext() IntranetContext {
	expires := time.Now().Add(time.Hour).UTC()
	return IntranetContext{
		Variant:   IntranetVariantContextual,
		Available: true,
		Sessions: []IntranetSession{{
			ID: 42, Host: "app.internal", URL: "https://app.internal/status",
			Protocol: "http_phpcmd", State: "connected", HeartbeatAt: time.Now().UTC(),
		}},
		Credentials: []IntranetCredential{{Ref: "node:7", Label: "svc account", Scope: "host", State: "active", ExpiresAt: &expires}},
	}
}

// TestWorkerPromptGainsIntranetBlockOnlyWhenAvailable is the prompt seam: the
// block appears with the session and credential detail when a context resolves,
// and nothing at all is appended when it does not — an unavailable reason must
// never reach the model, because the model would then reason about why it has no
// access instead of doing the intent.
func TestWorkerPromptGainsIntranetBlockOnlyWhenAvailable(t *testing.T) {
	block := workerIntranetBlock(sampleIntranetContext())
	if block == "" {
		t.Fatal("available context produced no prompt block")
	}
	for _, want := range []string{"内网", "app.internal", "https://app.internal/status", "http_phpcmd", "svc account", "node:7", "worker_intranet"} {
		if !strings.Contains(block, want) {
			t.Fatalf("block missing %q:\n%s", want, block)
		}
	}
	if !strings.Contains(block, "本任务") {
		t.Fatalf("block must scope use to the associated task:\n%s", block)
	}

	unavailable := IntranetContext{Variant: IntranetVariantPlain, Reason: ReasonSessionStale}
	if got := workerIntranetBlock(unavailable); got != "" {
		t.Fatalf("unavailable context leaked a block: %q", got)
	}
	if got := workerIntranetBlock(IntranetContext{}); got != "" {
		t.Fatalf("zero context leaked a block: %q", got)
	}
}

func intranetTool(t *testing.T, tools []actool.CoreTool, name string) actool.CoreTool {
	t.Helper()
	for _, tool := range tools {
		if tool.Name() == name {
			return tool
		}
	}
	t.Fatalf("tool %q not registered (have %d tools)", name, len(tools))
	return nil
}

func callTool(t *testing.T, tool actool.CoreTool, input string) actool.Result {
	t.Helper()
	res, err := tool.Call(context.Background(), json.RawMessage(input), &actool.ToolContext{})
	if err != nil {
		t.Fatalf("%s returned transport error: %v", tool.Name(), err)
	}
	return res
}

// TestWorkerIntranetToolsRegisterOnlyWithContext covers registration: without a
// resolver there are no tools (so the model is never offered a capability it
// cannot use), and with one both task-scoped tools appear.
func TestWorkerIntranetToolsRegisterOnlyWithContext(t *testing.T) {
	w := &Worker{}
	if tools := w.intranetTools(context.Background(), 1); len(tools) != 0 {
		t.Fatalf("nil resolver registered %d tools", len(tools))
	}

	w.SetIntranetContext(func(context.Context, int64) (IntranetContext, bool) {
		return sampleIntranetContext(), true
	})
	tools := w.intranetTools(context.Background(), 1)
	if len(tools) != 2 {
		t.Fatalf("registered %d tools, want 2", len(tools))
	}
	intranetTool(t, tools, "intranet_sessions")
	intranetTool(t, tools, "intranet_exec")

	// A resolver that says "no" is the same as no resolver: no tools, no block.
	unavailable := &Worker{}
	unavailable.SetIntranetContext(func(context.Context, int64) (IntranetContext, bool) {
		return IntranetContext{Reason: ReasonNoSession}, false
	})
	if tools := unavailable.intranetTools(context.Background(), 1); len(tools) != 0 {
		t.Fatalf("unavailable resolver registered %d tools", len(tools))
	}
}

// TestWorkerIntranetExecReportsUnwiredExecutor covers the explicit gap left by
// #9 not being merged: the tool exists, validates its call, and then says
// plainly that no executor is wired instead of pretending success.
func TestWorkerIntranetExecReportsUnwiredExecutor(t *testing.T) {
	w := &Worker{}
	w.SetIntranetContext(func(context.Context, int64) (IntranetContext, bool) {
		return sampleIntranetContext(), true
	})
	exec := intranetTool(t, w.intranetTools(context.Background(), 1), "intranet_exec")
	res := callTool(t, exec, `{"session_id":42,"command":"id"}`)
	if !res.IsError {
		t.Fatalf("unwired executor returned success: %s", res.Flatten())
	}
	if !strings.Contains(res.Flatten(), "unavailable") && !strings.Contains(res.Flatten(), "不可用") {
		t.Fatalf("unwired executor error is not explicit: %s", res.Flatten())
	}
}

// TestWorkerIntranetExecValidatesEveryCall covers per-call validation: the tool
// re-resolves the context on each call, so a session that went stale, an unknown
// session, and a cross-task session are all refused after the tool was built.
type recordingExecutor struct {
	taskID    int64
	sessionID int64
	command   string
	calls     int
	err       error
}

func (e *recordingExecutor) Exec(_ context.Context, taskID, sessionID int64, command string) (string, error) {
	e.calls++
	e.taskID, e.sessionID, e.command = taskID, sessionID, command
	if e.err != nil {
		return "", e.err
	}
	return "uid=0(root)", nil
}

func TestWorkerIntranetExecValidatesEveryCall(t *testing.T) {
	current := sampleIntranetContext()
	var resolvedTask int64
	w := &Worker{}
	w.SetIntranetContext(func(_ context.Context, taskID int64) (IntranetContext, bool) {
		resolvedTask = taskID
		return current, current.Available
	})
	executor := &recordingExecutor{}
	w.SetIntranetExecutor(executor)
	exec := intranetTool(t, w.intranetTools(context.Background(), 99), "intranet_exec")

	// Happy path: the call reaches the executor with this call's task and session.
	res := callTool(t, exec, `{"session_id":42,"command":"id"}`)
	if res.IsError || !strings.Contains(res.Flatten(), "uid=0") {
		t.Fatalf("wired execution failed: %s", res.Flatten())
	}
	if resolvedTask != 99 || executor.taskID != 99 || executor.sessionID != 42 || executor.command != "id" {
		t.Fatalf("call routing task=%d/%d session=%d command=%q", resolvedTask, executor.taskID, executor.sessionID, executor.command)
	}

	// Unknown session: not in this task's context.
	if res := callTool(t, exec, `{"session_id":7,"command":"id"}`); !res.IsError {
		t.Fatalf("unknown session accepted: %s", res.Flatten())
	}

	// Empty command and missing session are refused before any work.
	if res := callTool(t, exec, `{"session_id":42,"command":"   "}`); !res.IsError {
		t.Fatalf("empty command accepted: %s", res.Flatten())
	}
	if res := callTool(t, exec, `{}`); !res.IsError {
		t.Fatalf("missing session accepted: %s", res.Flatten())
	}

	// The context goes stale between calls: the very same tool must refuse now.
	current = IntranetContext{Variant: IntranetVariantPlain, Reason: ReasonSessionStale}
	before := executor.calls
	if res := callTool(t, exec, `{"session_id":42,"command":"id"}`); !res.IsError {
		t.Fatalf("stale context accepted: %s", res.Flatten())
	}
	if executor.calls != before {
		t.Fatalf("executor reached with a stale context")
	}
}

// TestWorkerIntranetSessionsListsEffectiveContext covers the read tool: it lists
// exactly what the model was told, and reports unavailability explicitly.
func TestWorkerIntranetSessionsListsEffectiveContext(t *testing.T) {
	current := sampleIntranetContext()
	w := &Worker{}
	w.SetIntranetContext(func(context.Context, int64) (IntranetContext, bool) { return current, current.Available })
	list := intranetTool(t, w.intranetTools(context.Background(), 5), "intranet_sessions")

	res := callTool(t, list, `{}`)
	for _, want := range []string{"app.internal", "node:7", "svc account"} {
		if !strings.Contains(res.Flatten(), want) {
			t.Fatalf("listing missing %q: %s", want, res.Flatten())
		}
	}

	current = IntranetContext{Variant: IntranetVariantPlain, Reason: ReasonCredentialExpired}
	res = callTool(t, list, `{}`)
	if !res.IsError || !strings.Contains(res.Flatten(), ReasonCredentialExpired) {
		t.Fatalf("unavailable listing=%q error=%v", res.Flatten(), res.IsError)
	}
}

// TestWorkerIntranetExecutorErrorsSurfaceAsToolErrors keeps adapter failures
// (unsupported action, timeout) visible to the model rather than swallowed.
func TestWorkerIntranetExecutorErrorsSurfaceAsToolErrors(t *testing.T) {
	w := &Worker{}
	current := sampleIntranetContext()
	w.SetIntranetContext(func(context.Context, int64) (IntranetContext, bool) { return current, true })
	w.SetIntranetExecutor(&recordingExecutor{err: errors.New("unsupported action: upload")})
	exec := intranetTool(t, w.intranetTools(context.Background(), 1), "intranet_exec")
	res := callTool(t, exec, `{"session_id":42,"command":"upload x"}`)
	if !res.IsError || !strings.Contains(res.Flatten(), "unsupported action") {
		t.Fatalf("executor error swallowed: %q error=%v", res.Flatten(), res.IsError)
	}
}

// TestWorkerIntranetToolsGatedOnResolvedContext covers the run-level gate: a
// worker with a resolver that reports unavailability registers NO intranet tools
// and appends NO prompt block, so the model is never shown a capability that the
// resolver would refuse at call time.
func TestWorkerIntranetToolsGatedOnResolvedContext(t *testing.T) {
	w := &Worker{}
	w.SetIntranetContext(func(context.Context, int64) (IntranetContext, bool) {
		return IntranetContext{Variant: IntranetVariantPlain, Reason: ReasonCredentialExpired}, false
	})
	if _, ok := w.resolveIntranet(context.Background(), 3); ok {
		t.Fatal("unavailable resolver resolved as available")
	}
	if tools := w.intranetTools(context.Background(), 3); len(tools) != 0 {
		t.Fatalf("unavailable resolver registered %d tools", len(tools))
	}
	if block := workerIntranetBlock(IntranetContext{}); block != "" {
		t.Fatalf("unavailable context produced a block: %q", block)
	}

	// A context that claims available but carries no session is also refused:
	// there is nothing to execute through.
	w.SetIntranetContext(func(context.Context, int64) (IntranetContext, bool) {
		return IntranetContext{Variant: IntranetVariantContextual, Available: true}, true
	})
	if _, ok := w.resolveIntranet(context.Background(), 3); ok {
		t.Fatal("sessionless context resolved as available")
	}
	if tools := w.intranetTools(context.Background(), 3); len(tools) != 0 {
		t.Fatalf("sessionless context registered %d tools", len(tools))
	}

	// Task id 0 (no task) never resolves, so a non-task agent never gets tools.
	w.SetIntranetContext(func(context.Context, int64) (IntranetContext, bool) { return sampleIntranetContext(), true })
	if tools := w.intranetTools(context.Background(), 0); len(tools) != 0 {
		t.Fatalf("taskless worker registered %d tools", len(tools))
	}
}
