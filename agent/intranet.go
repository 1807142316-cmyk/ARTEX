package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// The intranet context types live in db because they are built from PostgreSQL
// rows; the agent package aliases them so the worker API reads in agent terms
// without maintaining a parallel copy that could drift.
type (
	IntranetContext    = db.IntranetContext
	IntranetSession    = db.IntranetSession
	IntranetCredential = db.IntranetCredential
)

// Variant and reason constants, re-exported for the worker-side seam.
const (
	IntranetVariantContextual = db.IntranetVariantContextual
	IntranetVariantPlain      = db.IntranetVariantPlain

	ReasonNoSession              = db.IntranetReasonNoSession
	ReasonSessionStale           = db.IntranetReasonSessionStale
	ReasonCredentialExpired      = db.IntranetReasonCredentialExpired
	ReasonIntegrationUnreachable = db.IntranetReasonIntegrationUnreachable
)

// IntranetExecutor runs one command through a session adapter. It is the seam
// #9 fills in with the real C2/WebShell adapter; until then the server leaves it
// unwired and intranet_exec reports that plainly.
//
// taskID is passed on every call (not captured at construction) so an executor
// can re-verify ownership at execution time rather than trusting the tool.
type IntranetExecutor interface {
	Exec(ctx context.Context, taskID, sessionID int64, command string) (string, error)
}

// SetIntranetContext wires the per-task resolver. The resolver is consulted on
// every run and every tool call, so a session that goes stale or a credential
// that expires mid-run takes effect immediately. nil = no intranet capability.
func (w *Worker) SetIntranetContext(fn func(ctx context.Context, taskID int64) (IntranetContext, bool)) {
	w.intranetContext = fn
}

// SetIntranetExecutor wires the adapter used by intranet_exec. nil leaves the
// tool present but explicitly unavailable, which is the #10 state before #9
// merges.
func (w *Worker) SetIntranetExecutor(executor IntranetExecutor) {
	w.intranetExecutor = executor
}

// errToolf builds a failed tool result with a formatted message; actool.Errorf
// takes only a literal, and every message here carries call detail.
func errToolf(format string, args ...any) actool.Result {
	return actool.Errorf(fmt.Sprintf(format, args...))
}

// resolveIntranet returns the context for taskID, or the zero value when there
// is no resolver, when it reports unavailability, or when the context carries no
// usable session. Everything downstream gates on the second return value.
func (w *Worker) resolveIntranet(ctx context.Context, taskID int64) (IntranetContext, bool) {
	if w.intranetContext == nil || taskID <= 0 {
		return IntranetContext{}, false
	}
	ictx, available := w.intranetContext(ctx, taskID)
	if !available || !ictx.Available || len(ictx.Sessions) == 0 {
		return IntranetContext{}, false
	}
	return ictx, true
}

// intranetUnavailableReason reports the resolver's reason code for a task it
// refused, so a tool call can say WHY it was refused. Only tool results carry a
// reason — the system prompt never does, because a prompt-level reason invites
// the model to argue with the gap instead of finishing the intent.
func (w *Worker) intranetUnavailableReason(ctx context.Context, taskID int64) string {
	if w.intranetContext == nil || taskID <= 0 {
		return ReasonIntegrationUnreachable
	}
	if ictx, _ := w.intranetContext(ctx, taskID); ictx.Reason != "" {
		return ictx.Reason
	}
	return ReasonIntegrationUnreachable
}

// workerIntranetBlock renders the Chinese system-prompt block for an available
// context. An unavailable context renders NOTHING: the model must never learn
// why it has no intranet access, because a reason invites it to reason about the
// gap instead of completing the intent.
func workerIntranetBlock(ictx IntranetContext) string {
	if !ictx.Available || len(ictx.Sessions) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n**【内网上下文 · 变体 ")
	b.WriteString(IntranetVariantContextual)
	b.WriteString("】**\n")
	b.WriteString("本任务已建立可用的内网访问通道。以下会话与凭据**只对本任务有效**：不得用于其它任务、不得跨任务复用，也不得把凭据写入资产、事实或报告正文。\n")
	b.WriteString("\n可用会话（intranet_sessions 可随时重新读取，每次调用都会重新校验有效性）：\n")
	for _, s := range ictx.Sessions {
		b.WriteString(fmt.Sprintf("- 会话 #%d %s · %s · %s · 心跳 %s\n", s.ID, s.Host, s.URL, s.Protocol, s.HeartbeatAt.Format("2006-01-02 15:04:05 MST")))
	}
	if len(ictx.Credentials) > 0 {
		b.WriteString("\n可用凭据引用（只提供引用标识，不含明文）：\n")
		for _, c := range ictx.Credentials {
			b.WriteString(fmt.Sprintf("- %s · %s · 范围 %s · 状态 %s\n", c.Ref, c.Label, c.Scope, c.State))
		}
	}
	b.WriteString("\n**使用规则**：\n")
	b.WriteString("1. 只能通过 intranet_exec 在这些会话上执行命令；其它工具不会走内网通道。\n")
	b.WriteString("2. 会话失效、凭据过期或与本任务无关时，工具会直接拒绝——遇到拒绝就停止，不要重试、不要猜测替代凭据。\n")
	b.WriteString("3. 内网发现同样要写回知识图谱（insert_assets / record_fact / report_finding），并保留真实命令与输出作为证据。\n")
	return b.String()
}

// intranetTools builds the two task-scoped tools. Both re-resolve the context on
// every call, so availability is checked per invocation rather than frozen at
// agent construction.
func (w *Worker) intranetTools(ctx context.Context, taskID int64) []actool.CoreTool {
	if _, ok := w.resolveIntranet(ctx, taskID); !ok {
		return nil
	}
	allow := func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() }
	sessions := actool.Build(actool.Spec{
		Name:        "intranet_sessions",
		Description: "列出本任务当前有效的内网会话与凭据引用（每次调用重新校验）。",
		Prompt:      "返回本任务内网上下文中有效的会话与凭据引用。没有可用上下文时返回错误，不要假设存在通道。",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: allow,
		Run: func(ctx context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			ictx, ok := w.resolveIntranet(ctx, taskID)
			if !ok {
				return errToolf("intranet context unavailable for this task: %s", w.intranetUnavailableReason(ctx, taskID)), nil
			}
			payload, err := json.Marshal(map[string]any{
				"variant":     ictx.Variant,
				"available":   true,
				"sessions":    ictx.Sessions,
				"credentials": ictx.Credentials,
			})
			if err != nil {
				return errToolf("encode intranet context: %v", err), nil
			}
			return actool.Text(string(payload)), nil
		},
	})
	exec := actool.Build(actool.Spec{
		Name:        "intranet_exec",
		Description: "在属于本任务的内网会话上执行一条非交互命令。",
		Prompt:      "在指定会话上执行命令。session_id 必须出现在 intranet_sessions 的返回中；任务不匹配、会话失效或未接入适配器时直接返回错误。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "integer", "description": "intranet_sessions 返回的会话 id"},
				"command":    map[string]any{"type": "string", "description": "非交互命令"},
			},
			"required": []string{"session_id", "command"},
		},
		Permissions: allow,
		Run: func(ctx context.Context, raw json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var input struct {
				SessionID int64  `json:"session_id"`
				Command   string `json:"command"`
			}
			if err := json.Unmarshal(raw, &input); err != nil {
				return errToolf("invalid intranet_exec input: %v", err), nil
			}
			command := strings.TrimSpace(input.Command)
			if input.SessionID < 1 || command == "" {
				return errToolf("intranet_exec requires session_id and a non-empty command"), nil
			}
			ictx, ok := w.resolveIntranet(ctx, taskID)
			if !ok {
				return errToolf("intranet context unavailable for this task: %s; refusing execution", w.intranetUnavailableReason(ctx, taskID)), nil
			}
			allowed := false
			for _, s := range ictx.Sessions {
				if s.ID == input.SessionID && s.State == "connected" {
					allowed = true
					break
				}
			}
			if !allowed {
				return errToolf("session %d is not a valid session for this task", input.SessionID), nil
			}
			if w.intranetExecutor == nil {
				return errToolf("intranet executor unavailable: no session adapter is wired (integration_unreachable)"), nil
			}
			out, err := w.intranetExecutor.Exec(ctx, taskID, input.SessionID, command)
			if err != nil {
				return errToolf("intranet exec failed: %v", err), nil
			}
			return actool.Text(out), nil
		},
	})
	return []actool.CoreTool{sessions, exec}
}
