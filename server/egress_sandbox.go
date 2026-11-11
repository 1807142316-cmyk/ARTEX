package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/egress"
	actool "github.com/Autumn-27/norma/tool"
)

// settingEgressSandbox turns the transparent task egress sandbox on. It is only
// meaningful together with the proxy pool: without a lease there is no route to
// force traffic through, so the sandbox stays off.
const settingEgressSandbox = "egress_sandbox_enabled"

// egressRelayBinary overrides the relay executable. Empty re-executes the server
// binary itself; tests point it at a failing binary to exercise setup errors.
var egressRelayBinary string

// egressSandbox is the process-wide sandbox manager, created lazily the first
// time a task actually needs it and torn down with the server.
type egressSandbox struct {
	s    *Server
	once sync.Once
	mgr  *egress.Manager
	err  error
}

func (e *egressSandbox) manager() (*egress.Manager, error) {
	e.once.Do(func() {
		e.mgr, e.err = egress.NewManager(egress.Config{
			SocketDir:   filepath.Join(e.s.m.dir, "egress"),
			Resolver:    e.s.egressResolver(),
			RelayBinary: egressRelayBinary,
			Dial:        e.s.taskEgressDial,
			Gateway:     e.s.taskEgressGateway,
			Logf: func(format string, args ...any) {
				log.Printf("[egress] "+format, args...)
			},
			OnFailure: e.s.sandboxFailed,
		})
	})
	return e.mgr, e.err
}

// enabled reports whether the sandbox is switched on AND usable here.
func (e *egressSandbox) enabled() bool {
	if !egress.Available() {
		return false
	}
	if !e.s.m.pg.GetBool(settingProxyPool, false) {
		return false
	}
	return e.s.m.pg.GetBool(settingEgressSandbox, false)
}

// forTask returns the task's sandbox, or nil when the feature is off for it.
func (e *egressSandbox) forTask(ctx context.Context, taskID int64) (*egress.Sandbox, error) {
	if taskID <= 0 || !e.enabled() {
		return nil, nil
	}
	mgr, err := e.manager()
	if err != nil {
		return nil, err
	}
	return mgr.Sandbox(ctx, taskID)
}

func (e *egressSandbox) closeTask(taskID int64) {
	if e.mgr != nil {
		e.mgr.CloseTask(taskID)
	}
}

func (e *egressSandbox) close() {
	if e.mgr != nil {
		e.mgr.Close()
	}
}

// taskEgressDial resolves address through the task's existing lease and policy
// code (proxyPool.route + dialTaskProxy) instead of reimplementing routing here.
func (s *Server) taskEgressDial(ctx context.Context, taskID int64, address string) (net.Conn, error) {
	if s.proxyPool == nil {
		return nil, errors.New("task egress pool is unavailable")
	}
	upstream, err := s.proxyPool.route(ctx, taskID)
	if err != nil {
		return nil, err
	}
	return dialTaskProxy(ctx, upstream, address)
}

// taskEgressGateway exposes the task's HTTP gateway address (scheme stripped) so
// the relay can mirror it inside the sandbox namespace: proxy-aware clients keep
// the same proxy URL and still reach the lease-enforcing gateway.
func (s *Server) taskEgressGateway(taskID int64) (string, error) {
	if s.proxyPool == nil {
		return "", errors.New("task egress pool is unavailable")
	}
	address, err := s.proxyPool.gateway(taskID)
	if err != nil {
		return "", err
	}
	return stripProxyScheme(address), nil
}

func stripProxyScheme(address string) string {
	for _, prefix := range []string{"http://", "https://"} {
		if strings.HasPrefix(address, prefix) {
			return strings.TrimPrefix(address, prefix)
		}
	}
	return address
}

// sandboxFailed is the relay's failure callback: the sandbox is already gone, so
// apply the task's existing egress failure policy (pause by default, explicit
// failover or direct when configured) and leave an audit trail.
func (s *Server) sandboxFailed(taskID int64, reason string) {
	if s.proxyPool == nil {
		return
	}
	go s.proxyPool.sandboxFailure(taskID, reason)
}

func (p *proxyPoolService) sandboxFailure(taskID int64, reason string) {
	p.egress.closeTask(taskID)
	ctx, cancel := context.WithTimeout(p.s.ctx, 10*time.Second)
	defer cancel()
	lease, err := p.s.m.pg.TaskEgress(ctx, taskID)
	if err != nil || lease == nil {
		return
	}
	_ = p.s.m.pg.RecordEgressEvent(ctx, taskID, "sandbox_failed", reason)
	if lease.State != "active" {
		// Already paused or explicitly direct: nothing left to renegotiate, but
		// the event above still records what happened.
		return
	}
	p.mu.Lock()
	g := p.gateways[taskID]
	p.mu.Unlock()
	if g != nil {
		g.cancelRequests()
	}
	if _, err := p.failed(ctx, lease); err != nil {
		log.Printf("[egress] task %d failover after sandbox failure: %v", taskID, err)
	}
}

// taskBashSandbox wraps Bash so task commands run inside the task's network
// namespace.
type taskBashSandbox struct {
	actool.CoreTool
	s *Server
}

// Call rewrites the command to run through nsenter, clears proxy bypass
// variables and delegates to the real Bash tool. A sandbox that cannot be
// established pauses the task and fails the call closed: the command never runs
// outside the namespace.
func (t *taskBashSandbox) Call(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	taskID := agent.RunInfoFrom(ctx).TaskID
	sandbox, err := t.s.egress.forTask(ctx, taskID)
	if err != nil {
		t.s.pauseTaskForEgress(taskID, "task egress sandbox setup failed: "+err.Error())
		return actool.Errorf("任务网络沙箱建立失败，命令未执行：" + err.Error()), nil
	}
	if sandbox == nil {
		return t.CoreTool.Call(ctx, input, tc)
	}
	var args map[string]any
	if err := json.Unmarshal(input, &args); err != nil {
		return t.CoreTool.Call(ctx, input, tc)
	}
	command, _ := args["command"].(string)
	if strings.TrimSpace(command) == "" {
		return t.CoreTool.Call(ctx, input, tc)
	}
	args["command"] = sandbox.WrapCommand(command)
	rewritten, err := json.Marshal(args)
	if err != nil {
		return t.CoreTool.Call(ctx, input, tc)
	}
	if tc == nil {
		return t.CoreTool.Call(ctx, rewritten, &actool.ToolContext{})
	}
	clone := *tc
	clone.Env = sandboxEnv(tc.Env)
	return t.CoreTool.Call(ctx, rewritten, &clone)
}

// sandboxEnv clears inherited proxy bypasses so proxy-aware clients cannot opt
// out of the task gateway. The proxy address and CA paths are left alone: the
// relay mirrors the gateway address inside the namespace.
func sandboxEnv(env []string) []string {
	out := make([]string, 0, len(env)+2)
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, "NO_PROXY") {
			continue
		}
		out = append(out, entry)
	}
	return append(out, "NO_PROXY=", "no_proxy=")
}

// pauseTaskForEgress pauses a task whose sandbox could not be established or
// whose relay died, recording why.
func (s *Server) pauseTaskForEgress(taskID int64, reason string) {
	if s.proxyPool == nil || taskID <= 0 {
		return
	}
	s.proxyPool.pause(taskID, reason)
}

// sandboxBash is the agent.BashSandbox hook: for a task run with the sandbox
// enabled it returns a Bash decorator, otherwise nil (tool unchanged).
func (s *Server) sandboxBash(ctx context.Context, bash actool.CoreTool) actool.CoreTool {
	if !s.egress.enabled() {
		return nil
	}
	if agent.RunInfoFrom(ctx).TaskID <= 0 {
		return nil
	}
	return &taskBashSandbox{CoreTool: bash, s: s}
}

// egressStatus is what the proxies page shows about the sandbox requirement.
func (s *Server) egressStatus() map[string]any {
	status := map[string]any{
		"available":    egress.Available(),
		"enabled":      s.m.pg.GetBool(settingEgressSandbox, false),
		"mode":         "http-proxy-only",
		"requirements": "Linux + CAP_SYS_ADMIN (CLONE_NEWNET) + CAP_NET_ADMIN (nftables); iproute2, nftables and util-linux (nsenter) must be installed",
	}
	if egress.Available() {
		status["mode"] = "network-namespace"
	}
	return status
}

// putEgressSettings toggles the sandbox. Enabling or disabling it pauses running
// tasks the same way a pool change does: their Bash environments were built
// without the new setting.
func (s *Server) putEgressSettings(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Enabled bool `json:"enabled"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&request) != nil {
		writeErr(w, 400, "invalid settings")
		return
	}
	if request.Enabled && !egress.Available() {
		writeErr(w, 409, "task egress sandbox requires Linux")
		return
	}
	if request.Enabled && !s.m.pg.GetBool(settingProxyPool, false) {
		writeErr(w, 409, "enable the proxy pool before the transparent sandbox")
		return
	}
	if request.Enabled != s.m.pg.GetBool(settingEgressSandbox, false) {
		for _, task := range s.m.List() {
			state := task.lifecycleSnapshot()
			if state.Paused || isTerminalStatus(state.Status) {
				continue
			}
			if _, err := s.applyTaskControlWithCause(task, "pause", errors.New("task egress sandbox configuration changed")); err != nil {
				writeErr(w, 409, "pause active tasks before changing the sandbox")
				return
			}
		}
		s.invalidateTaskAgents()
	}
	if err := s.m.pg.SetBool(settingEgressSandbox, request.Enabled); err != nil {
		writeErr(w, 500, "save settings failed")
		return
	}
	writeJSON(w, 200, s.egressStatus())
}

// egressResolver reads the configured TCP resolver used inside sandboxes.
func (s *Server) egressResolver() string {
	value, ok, err := s.m.pg.GetSetting("egress_dns_resolver")
	if err != nil || !ok || strings.TrimSpace(value) == "" {
		return "1.1.1.1:53"
	}
	return strings.TrimSpace(value)
}

// getEgressStatus reports the sandbox mode and its deployment requirements.
func (s *Server) getEgressStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.egressStatus())
}
