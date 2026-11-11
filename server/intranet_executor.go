package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// intranetAdapterExecutor is the #10 IntranetExecutor over the #9 C2/WebShell
// adapter. It exists so intranet_exec runs a real command on a real session
// instead of reporting integration_unreachable.
//
// Ownership and liveness are re-read from PostgreSQL on every call: the tool has
// already resolved the context once, but the task/agent must not be able to
// outlive a session that went stale or a task that lost its association.
type intranetAdapterExecutor struct {
	s *Server
}

var _ agent.IntranetExecutor = intranetAdapterExecutor{}

// intranetExecutor returns the executor the worker should use, or nil when the
// connection service is not available (no PostgreSQL / not initialised). The
// worker treats nil as "tool present but unavailable", so the nil case degrades
// to the #10 behaviour instead of panicking.
func (s *Server) intranetExecutor() agent.IntranetExecutor {
	if s == nil || s.connections == nil {
		return nil
	}
	return intranetAdapterExecutor{s: s}
}

// Exec runs one non-interactive command on a session owned by taskID. A non-zero
// exit, a timeout, a refused capability or a transport failure all come back as
// an error that carries the real outcome, so the model sees what happened rather
// than a fabricated success.
func (e intranetAdapterExecutor) Exec(ctx context.Context, taskID, sessionID int64, command string) (string, error) {
	command = strings.TrimSpace(command)
	if taskID < 1 || sessionID < 1 || command == "" {
		return "", errors.New("intranet exec requires a task, a session and a non-empty command")
	}
	item, _, err := e.s.m.pg.GetInventorySession(ctx, sessionID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("session %d does not exist", sessionID)
	}
	if err != nil {
		return "", fmt.Errorf("read session %d: %w", sessionID, err)
	}
	if item.TaskID == nil || *item.TaskID != taskID {
		return "", fmt.Errorf("session %d does not belong to task %d", sessionID, taskID)
	}
	if item.EffectiveState != "connected" {
		return "", fmt.Errorf("session %d is %s; refusing execution (re-sync the adapter)", sessionID, item.EffectiveState)
	}
	requestID := fmt.Sprintf("intranet-%d-%d", taskID, time.Now().UnixNano())
	record, _, err := e.s.executeConnectionOperation(ctx, sessionID, connectionOpRequest{
		Action:    "exec",
		Cmd:       command,
		RequestID: requestID,
	})
	if err != nil {
		var opErr *connectionOpError
		if errors.As(err, &opErr) {
			return "", errors.New(opErr.message)
		}
		return "", fmt.Errorf("record intranet operation: %w", err)
	}
	if record.Status == "succeeded" {
		return record.Output, nil
	}
	// Every non-success carries the stored outcome verbatim: the tool discards
	// output when an error is returned, so the message is the only channel the
	// model has for the real exit code, stderr and the start of stdout.
	message := "command failed"
	switch record.Status {
	case "unsupported":
		message = "action exec is not declared by this adapter"
	case "timeout":
		message = "command timed out" + connectionOpWindow(record)
	case "failed":
		message = fmt.Sprintf("command failed (exit %s)", connectionExitText(record.ExitCode))
	}
	if body := connectionOutputTail(record.Output); body != "" {
		message += "; stdout: " + body
	}
	return record.Output, errors.New(message + connectionDetail(record.Error))
}

// connectionOutputTail keeps the end of the output, which is where the error
// text usually is, and caps it so a huge stream cannot flood the tool result.
func connectionOutputTail(output string) string {
	output = strings.TrimSpace(output)
	if len(output) > 2000 {
		output = output[len(output)-2000:]
	}
	return output
}

func connectionDetail(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	return ": " + trimConnectionText(text, 1000)
}

func connectionExitText(code *int) string {
	if code == nil {
		return "unknown"
	}
	return fmt.Sprintf("%d", *code)
}

func connectionOpWindow(record db.ConnectionOperation) string {
	if record.FinishedAt == nil {
		return ""
	}
	return " (" + record.FinishedAt.Sub(record.StartedAt).Round(time.Millisecond).String() + ")"
}
