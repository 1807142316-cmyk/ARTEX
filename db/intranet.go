package db

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"
)

// IntranetContextVariant* are the two worker prompt variants. The constant names
// are part of the #10 contract: the API returns exactly these strings and the
// agent prompt builder switches on them.
const (
	IntranetVariantContextual = "worker_intranet"
	IntranetVariantPlain      = "worker"
)

// Intranet unavailable reasons. available=false always carries exactly one of
// these and available=true never carries any.
//
// Sessions are the gate: the http_phpcmd adapter needs no credential_ref node,
// so a task with a live session is usable with an empty credential list.
// Credentials are enrichment — an expired or inactive one is simply left out of
// the returned list rather than turning the whole context off.
//
//   - no_session: the task owns no session at all.
//   - session_stale: it owns sessions, but every one is past its heartbeat.
//   - integration_unreachable: the only sessions it owns belong to adapters that
//     cannot execute (disabled, auth_failed, unreachable), or the integration
//     could not be read.
//
// credential_expired remains part of the public vocabulary because topology
// edges use it; the intranet context itself no longer emits it.
const (
	IntranetReasonNoSession              = "no_session"
	IntranetReasonSessionStale           = "session_stale"
	IntranetReasonCredentialExpired      = "credential_expired"
	IntranetReasonIntegrationUnreachable = "integration_unreachable"
)

// IntranetSession is one usable session in a task's intranet context: a session
// observed as connected and still inside its heartbeat window.
type IntranetSession struct {
	ID          int64     `json:"id"`
	Host        string    `json:"host"`
	URL         string    `json:"url"`
	Protocol    string    `json:"protocol"`
	State       string    `json:"state"`
	HeartbeatAt time.Time `json:"heartbeat_at"`
}

// IntranetCredential is one usable credential reference: a credential_ref node
// owned by the task whose expiry (if any) is still in the future.
type IntranetCredential struct {
	Ref       string     `json:"ref"`
	Label     string     `json:"label"`
	Scope     string     `json:"scope"`
	State     string     `json:"state"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// IntranetContext is the task-scoped view the worker may act on. It is built
// only from sessions and credential nodes owned by the task; nothing is inferred
// from subnet membership and nothing is borrowed from another task.
type IntranetContext struct {
	Variant     string               `json:"variant"`
	Available   bool                 `json:"available"`
	Reason      string               `json:"reason"`
	Sessions    []IntranetSession    `json:"sessions"`
	Credentials []IntranetCredential `json:"credentials"`
}

// IntranetUnavailable returns the explicit empty context for reason.
func IntranetUnavailable(reason string) IntranetContext {
	return IntranetContext{Variant: IntranetVariantPlain, Reason: reason, Sessions: []IntranetSession{}, Credentials: []IntranetCredential{}}
}

// intranetStorageFailure is the storage-error path: the intranet integration
// could not be read, so the answer is "unavailable because the integration is
// unreachable" rather than a transport error. That reason is part of the
// contract's public vocabulary, and a caller that cannot distinguish it from
// no_session would misdiagnose its own scope instead of the platform.
func intranetStorageFailure() (IntranetContext, error) {
	return IntranetUnavailable(IntranetReasonIntegrationUnreachable), nil
}

// TaskIntranetContext resolves the intranet context for one task.
//
// A usable session is both necessary and sufficient: the worker reaches the
// target through the session, and the adapter holds its own credential. Tasks
// are gated by sessions only. Credentials are attached when they exist and are
// still valid; expired/inactive ones are excluded, never fatal.
//
// Adapter-backed sessions additionally require their adapter to be enabled and
// last observed reachable — advertising a session whose adapter is disabled or
// rejected the credential would hand the worker a tool call that cannot run.
func (d *DB) TaskIntranetContext(ctx context.Context, taskID int64) (IntranetContext, error) {
	var exists bool
	if err := d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM tasks WHERE id=$1)`, taskID).Scan(&exists); err != nil {
		return intranetStorageFailure()
	}
	if !exists {
		return IntranetContext{}, sql.ErrNoRows
	}
	rows, err := d.QueryContext(ctx, `SELECT `+inventoryColumns+` FROM session_inventory WHERE task_id=$1 ORDER BY id`, taskID)
	if err != nil {
		return intranetStorageFailure()
	}
	usable := []IntranetSession{}
	sawSession := false
	stale := false
	excluded := 0
	for rows.Next() {
		s, scanErr := scanInventory(rows)
		if scanErr != nil {
			rows.Close()
			return intranetStorageFailure()
		}
		sawSession = true
		switch s.EffectiveState {
		case "connected":
			if s.HeartbeatAt == nil {
				continue
			}
			// Adapter-owned sessions are usable only while the adapter itself is
			// in a runnable state. The adapter ID is carried in the source prefix
			// written by the sync path.
			if adapterID := connectionSourceAdapterID(s.Source); adapterID > 0 {
				adapter, adapterErr := d.ConnectionAdapter(ctx, adapterID)
				if adapterErr != nil {
					rows.Close()
					return intranetStorageFailure()
				}
				if adapter == nil || !adapter.Enabled || adapter.State != "reachable" {
					excluded++
					continue
				}
			}
			usable = append(usable, IntranetSession{ID: s.ID, Host: s.Host, URL: s.URL, Protocol: s.ProtocolLabel, State: s.EffectiveState, HeartbeatAt: *s.HeartbeatAt})
		case "stale":
			stale = true
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return intranetStorageFailure()
	}
	rows.Close()
	if len(usable) == 0 {
		// Order the reasons from most basic to most specific so the same task
		// always reports the same one.
		switch {
		case !sawSession:
			return IntranetUnavailable(IntranetReasonNoSession), nil
		case stale:
			return IntranetUnavailable(IntranetReasonSessionStale), nil
		case excluded > 0:
			return IntranetUnavailable(IntranetReasonIntegrationUnreachable), nil
		default:
			return IntranetUnavailable(IntranetReasonNoSession), nil
		}
	}
	rows, err = d.QueryContext(ctx, `SELECT id,label,scope,state,expires_at FROM session_inventory_nodes
 WHERE task_id=$1 AND kind='credential_ref' ORDER BY id`, taskID)
	if err != nil {
		return intranetStorageFailure()
	}
	credentials := []IntranetCredential{}
	for rows.Next() {
		var id int64
		var label, scope, state string
		var expiresAt *time.Time
		if err = rows.Scan(&id, &label, &scope, &state, &expiresAt); err != nil {
			rows.Close()
			return intranetStorageFailure()
		}
		// Expired and inactive credentials are excluded from the list. They do
		// not gate the context: the session is what grants access.
		if inventoryCredentialExpired("credential_ref", state, expiresAt) || state != "active" {
			continue
		}
		credentials = append(credentials, IntranetCredential{
			Ref: "node:" + strconv.FormatInt(id, 10), Label: label, Scope: scope, State: state, ExpiresAt: expiresAt,
		})
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return intranetStorageFailure()
	}
	rows.Close()
	return IntranetContext{Variant: IntranetVariantContextual, Available: true, Sessions: usable, Credentials: credentials}, nil
}

// connectionSourceAdapterID extracts the adapter id from the "connection:<id>"
// inventory source the C2 adapter writes. 0 means the row was not created by an
// adapter (the read-only observer), so no adapter state applies to it.
func connectionSourceAdapterID(source string) int64 {
	const prefix = "connection:"
	if !strings.HasPrefix(source, prefix) {
		return 0
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(source, prefix), 10, 64)
	if err != nil || id < 1 {
		return 0
	}
	return id
}
