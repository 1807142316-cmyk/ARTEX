package db

import (
	"context"
	"database/sql"
	"strconv"
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
// no_session / session_stale / credential_expired / integration_unreachable come
// straight from the #10 contract. no_credential is the one addition: a task can
// hold a perfectly live session and still have nothing to authenticate with, and
// reporting that as credential_expired would be a lie the UI would have to
// explain away.
const (
	IntranetReasonNoSession              = "no_session"
	IntranetReasonSessionStale           = "session_stale"
	IntranetReasonNoCredential           = "no_credential"
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
// Availability requires BOTH a usable session and a usable credential: a worker
// handed only a session has no way in, and one handed only a credential has no
// route. Unavailable reasons are ordered from most basic to most specific —
// session problems outrank credential problems — so the same task always reports
// the same reason.
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
	stale := false
	for rows.Next() {
		s, scanErr := scanInventory(rows)
		if scanErr != nil {
			rows.Close()
			return intranetStorageFailure()
		}
		switch s.EffectiveState {
		case "connected":
			if s.HeartbeatAt != nil {
				usable = append(usable, IntranetSession{ID: s.ID, Host: s.Host, URL: s.URL, Protocol: s.ProtocolLabel, State: s.EffectiveState, HeartbeatAt: *s.HeartbeatAt})
			}
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
		// Distinguish "never had a route in" from "went quiet": both leave the
		// worker without a session, but only one of them is worth chasing.
		if stale {
			return IntranetUnavailable(IntranetReasonSessionStale), nil
		}
		return IntranetUnavailable(IntranetReasonNoSession), nil
	}
	rows, err = d.QueryContext(ctx, `SELECT id,label,scope,state,expires_at FROM session_inventory_nodes
 WHERE task_id=$1 AND kind='credential_ref' ORDER BY id`, taskID)
	if err != nil {
		return intranetStorageFailure()
	}
	credentials := []IntranetCredential{}
	expired := false
	for rows.Next() {
		var id int64
		var label, scope, state string
		var expiresAt *time.Time
		if err = rows.Scan(&id, &label, &scope, &state, &expiresAt); err != nil {
			rows.Close()
			return intranetStorageFailure()
		}
		// An inactive (not merely expired) credential is also unusable; only the
		// expiry gets its own reason, because only the expiry is self-explanatory.
		if inventoryCredentialExpired("credential_ref", state, expiresAt) || state != "active" {
			expired = true
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
	switch {
	case len(credentials) > 0:
		return IntranetContext{Variant: IntranetVariantContextual, Available: true, Sessions: usable, Credentials: credentials}, nil
	case expired:
		return IntranetUnavailable(IntranetReasonCredentialExpired), nil
	default:
		return IntranetUnavailable(IntranetReasonNoCredential), nil
	}
}
