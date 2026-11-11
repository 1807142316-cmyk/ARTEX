package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Connection adapters are operator-configured C2/WebShell endpoints. Only
// http_phpcmd is implemented; the kind column is kept so a future adapter can
// declare its own capabilities without a second table.
type ConnectionAdapter struct {
	ID              int64      `json:"id"`
	Name            string     `json:"name"`
	Kind            string     `json:"kind"`
	BaseURL         string     `json:"base_url"`
	SealedSecret    string     `json:"-"` // AES-GCM; never serialized
	SecretRef       string     `json:"secret_ref"`
	TimeoutSeconds  int        `json:"timeout_seconds"`
	HeartbeatTTL    int        `json:"heartbeat_ttl_seconds"`
	Enabled         bool       `json:"enabled"`
	State           string     `json:"state"`
	LastError       string     `json:"last_error"`
	CheckedAt       *time.Time `json:"checked_at"`
	TaskID          *int64     `json:"task_id,omitempty"`
	AssetID         *int64     `json:"asset_id,omitempty"`
	SessionID       *int64     `json:"session_id,omitempty"` // resolved, not stored
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	OperationCount  int        `json:"operation_count"`
	LastOperationAt *time.Time `json:"last_operation_at,omitempty"`
}

// ConnectionOperation is the explicit record of one request to a session. A
// rejected capability is recorded too, so the UI never shows an action that
// appears to have run when nothing was sent.
type ConnectionOperation struct {
	ID          int64      `json:"id"`
	AdapterID   int64      `json:"adapter_id"`
	SessionID   int64      `json:"session_id"`
	RequestID   string     `json:"request_id"`
	Action      string     `json:"action"`
	ArgsSummary string     `json:"args_summary"`
	Status      string     `json:"status"`
	ExitCode    *int       `json:"exit_code"`
	Output      string     `json:"output"`
	Error       string     `json:"error"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at"`
}

const connectionAdapterColumns = `id,name,kind,base_url,sealed_secret,secret_ref,timeout_seconds,heartbeat_ttl_seconds,enabled,state,last_error,checked_at,task_id,asset_id,created_at,updated_at`

func scanConnectionAdapter(row interface{ Scan(...any) error }) (*ConnectionAdapter, error) {
	a := new(ConnectionAdapter)
	err := row.Scan(&a.ID, &a.Name, &a.Kind, &a.BaseURL, &a.SealedSecret, &a.SecretRef, &a.TimeoutSeconds, &a.HeartbeatTTL, &a.Enabled, &a.State, &a.LastError, &a.CheckedAt, &a.TaskID, &a.AssetID, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return a, err
}

func (d *DB) ConnectionAdapters(ctx context.Context) ([]*ConnectionAdapter, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+connectionAdapterColumns+` FROM connection_adapters ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ConnectionAdapter{}
	for rows.Next() {
		a, e := scanConnectionAdapter(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (d *DB) ConnectionAdapter(ctx context.Context, id int64) (*ConnectionAdapter, error) {
	return scanConnectionAdapter(d.QueryRowContext(ctx, `SELECT `+connectionAdapterColumns+` FROM connection_adapters WHERE id=$1`, id))
}

// CheckConnectionAssociation mirrors the inventory reference rules: the task
// must exist and the asset must be one of that task's assets.
func (d *DB) CheckConnectionAssociation(ctx context.Context, task, asset *int64) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return validateInventoryReferences(ctx, tx, task, asset)
}

func (d *DB) SaveConnectionAdapter(ctx context.Context, a *ConnectionAdapter) error {
	if a.ID == 0 {
		return d.QueryRowContext(ctx, `INSERT INTO connection_adapters(name,kind,base_url,sealed_secret,secret_ref,timeout_seconds,heartbeat_ttl_seconds,enabled,task_id,asset_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id,state,last_error,checked_at,created_at,updated_at`, a.Name, a.Kind, a.BaseURL, a.SealedSecret, a.SecretRef, a.TimeoutSeconds, a.HeartbeatTTL, a.Enabled, a.TaskID, a.AssetID).Scan(&a.ID, &a.State, &a.LastError, &a.CheckedAt, &a.CreatedAt, &a.UpdatedAt)
	}
	// An edit only invalidates the last probe when it changes the endpoint or the
	// credential the probe used. Renames, timeouts, the enabled flag and
	// task/asset associations keep the observed state: resetting on those made a
	// harmless edit look like the adapter had gone offline.
	result, err := d.ExecContext(ctx, `UPDATE connection_adapters SET name=$1,kind=$2,base_url=$3,sealed_secret=$4,secret_ref=$5,timeout_seconds=$6,heartbeat_ttl_seconds=$7,enabled=$8,task_id=$9,asset_id=$10,
 state=CASE WHEN base_url IS DISTINCT FROM $3 OR sealed_secret IS DISTINCT FROM $4 THEN 'unconfigured' ELSE state END,
 last_error=CASE WHEN base_url IS DISTINCT FROM $3 OR sealed_secret IS DISTINCT FROM $4 THEN '' ELSE last_error END,
 checked_at=CASE WHEN base_url IS DISTINCT FROM $3 OR sealed_secret IS DISTINCT FROM $4 THEN NULL ELSE checked_at END,
 updated_at=now() WHERE id=$11`, a.Name, a.Kind, a.BaseURL, a.SealedSecret, a.SecretRef, a.TimeoutSeconds, a.HeartbeatTTL, a.Enabled, a.TaskID, a.AssetID, a.ID)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	updated, err := d.ConnectionAdapter(ctx, a.ID)
	if err != nil {
		return err
	}
	if updated != nil {
		*a = *updated
	}
	return nil
}

func (d *DB) SetConnectionAdapterState(ctx context.Context, id int64, state, lastError string) (*ConnectionAdapter, error) {
	a, err := scanConnectionAdapter(d.QueryRowContext(ctx, `UPDATE connection_adapters SET state=$2,last_error=$3,checked_at=now(),updated_at=now() WHERE id=$1 RETURNING `+connectionAdapterColumns, id, state, lastError))
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, sql.ErrNoRows
	}
	return a, nil
}

func (d *DB) DeleteConnectionAdapter(ctx context.Context, id int64) error {
	result, err := d.ExecContext(ctx, `DELETE FROM connection_adapters WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// NextInventorySequence returns the sequence that would follow the stored
// observation for (source, source_id). 1 when no observation exists yet.
func (d *DB) NextInventorySequence(ctx context.Context, source, sourceID string) (int64, error) {
	var sequence int64
	err := d.QueryRowContext(ctx, `SELECT sequence FROM session_inventory WHERE source=$1 AND source_id=$2`, source, sourceID).Scan(&sequence)
	if errors.Is(err, sql.ErrNoRows) {
		return 1, nil
	}
	if err != nil {
		return 0, err
	}
	return sequence + 1, nil
}

// ConnectionSessions lists the inventory sessions owned by adapter sync. The
// existing observer rows are untouched: the source prefix is what distinguishes
// an adapter-backed session.
func (d *DB) ConnectionSessions(ctx context.Context, q string) ([]InventorySession, error) {
	pattern := likePattern(q)
	rows, err := d.QueryContext(ctx, `SELECT `+inventoryColumns+` FROM (SELECT *,CASE WHEN state='connected' AND heartbeat_at+heartbeat_ttl_seconds*interval '1 second'<now() THEN 'stale' ELSE state END AS effective_state FROM session_inventory WHERE source LIKE 'connection:%') inventory WHERE ($1='' OR source ILIKE $1 OR host ILIKE $1 OR url ILIKE $1) ORDER BY updated_at DESC,id DESC LIMIT 200`, pattern)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []InventorySession{}
	for rows.Next() {
		s, e := scanInventory(rows)
		if e != nil {
			return nil, e
		}
		s.Mode = "adapter"
		out = append(out, s)
	}
	return out, rows.Err()
}

// StartConnectionOperation records the request before it leaves the process.
// A repeated request_id returns the existing row and replayed=true so the
// handler cannot send the same command twice.
func (d *DB) StartConnectionOperation(ctx context.Context, adapterID, sessionID int64, requestID, action, argsSummary string) (ConnectionOperation, bool, error) {
	var op ConnectionOperation
	err := d.QueryRowContext(ctx, `INSERT INTO connection_operations(adapter_id,session_id,request_id,action,args_summary,status) VALUES($1,$2,$3,$4,$5,'running') ON CONFLICT(session_id,request_id) DO NOTHING RETURNING id,adapter_id,session_id,request_id,action,args_summary,status,exit_code,output,error,started_at,finished_at`, adapterID, sessionID, requestID, action, argsSummary).Scan(&op.ID, &op.AdapterID, &op.SessionID, &op.RequestID, &op.Action, &op.ArgsSummary, &op.Status, &op.ExitCode, &op.Output, &op.Error, &op.StartedAt, &op.FinishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		existing, e := d.connectionOperation(ctx, sessionID, requestID)
		return existing, true, e
	}
	return op, false, err
}

func (d *DB) connectionOperation(ctx context.Context, sessionID int64, requestID string) (ConnectionOperation, error) {
	var op ConnectionOperation
	err := d.QueryRowContext(ctx, `SELECT id,adapter_id,session_id,request_id,action,args_summary,status,exit_code,output,error,started_at,finished_at FROM connection_operations WHERE session_id=$1 AND request_id=$2`, sessionID, requestID).Scan(&op.ID, &op.AdapterID, &op.SessionID, &op.RequestID, &op.Action, &op.ArgsSummary, &op.Status, &op.ExitCode, &op.Output, &op.Error, &op.StartedAt, &op.FinishedAt)
	return op, err
}

func (d *DB) FinishConnectionOperation(ctx context.Context, id int64, status string, exitCode *int, output, errMsg string) (ConnectionOperation, error) {
	var op ConnectionOperation
	err := d.QueryRowContext(ctx, `UPDATE connection_operations SET status=$2,exit_code=$3,output=$4,error=$5,finished_at=now() WHERE id=$1 RETURNING id,adapter_id,session_id,request_id,action,args_summary,status,exit_code,output,error,started_at,finished_at`, id, status, exitCode, output, errMsg).Scan(&op.ID, &op.AdapterID, &op.SessionID, &op.RequestID, &op.Action, &op.ArgsSummary, &op.Status, &op.ExitCode, &op.Output, &op.Error, &op.StartedAt, &op.FinishedAt)
	return op, err
}

func (d *DB) ConnectionOperations(ctx context.Context, sessionID int64, limit int) ([]ConnectionOperation, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	rows, err := d.QueryContext(ctx, `SELECT id,adapter_id,session_id,request_id,action,args_summary,status,exit_code,output,error,started_at,finished_at FROM connection_operations WHERE session_id=$1 ORDER BY id DESC LIMIT $2`, sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ConnectionOperation{}
	for rows.Next() {
		var op ConnectionOperation
		if err := rows.Scan(&op.ID, &op.AdapterID, &op.SessionID, &op.RequestID, &op.Action, &op.ArgsSummary, &op.Status, &op.ExitCode, &op.Output, &op.Error, &op.StartedAt, &op.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, op)
	}
	return out, rows.Err()
}

// likePattern escapes SQL LIKE metacharacters for a substring match.
func likePattern(q string) string {
	return "%" + strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(q) + "%"
}

// ConnectionSessionBySource resolves the adapter-owned inventory row. It reads
// through the same effective-state computation as the observer inventory.
func (d *DB) ConnectionSessionBySource(ctx context.Context, source, sourceID string) (*InventorySession, error) {
	s, err := scanInventory(d.QueryRowContext(ctx, `SELECT `+inventoryColumns+` FROM (SELECT *,CASE WHEN state='connected' AND heartbeat_at+heartbeat_ttl_seconds*interval '1 second'<now() THEN 'stale' ELSE state END AS effective_state FROM session_inventory) inventory WHERE source=$1 AND source_id=$2`, source, sourceID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s.Mode = "adapter"
	return &s, nil
}
