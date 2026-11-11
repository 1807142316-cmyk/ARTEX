package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var ErrInventoryConflict = errors.New("observation sequence is stale or conflicts with its stored content")
var ErrInventoryReference = errors.New("task/asset reference is missing or the asset does not belong to the task")

type SessionObservation struct {
	Source              string     `json:"source"`
	SourceID            string     `json:"source_id"`
	Sequence            int64      `json:"sequence"`
	Kind                string     `json:"kind"`
	ProtocolLabel       string     `json:"protocol_label"`
	State               string     `json:"state"`
	Host                string     `json:"host"`
	URL                 string     `json:"url"`
	TaskID              *int64     `json:"task_id,omitempty"`
	AssetID             *int64     `json:"asset_id,omitempty"`
	HeartbeatAt         *time.Time `json:"heartbeat_at,omitempty"`
	HeartbeatTTLSeconds int        `json:"heartbeat_ttl_seconds"`
	DisconnectReason    string     `json:"disconnect_reason"`
}
type InventorySession struct {
	ID int64 `json:"id"`
	SessionObservation
	Mode           string    `json:"mode"`
	EffectiveState string    `json:"effective_state"`
	Annotation     string    `json:"annotation"`
	UpdatedAt      time.Time `json:"updated_at"`
}
type InventoryAudit struct {
	ID        int64     `json:"id"`
	Action    string    `json:"action"`
	Sequence  int64     `json:"sequence"`
	State     string    `json:"state"`
	Detail    string    `json:"detail"`
	CreatedAt time.Time `json:"created_at"`
}

const inventoryColumns = `id,source,source_id,sequence,kind,protocol_label,state,host,url,task_id,asset_id,heartbeat_at,heartbeat_ttl_seconds,disconnect_reason,annotation,updated_at`

func scanInventory(row interface{ Scan(...any) error }) (InventorySession, error) {
	var s InventorySession
	err := row.Scan(&s.ID, &s.Source, &s.SourceID, &s.Sequence, &s.Kind, &s.ProtocolLabel, &s.State, &s.Host, &s.URL, &s.TaskID, &s.AssetID, &s.HeartbeatAt, &s.HeartbeatTTLSeconds, &s.DisconnectReason, &s.Annotation, &s.UpdatedAt)
	s.Mode = "observer"
	s.EffectiveState = s.State
	if s.State == "connected" && s.HeartbeatAt != nil && time.Now().After(s.HeartbeatAt.Add(time.Duration(s.HeartbeatTTLSeconds)*time.Second)) {
		s.EffectiveState = "stale"
	}
	return s, err
}
func validateInventoryReferences(ctx context.Context, tx *sql.Tx, task, asset *int64) error {
	if task != nil {
		var id int64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM tasks WHERE id=$1 FOR KEY SHARE`, *task).Scan(&id); errors.Is(err, sql.ErrNoRows) {
			return ErrInventoryReference
		} else if err != nil {
			return err
		}
	}
	if asset != nil {
		var matches bool
		err := tx.QueryRowContext(ctx, `SELECT $2::bigint IS NULL OR $2=ANY(task_ids) FROM assets WHERE id=$1 FOR KEY SHARE`, *asset, task).Scan(&matches)
		if errors.Is(err, sql.ErrNoRows) || err == nil && !matches {
			return ErrInventoryReference
		}
		if err != nil {
			return err
		}
	}
	return nil
}
func (d *DB) ObserveSession(ctx context.Context, input SessionObservation) (InventorySession, bool, bool, error) {
	var empty InventorySession
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return empty, false, false, err
	}
	defer tx.Rollback()
	// Serialize only observations of the same external identity, including its first insert.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, input.Source+"\n"+input.SourceID); err != nil {
		return empty, false, false, err
	}
	if err = validateInventoryReferences(ctx, tx, input.TaskID, input.AssetID); err != nil {
		return empty, false, false, err
	}
	payload, _ := json.Marshal(input)
	sum := sha256.Sum256(payload)
	hash := hex.EncodeToString(sum[:])
	var id, sequence int64
	var previous string
	err = tx.QueryRowContext(ctx, `SELECT id,sequence,content_hash FROM session_inventory WHERE source=$1 AND source_id=$2 FOR UPDATE`, input.Source, input.SourceID).Scan(&id, &sequence, &previous)
	created := errors.Is(err, sql.ErrNoRows)
	if err != nil && !created {
		return empty, false, false, err
	}
	if !created && input.Sequence <= sequence {
		if input.Sequence != sequence || hash != previous {
			return empty, false, false, ErrInventoryConflict
		}
		s, err := scanInventory(tx.QueryRowContext(ctx, `SELECT `+inventoryColumns+` FROM session_inventory WHERE id=$1`, id))
		return s, false, true, err
	}
	heartbeat := time.Now().UTC()
	if input.HeartbeatAt != nil {
		heartbeat = *input.HeartbeatAt
	}
	s, err := scanInventory(tx.QueryRowContext(ctx, `INSERT INTO session_inventory
 (source,source_id,sequence,content_hash,kind,protocol_label,state,host,url,task_id,asset_id,heartbeat_at,heartbeat_ttl_seconds,disconnect_reason)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
 ON CONFLICT(source,source_id) DO UPDATE SET sequence=EXCLUDED.sequence,content_hash=EXCLUDED.content_hash,kind=EXCLUDED.kind,protocol_label=EXCLUDED.protocol_label,state=EXCLUDED.state,host=EXCLUDED.host,url=EXCLUDED.url,task_id=EXCLUDED.task_id,asset_id=EXCLUDED.asset_id,heartbeat_at=EXCLUDED.heartbeat_at,heartbeat_ttl_seconds=EXCLUDED.heartbeat_ttl_seconds,disconnect_reason=EXCLUDED.disconnect_reason,updated_at=now()
 RETURNING `+inventoryColumns, input.Source, input.SourceID, input.Sequence, hash, input.Kind, input.ProtocolLabel, input.State, input.Host, input.URL, input.TaskID, input.AssetID, heartbeat, input.HeartbeatTTLSeconds, input.DisconnectReason))
	if err != nil {
		return empty, false, false, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO session_inventory_audit(session_id,action,sequence,state,detail) VALUES($1,'observation',$2,$3,$4)`, s.ID, s.Sequence, s.State, s.DisconnectReason); err != nil {
		return empty, false, false, err
	}
	return s, created, false, tx.Commit()
}
func (d *DB) GetInventorySession(ctx context.Context, id int64) (InventorySession, []InventoryAudit, error) {
	s, err := scanInventory(d.QueryRowContext(ctx, `SELECT `+inventoryColumns+` FROM session_inventory WHERE id=$1`, id))
	if err != nil {
		return s, nil, err
	}
	rows, err := d.QueryContext(ctx, `SELECT id,action,sequence,state,detail,created_at FROM session_inventory_audit WHERE session_id=$1 ORDER BY id DESC LIMIT 100`, id)
	if err != nil {
		return s, nil, err
	}
	defer rows.Close()
	audit := []InventoryAudit{}
	for rows.Next() {
		var a InventoryAudit
		if err = rows.Scan(&a.ID, &a.Action, &a.Sequence, &a.State, &a.Detail, &a.CreatedAt); err != nil {
			return s, nil, err
		}
		audit = append(audit, a)
	}
	return s, audit, rows.Err()
}

type InventoryFilter struct {
	Source, Kind, State, Query string
	TaskID                     *int64
	Page, Limit                int
}

func (d *DB) ListInventorySessions(ctx context.Context, f InventoryFilter) ([]InventorySession, int, error) {
	where := ` WHERE ($1='' OR source=$1) AND ($2='' OR kind=$2) AND ($3::bigint IS NULL OR task_id=$3) AND ($4='' OR effective_state=$4) AND ($5='' OR source ILIKE $6 OR source_id ILIKE $6 OR host ILIKE $6 OR annotation ILIKE $6)`
	base := ` FROM (SELECT *,CASE WHEN state='connected' AND heartbeat_at+heartbeat_ttl_seconds*interval '1 second'<now() THEN 'stale' ELSE state END AS effective_state FROM session_inventory) inventory`
	pattern := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(f.Query) + "%"
	args := []any{f.Source, f.Kind, f.TaskID, f.State, f.Query, pattern}
	total := 0
	if err := d.QueryRowContext(ctx, `SELECT count(*)`+base+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.Limit, (f.Page-1)*f.Limit)
	rows, err := d.QueryContext(ctx, `SELECT `+inventoryColumns+base+where+` ORDER BY updated_at DESC,id DESC LIMIT $7 OFFSET $8`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := []InventorySession{}
	for rows.Next() {
		s, err := scanInventory(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, s)
	}
	return items, total, rows.Err()
}
func (d *DB) AnnotateInventorySession(ctx context.Context, id int64, action, detail string) (InventorySession, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return InventorySession{}, err
	}
	defer tx.Rollback()
	statement := `UPDATE session_inventory SET annotation=$2,updated_at=now() WHERE id=$1 RETURNING ` + inventoryColumns
	if action == "disconnect" {
		statement = `UPDATE session_inventory SET state='disconnected',disconnect_reason=$2,updated_at=now() WHERE id=$1 RETURNING ` + inventoryColumns
	}
	s, err := scanInventory(tx.QueryRowContext(ctx, statement, id, detail))
	if err != nil {
		return s, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO session_inventory_audit(session_id,action,sequence,state,detail) VALUES($1,$2,$3,$4,$5)`, id, action, s.Sequence, s.State, detail)
	if err != nil {
		return s, err
	}
	return s, tx.Commit()
}
