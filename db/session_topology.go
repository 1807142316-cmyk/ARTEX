package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

type InventoryNode struct {
	ID          int64     `json:"id"`
	Ref         string    `json:"ref"`
	Kind        string    `json:"kind"`
	ExternalRef string    `json:"external_ref"`
	Label       string    `json:"label"`
	Address     string    `json:"address"`
	State       string    `json:"state"`
	TaskID      *int64    `json:"task_id,omitempty"`
	AssetID     *int64    `json:"asset_id,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (d *DB) SaveInventoryNode(ctx context.Context, n InventoryNode) (InventoryNode, bool, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return n, false, err
	}
	defer tx.Rollback()
	if err = validateInventoryReferences(ctx, tx, n.TaskID, n.AssetID); err != nil {
		return n, false, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,1))`, n.ExternalRef); err != nil {
		return n, false, err
	}
	var existingID int64
	var previousKind string
	err = tx.QueryRowContext(ctx, `SELECT id,kind FROM session_inventory_nodes WHERE external_ref=$1 FOR UPDATE`, n.ExternalRef).Scan(&existingID, &previousKind)
	created := errors.Is(err, sql.ErrNoRows)
	if err != nil && !created {
		return n, false, err
	}
	if !created && n.Kind != previousKind {
		return n, false, ErrInventoryConflict
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO session_inventory_nodes(kind,external_ref,label,address,state,task_id,asset_id) VALUES($1,$2,$3,$4,$5,$6,$7)
 ON CONFLICT(external_ref) DO UPDATE SET kind=EXCLUDED.kind,label=EXCLUDED.label,address=EXCLUDED.address,state=EXCLUDED.state,task_id=EXCLUDED.task_id,asset_id=EXCLUDED.asset_id,updated_at=now()
 RETURNING id,updated_at`, n.Kind, n.ExternalRef, n.Label, n.Address, n.State, n.TaskID, n.AssetID).Scan(&n.ID, &n.UpdatedAt)
	if err != nil {
		return n, false, err
	}
	n.Ref = "node:" + strconv.FormatInt(n.ID, 10)
	if _, err = tx.ExecContext(ctx, `INSERT INTO session_inventory_node_audit(node_id,state,label) VALUES($1,$2,$3)`, n.ID, n.State, n.Label); err != nil {
		return n, false, err
	}
	return n, created, tx.Commit()
}

type InventoryEdge struct {
	ID             int64     `json:"id"`
	SourceRef      string    `json:"source_ref"`
	TargetRef      string    `json:"target_ref"`
	Relation       string    `json:"relation"`
	State          string    `json:"state"`
	EffectiveState string    `json:"effective_state"`
	Note           string    `json:"note"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func inventoryEndpointKind(ctx context.Context, tx *sql.Tx, ref string) (string, *int64, error) {
	prefix, raw, ok := strings.Cut(ref, ":")
	id, err := strconv.ParseInt(raw, 10, 64)
	if !ok || err != nil || id < 1 {
		return "", nil, ErrInventoryReference
	}
	var kind string
	var task *int64
	switch prefix {
	case "session":
		err = tx.QueryRowContext(ctx, `SELECT 'session',task_id FROM session_inventory WHERE id=$1 FOR KEY SHARE`, id).Scan(&kind, &task)
	case "node":
		err = tx.QueryRowContext(ctx, `SELECT kind,task_id FROM session_inventory_nodes WHERE id=$1 FOR KEY SHARE`, id).Scan(&kind, &task)
	default:
		return "", nil, ErrInventoryReference
	}
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, ErrInventoryReference
	}
	return kind, task, err
}
func (d *DB) SaveInventoryEdge(ctx context.Context, e InventoryEdge) (InventoryEdge, bool, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return e, false, err
	}
	defer tx.Rollback()
	source, sourceTask, err := inventoryEndpointKind(ctx, tx, e.SourceRef)
	if err != nil {
		return e, false, err
	}
	target, targetTask, err := inventoryEndpointKind(ctx, tx, e.TargetRef)
	if err != nil {
		return e, false, err
	}
	if sourceTask != nil && targetTask != nil && *sourceTask != *targetTask {
		return e, false, ErrInventoryReference
	}
	allowed := e.Relation == "hosted_on" && source == "session" && target == "host" || e.Relation == "member_of" && source == "host" && target == "subnet" || e.Relation == "tunnel_metadata" && source == "session" && target == "tunnel" || e.Relation == "credential_reference" && source == "session" && target == "credential_ref"
	if !allowed {
		return e, false, ErrInventoryReference
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,2))`, e.SourceRef+"\n"+e.TargetRef+"\n"+e.Relation); err != nil {
		return e, false, err
	}
	var existing int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM session_inventory_edges WHERE source_ref=$1 AND target_ref=$2 AND relation=$3 FOR UPDATE`, e.SourceRef, e.TargetRef, e.Relation).Scan(&existing)
	created := errors.Is(err, sql.ErrNoRows)
	if err != nil && !created {
		return e, false, err
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO session_inventory_edges(source_ref,target_ref,relation,state,note)VALUES($1,$2,$3,$4,$5)
 ON CONFLICT(source_ref,target_ref,relation)DO UPDATE SET state=EXCLUDED.state,note=EXCLUDED.note,updated_at=now() RETURNING id,updated_at`, e.SourceRef, e.TargetRef, e.Relation, e.State, e.Note).Scan(&e.ID, &e.UpdatedAt)
	if err != nil {
		return e, false, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO session_inventory_edge_audit(edge_id,state,note)VALUES($1,$2,$3)`, e.ID, e.State, e.Note); err != nil {
		return e, false, err
	}
	return e, created, tx.Commit()
}
func (d *DB) InventoryNodeDetail(ctx context.Context, id int64) (InventoryNode, []map[string]any, error) {
	var n InventoryNode
	err := d.QueryRowContext(ctx, `SELECT id,kind,external_ref,label,address,state,task_id,asset_id,updated_at FROM session_inventory_nodes WHERE id=$1`, id).Scan(&n.ID, &n.Kind, &n.ExternalRef, &n.Label, &n.Address, &n.State, &n.TaskID, &n.AssetID, &n.UpdatedAt)
	if err != nil {
		return n, nil, err
	}
	n.Ref = "node:" + strconv.FormatInt(id, 10)
	rows, err := d.QueryContext(ctx, `SELECT jsonb_build_object('id',id,'state',state,'label',label,'created_at',created_at) FROM session_inventory_node_audit WHERE node_id=$1 ORDER BY id DESC LIMIT 100`, id)
	if err != nil {
		return n, nil, err
	}
	defer rows.Close()
	audit := []map[string]any{}
	for rows.Next() {
		var raw []byte
		var a map[string]any
		if err = rows.Scan(&raw); err != nil {
			return n, nil, err
		}
		if err = json.Unmarshal(raw, &a); err != nil {
			return n, nil, err
		}
		audit = append(audit, a)
	}
	return n, audit, rows.Err()
}

func (d *DB) InventoryEdgeAudit(ctx context.Context, id int64) ([]map[string]any, error) {
	var exists bool
	if err := d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM session_inventory_edges WHERE id=$1)`, id).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, sql.ErrNoRows
	}
	rows, err := d.QueryContext(ctx, `SELECT jsonb_build_object('id',id,'state',state,'note',note,'created_at',created_at) FROM session_inventory_edge_audit WHERE edge_id=$1 ORDER BY id DESC LIMIT 100`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var raw []byte
		var item map[string]any
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

type InventoryTopology struct {
	Nodes     []map[string]any `json:"nodes"`
	Edges     []InventoryEdge  `json:"edges"`
	Truncated bool             `json:"truncated"`
	Mode      string           `json:"mode"`
}

func (d *DB) InventoryTopology(ctx context.Context, q string, task *int64) (InventoryTopology, error) {
	graph := InventoryTopology{Nodes: []map[string]any{}, Edges: []InventoryEdge{}, Mode: "observer"}
	tx, err := d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return graph, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT jsonb_build_object('ref','node:'||id,'id',id,'kind',kind,'external_ref',external_ref,'label',label,'address',address,'state',state,'effective_state',state,'task_id',task_id,'asset_id',asset_id)
 FROM session_inventory_nodes WHERE ($1='' OR external_ref ILIKE $2 OR label ILIKE $2) AND ($3::bigint IS NULL OR task_id=$3) ORDER BY id LIMIT 501`, q, "%"+q+"%", task)
	if err != nil {
		return graph, err
	}
	active := map[string]bool{}
	owners := map[string]*int64{}
	for rows.Next() {
		var raw []byte
		var n map[string]any
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return graph, err
		}
		if err = json.Unmarshal(raw, &n); err != nil {
			rows.Close()
			return graph, err
		}
		graph.Nodes = append(graph.Nodes, n)
		active[n["ref"].(string)] = n["state"] == "active"
		if raw, ok := n["task_id"].(float64); ok {
			id := int64(raw)
			owners[n["ref"].(string)] = &id
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return graph, err
	}
	rows.Close()
	rows, err = tx.QueryContext(ctx, `SELECT `+inventoryColumns+` FROM session_inventory WHERE ($1='' OR source ILIKE $2 OR source_id ILIKE $2 OR host ILIKE $2) AND ($3::bigint IS NULL OR task_id=$3) ORDER BY id LIMIT 501`, q, "%"+q+"%", task)
	if err != nil {
		return graph, err
	}
	for rows.Next() {
		s, err := scanInventory(rows)
		if err != nil {
			rows.Close()
			return graph, err
		}
		ref := "session:" + strconv.FormatInt(s.ID, 10)
		n := map[string]any{"ref": ref, "id": s.ID, "kind": "session", "label": s.Source + " / " + s.SourceID, "state": s.State, "effective_state": s.EffectiveState, "task_id": s.TaskID, "asset_id": s.AssetID}
		graph.Nodes = append(graph.Nodes, n)
		active[ref] = s.EffectiveState == "connected"
		owners[ref] = s.TaskID
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return graph, err
	}
	rows.Close()
	if len(graph.Nodes) > 500 {
		graph.Truncated = true
		graph.Nodes = graph.Nodes[:500]
		active = map[string]bool{}
		for _, n := range graph.Nodes {
			state := n["effective_state"]
			active[n["ref"].(string)] = state == "active" || state == "connected"
		}
	}
	refs := make([]string, 0, len(active))
	for ref := range active {
		refs = append(refs, ref)
	}
	rows, err = tx.QueryContext(ctx, `SELECT id,source_ref,target_ref,relation,state,note,updated_at FROM session_inventory_edges WHERE source_ref=ANY($1::text[]) AND target_ref=ANY($1::text[]) ORDER BY id LIMIT 1001`, refs)
	if err != nil {
		return graph, err
	}
	defer rows.Close()
	for rows.Next() {
		var e InventoryEdge
		if err = rows.Scan(&e.ID, &e.SourceRef, &e.TargetRef, &e.Relation, &e.State, &e.Note, &e.UpdatedAt); err != nil {
			return graph, err
		}
		e.EffectiveState = e.State
		sourceOwner, targetOwner := owners[e.SourceRef], owners[e.TargetRef]
		if !active[e.SourceRef] || !active[e.TargetRef] || sourceOwner != nil && targetOwner != nil && *sourceOwner != *targetOwner {
			e.EffectiveState = "inactive"
		}
		graph.Edges = append(graph.Edges, e)
	}
	if len(graph.Edges) > 1000 {
		graph.Truncated = true
		graph.Edges = graph.Edges[:1000]
	}
	if err = rows.Err(); err != nil {
		return graph, err
	}
	return graph, tx.Commit()
}
