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
	ID          int64      `json:"id"`
	Ref         string     `json:"ref"`
	Kind        string     `json:"kind"`
	ExternalRef string     `json:"external_ref"`
	Label       string     `json:"label"`
	Address     string     `json:"address"`
	State       string     `json:"state"`
	TaskID      *int64     `json:"task_id,omitempty"`
	AssetID     *int64     `json:"asset_id,omitempty"`
	Scope       string     `json:"scope,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	UpdatedAt   time.Time  `json:"updated_at"`
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
	err = tx.QueryRowContext(ctx, `INSERT INTO session_inventory_nodes(kind,external_ref,label,address,state,task_id,asset_id,expires_at,scope) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
 ON CONFLICT(external_ref) DO UPDATE SET kind=EXCLUDED.kind,label=EXCLUDED.label,address=EXCLUDED.address,state=EXCLUDED.state,task_id=EXCLUDED.task_id,asset_id=EXCLUDED.asset_id,expires_at=EXCLUDED.expires_at,scope=EXCLUDED.scope,updated_at=now()
 RETURNING id,updated_at`, n.Kind, n.ExternalRef, n.Label, n.Address, n.State, n.TaskID, n.AssetID, n.ExpiresAt, n.Scope).Scan(&n.ID, &n.UpdatedAt)
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
	ID             int64  `json:"id"`
	SourceRef      string `json:"source_ref"`
	TargetRef      string `json:"target_ref"`
	Relation       string `json:"relation"`
	State          string `json:"state"`
	EffectiveState string `json:"effective_state"`
	// Reason explains a derived inactive state ("session_stale",
	// "credential_expired", ...). Empty when the edge is active or when an
	// operator deactivated it explicitly.
	Reason    string    `json:"reason"`
	Note      string    `json:"note"`
	UpdatedAt time.Time `json:"updated_at"`
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
	err := d.QueryRowContext(ctx, `SELECT id,kind,external_ref,label,address,state,task_id,asset_id,expires_at,scope,updated_at FROM session_inventory_nodes WHERE id=$1`, id).Scan(&n.ID, &n.Kind, &n.ExternalRef, &n.Label, &n.Address, &n.State, &n.TaskID, &n.AssetID, &n.ExpiresAt, &n.Scope, &n.UpdatedAt)
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

type InventoryTopologyNode struct {
	Ref            string     `json:"ref"`
	ID             int64      `json:"id"`
	Kind           string     `json:"kind"`
	ExternalRef    *string    `json:"external_ref,omitempty"`
	Label          string     `json:"label"`
	Address        *string    `json:"address,omitempty"`
	State          string     `json:"state"`
	EffectiveState string     `json:"effective_state"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	TaskID         *int64     `json:"task_id"`
	AssetID        *int64     `json:"asset_id"`
}

// InventoryTopologySummary counts the task-scoped graph by node kind plus the
// active/inactive edge split. Counts are computed before the response is
// truncated so a capped graph still reports the true shape of the task.
type InventoryTopologySummary struct {
	Hosts       int `json:"hosts"`
	Subnets     int `json:"subnets"`
	Sessions    int `json:"sessions"`
	Tunnels     int `json:"tunnels"`
	Credentials int `json:"credentials"`
	ActiveEdges int `json:"active_edges"`
	Inactive    int `json:"inactive_edges"`
}

// InventoryTopologyEmpty marks which collections hold nothing at all, so the UI
// can tell "this task has no hosts" apart from "the filter matched nothing".
// true means the collection is empty.
type InventoryTopologyEmpty struct {
	Nodes       bool `json:"nodes"`
	Edges       bool `json:"edges"`
	Sessions    bool `json:"sessions"`
	Tunnels     bool `json:"tunnels"`
	Credentials bool `json:"credentials"`
}

type InventoryTopology struct {
	Nodes     []InventoryTopologyNode  `json:"nodes"`
	Edges     []InventoryEdge          `json:"edges"`
	Truncated bool                     `json:"truncated"`
	Mode      string                   `json:"mode"`
	Summary   InventoryTopologySummary `json:"summary"`
	Empty     InventoryTopologyEmpty   `json:"empty"`
}

// inventoryCredentialExpired reports whether a credential_ref node has passed
// its explicit expiry. Expiry is evaluated at read time so a writer that forgets
// to flip the stored state cannot leave a dead credential looking usable.
func inventoryCredentialExpired(kind, state string, expiresAt *time.Time) bool {
	if kind != "credential_ref" || expiresAt == nil {
		return false
	}
	return !expiresAt.After(time.Now())
}

// inventoryEffectiveNodeState folds stored state and credential expiry into the
// state the API reports and the intranet resolver consumes.
func inventoryEffectiveNodeState(kind, state string, expiresAt *time.Time) string {
	if inventoryCredentialExpired(kind, state, expiresAt) {
		return "expired"
	}
	return state
}

// topoEndpoint is the resolved view of one side of an edge, used to explain why
// the edge is inactive. exists=false means the ref was not part of this graph.
type topoEndpoint struct {
	kind      string
	effective string
	task      *int64
	exists    bool
}

// inventoryEdgeReason returns the machine-readable reason an edge is inactive,
// or "" when the edge is active or was explicitly deactivated by an operator.
// Precedence is fixed, so the same graph always yields the same reason:
//
//  1. an operator's explicit inactive state is not a derived condition;
//  2. a dangling endpoint (the node or session row is gone) is node_invalid;
//  3. an ownership violation — task_mismatch — outranks endpoint state, because
//     no amount of health makes a cross-task relationship legal;
//  4. otherwise the first unhealthy endpoint in graph order (source, then target).
func inventoryEdgeReason(e InventoryEdge, source, target topoEndpoint) string {
	if e.State == "inactive" {
		return ""
	}
	if !source.exists || !target.exists {
		return "node_invalid"
	}
	if source.task != nil && target.task != nil && *source.task != *target.task {
		return "task_mismatch"
	}
	for _, endpoint := range []topoEndpoint{source, target} {
		if reason := inventoryEndpointReason(endpoint); reason != "" {
			return reason
		}
	}
	return ""
}

// inventoryGraphEndpoint resolves one edge side: from the filtered graph when
// present, otherwise from storage so an endpoint that drifted out of the filter
// (reassigned task, renamed owner) still explains the edge. Unknown refs resolve
// to exists=false and the edge is dropped by the caller.
func inventoryGraphEndpoint(ctx context.Context, tx *sql.Tx, graph map[string]topoEndpoint, ref string) (topoEndpoint, error) {
	if endpoint, ok := graph[ref]; ok {
		return endpoint, nil
	}
	prefix, raw, ok := strings.Cut(ref, ":")
	id, convErr := strconv.ParseInt(raw, 10, 64)
	if !ok || convErr != nil || id < 1 {
		return topoEndpoint{}, nil
	}
	switch prefix {
	case "session":
		s, err := scanInventory(tx.QueryRowContext(ctx, `SELECT `+inventoryColumns+` FROM session_inventory WHERE id=$1`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return topoEndpoint{}, nil
		}
		if err != nil {
			return topoEndpoint{}, err
		}
		return topoEndpoint{kind: "session", effective: s.EffectiveState, task: s.TaskID, exists: true}, nil
	case "node":
		var kind, state string
		var task *int64
		var expiresAt *time.Time
		err := tx.QueryRowContext(ctx, `SELECT kind,state,task_id,expires_at FROM session_inventory_nodes WHERE id=$1`, id).Scan(&kind, &state, &task, &expiresAt)
		if errors.Is(err, sql.ErrNoRows) {
			return topoEndpoint{}, nil
		}
		if err != nil {
			return topoEndpoint{}, err
		}
		return topoEndpoint{kind: kind, effective: inventoryEffectiveNodeState(kind, state, expiresAt), task: task, exists: true}, nil
	}
	return topoEndpoint{}, nil
}

func inventoryEndpointReason(endpoint topoEndpoint) string {
	switch endpoint.kind {
	case "session":
		switch endpoint.effective {
		case "connected":
			return ""
		case "stale":
			return "session_stale"
		default: // disconnected or unknown: the session is not carrying traffic
			return "session_disconnected"
		}
	case "credential_ref":
		if endpoint.effective == "expired" {
			return "credential_expired"
		}
		if endpoint.effective != "active" {
			return "node_invalid"
		}
		return ""
	case "tunnel":
		if endpoint.effective != "active" {
			return "tunnel_inactive"
		}
		return ""
	default: // host / subnet
		if endpoint.effective != "active" {
			return "node_invalid"
		}
		return ""
	}
}

// InventoryTopology returns the task-scoped node/edge graph with derived edge
// reasons, task-filtered summary counts and explicit empty-state flags.
func (d *DB) InventoryTopology(ctx context.Context, q string, task *int64) (InventoryTopology, error) {
	graph := InventoryTopology{Nodes: []InventoryTopologyNode{}, Edges: []InventoryEdge{}, Mode: "observer"}
	tx, err := d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return graph, err
	}
	defer tx.Rollback()
	pattern := "%" + q + "%"
	rows, err := tx.QueryContext(ctx, `SELECT id,kind,external_ref,label,address,state,task_id,asset_id,expires_at
 FROM session_inventory_nodes WHERE ($1='' OR external_ref ILIKE $2 OR label ILIKE $2) AND ($3::bigint IS NULL OR task_id=$3) ORDER BY id LIMIT 501`, q, pattern, task)
	if err != nil {
		return graph, err
	}
	endpoints := map[string]topoEndpoint{}
	var summary InventoryTopologySummary
	for rows.Next() {
		var n InventoryTopologyNode
		if err = rows.Scan(&n.ID, &n.Kind, &n.ExternalRef, &n.Label, &n.Address, &n.State, &n.TaskID, &n.AssetID, &n.ExpiresAt); err != nil {
			rows.Close()
			return graph, err
		}
		n.Ref = "node:" + strconv.FormatInt(n.ID, 10)
		n.EffectiveState = inventoryEffectiveNodeState(n.Kind, n.State, n.ExpiresAt)
		switch n.Kind {
		case "host":
			summary.Hosts++
		case "subnet":
			summary.Subnets++
		case "tunnel":
			summary.Tunnels++
		case "credential_ref":
			summary.Credentials++
		}
		graph.Nodes = append(graph.Nodes, n)
		endpoints[n.Ref] = topoEndpoint{kind: n.Kind, effective: n.EffectiveState, task: n.TaskID, exists: true}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return graph, err
	}
	rows.Close()
	rows, err = tx.QueryContext(ctx, `SELECT `+inventoryColumns+` FROM session_inventory WHERE ($1='' OR source ILIKE $2 OR source_id ILIKE $2 OR host ILIKE $2) AND ($3::bigint IS NULL OR task_id=$3) ORDER BY id LIMIT 501`, q, pattern, task)
	if err != nil {
		return graph, err
	}
	for rows.Next() {
		s, scanErr := scanInventory(rows)
		if scanErr != nil {
			rows.Close()
			return graph, scanErr
		}
		ref := "session:" + strconv.FormatInt(s.ID, 10)
		graph.Nodes = append(graph.Nodes, InventoryTopologyNode{Ref: ref, ID: s.ID, Kind: "session", Label: s.Source + " / " + s.SourceID, State: s.State, EffectiveState: s.EffectiveState, TaskID: s.TaskID, AssetID: s.AssetID})
		summary.Sessions++
		endpoints[ref] = topoEndpoint{kind: "session", effective: s.EffectiveState, task: s.TaskID, exists: true}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return graph, err
	}
	rows.Close()
	if len(graph.Nodes) > 500 {
		graph.Truncated = true
		graph.Nodes = graph.Nodes[:500]
	}
	refs := make([]string, 0, len(endpoints))
	for ref := range endpoints {
		refs = append(refs, ref)
	}
	// Edges attach when EITHER endpoint is in the filtered graph. The other side
	// is resolved separately: without that, a node reassigned to another task
	// would silently drop its relationship instead of surfacing task_mismatch.
	rows, err = tx.QueryContext(ctx, `SELECT id,source_ref,target_ref,relation,state,note,updated_at FROM session_inventory_edges WHERE source_ref=ANY($1::text[]) OR target_ref=ANY($1::text[]) ORDER BY id LIMIT 1001`, refs)
	if err != nil {
		return graph, err
	}
	// Materialize before resolving off-graph endpoints: the transaction holds a
	// single connection, so a lookup cannot run while the edge rows are still open.
	stored := make([]InventoryEdge, 0, 32)
	for rows.Next() {
		var e InventoryEdge
		if err = rows.Scan(&e.ID, &e.SourceRef, &e.TargetRef, &e.Relation, &e.State, &e.Note, &e.UpdatedAt); err != nil {
			rows.Close()
			return graph, err
		}
		stored = append(stored, e)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return graph, err
	}
	rows.Close()
	for _, e := range stored {
		source, sourceErr := inventoryGraphEndpoint(ctx, tx, endpoints, e.SourceRef)
		if sourceErr != nil {
			return graph, sourceErr
		}
		target, targetErr := inventoryGraphEndpoint(ctx, tx, endpoints, e.TargetRef)
		if targetErr != nil {
			return graph, targetErr
		}
		e.Reason = inventoryEdgeReason(e, source, target)
		if e.State == "inactive" || e.Reason != "" {
			e.EffectiveState = "inactive"
			summary.Inactive++
		} else {
			e.EffectiveState = "active"
			summary.ActiveEdges++
		}
		graph.Edges = append(graph.Edges, e)
	}
	if len(graph.Edges) > 1000 {
		graph.Truncated = true
		graph.Edges = graph.Edges[:1000]
	}
	graph.Summary = summary
	graph.Empty = InventoryTopologyEmpty{
		Nodes:       len(graph.Nodes) == 0,
		Edges:       len(graph.Edges) == 0,
		Sessions:    summary.Sessions == 0,
		Tunnels:     summary.Tunnels == 0,
		Credentials: summary.Credentials == 0,
	}
	return graph, tx.Commit()
}
