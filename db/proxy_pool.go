package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type ProxyEndpoint struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	Address   string     `json:"url"`
	SealedURL string     `json:"-"`
	Enabled   bool       `json:"enabled"`
	CheckURL  string     `json:"check_url"`
	Health    string     `json:"health"`
	ExitIP    string     `json:"exit_ip"`
	LastError string     `json:"last_error"`
	CheckedAt *time.Time `json:"checked_at"`
}
type TaskEgress struct {
	TaskID    int64     `json:"task_id"`
	ProxyID   *int64    `json:"proxy_id"`
	Policy    string    `json:"policy"`
	State     string    `json:"state"`
	ExitIP    string    `json:"exit_ip"`
	UpdatedAt time.Time `json:"updated_at"`
	ProxyURL  string    `json:"proxy_url,omitempty"`
}
type EgressEvent struct {
	ID        int64     `json:"id"`
	Kind      string    `json:"kind"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

const proxyColumns = `id,name,address,sealed_url,enabled,check_url,health,exit_ip,last_error,checked_at`

func scanProxy(row interface{ Scan(...any) error }) (*ProxyEndpoint, error) {
	p := new(ProxyEndpoint)
	err := row.Scan(&p.ID, &p.Name, &p.Address, &p.SealedURL, &p.Enabled, &p.CheckURL, &p.Health, &p.ExitIP, &p.LastError, &p.CheckedAt)
	return p, err
}
func (d *DB) ProxyEndpoints(ctx context.Context) ([]*ProxyEndpoint, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+proxyColumns+` FROM proxy_endpoints ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ProxyEndpoint{}
	for rows.Next() {
		p, e := scanProxy(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (d *DB) ProxyEndpoint(ctx context.Context, id int64) (*ProxyEndpoint, error) {
	p, e := scanProxy(d.QueryRowContext(ctx, `SELECT `+proxyColumns+` FROM proxy_endpoints WHERE id=$1`, id))
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	return p, e
}
func (d *DB) SaveProxyEndpoint(ctx context.Context, p *ProxyEndpoint) error {
	if p.ID == 0 {
		return d.QueryRowContext(ctx, `INSERT INTO proxy_endpoints(name,address,sealed_url,enabled,check_url) VALUES($1,$2,$3,$4,$5) RETURNING id,health,exit_ip,last_error,checked_at`, p.Name, p.Address, p.SealedURL, p.Enabled, p.CheckURL).Scan(&p.ID, &p.Health, &p.ExitIP, &p.LastError, &p.CheckedAt)
	}
	result, e := d.ExecContext(ctx, `UPDATE proxy_endpoints SET name=$1,address=$2,sealed_url=$3,enabled=$4,check_url=$5,health='unchecked',exit_ip='',checked_at=NULL,last_error='' WHERE id=$6 AND NOT EXISTS(SELECT 1 FROM task_egress_leases l JOIN tasks t ON t.id=l.task_id WHERE l.proxy_id=$6 AND l.state='active' AND t.deleted_at IS NULL AND t.archived_at IS NULL AND t.status NOT IN ('done','failed','timeout'))`, p.Name, p.Address, p.SealedURL, p.Enabled, p.CheckURL, p.ID)
	if e != nil {
		return e
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return errors.New("proxy is missing or has active task leases")
	}
	return nil
}
func (d *DB) SetProxyHealth(ctx context.Context, id int64, healthy bool, exitIP, message string) error {
	state := "unhealthy"
	if healthy {
		state = "healthy"
	}
	_, e := d.ExecContext(ctx, `UPDATE proxy_endpoints SET health=$2,exit_ip=$3,last_error=$4,checked_at=now() WHERE id=$1`, id, state, exitIP, message)
	return e
}

const egressColumns = `task_id,proxy_id,policy,state,exit_ip,updated_at`

func scanEgress(row interface{ Scan(...any) error }) (*TaskEgress, error) {
	v := new(TaskEgress)
	e := row.Scan(&v.TaskID, &v.ProxyID, &v.Policy, &v.State, &v.ExitIP, &v.UpdatedAt)
	return v, e
}
func (d *DB) TaskEgress(ctx context.Context, id int64) (*TaskEgress, error) {
	v, e := scanEgress(d.QueryRowContext(ctx, `SELECT `+egressColumns+` FROM task_egress_leases WHERE task_id=$1`, id))
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	return v, e
}
func (d *DB) AssignTaskEgress(ctx context.Context, taskID, proxyID int64, policy, kind string) (*TaskEgress, error) {
	tx, e := d.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7337741020)`); e != nil {
		return nil, e
	}
	if kind == "assigned" && proxyID == 0 {
		existing, lookupErr := scanEgress(tx.QueryRowContext(ctx, `SELECT `+egressColumns+` FROM task_egress_leases WHERE task_id=$1`, taskID))
		if lookupErr == nil && existing.State == "active" && existing.Policy == policy {
			return existing, tx.Commit()
		}
		if lookupErr != nil && !errors.Is(lookupErr, sql.ErrNoRows) {
			return nil, lookupErr
		}
	}
	var exists bool
	if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM tasks WHERE id=$1 AND deleted_at IS NULL AND archived_at IS NULL AND status NOT IN ('done','failed','timeout'))`, taskID).Scan(&exists); e != nil {
		return nil, e
	}
	if !exists {
		return nil, sql.ErrNoRows
	}
	var selected int64
	var exit string
	if policy != "direct" || kind != "direct" {
		e = tx.QueryRowContext(ctx, `SELECT p.id,p.exit_ip FROM proxy_endpoints p WHERE p.enabled AND p.health='healthy' AND ($2::bigint=0 OR p.id=$2) AND NOT EXISTS(SELECT 1 FROM task_egress_leases l JOIN tasks t ON t.id=l.task_id WHERE l.proxy_id=p.id AND l.task_id<>$1 AND l.state='active' AND t.deleted_at IS NULL AND t.archived_at IS NULL AND t.status NOT IN ('done','failed','timeout')) ORDER BY p.id LIMIT 1`, taskID, proxyID).Scan(&selected, &exit)
		if e != nil {
			return nil, e
		}
	}
	state := "active"
	var assigned any = selected
	if selected == 0 {
		state = "direct"
		assigned = nil
	}
	v, e := scanEgress(tx.QueryRowContext(ctx, `INSERT INTO task_egress_leases(task_id,proxy_id,policy,state,exit_ip) VALUES($1,$2,$3,$4,$5) ON CONFLICT(task_id) DO UPDATE SET proxy_id=EXCLUDED.proxy_id,policy=EXCLUDED.policy,state=EXCLUDED.state,exit_ip=EXCLUDED.exit_ip,updated_at=now() RETURNING `+egressColumns, taskID, assigned, policy, state, exit))
	if e != nil {
		return nil, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO task_egress_events(task_id,kind,message) VALUES($1,$2,$3)`, taskID, kind, "task egress policy="+policy+", state="+state); e != nil {
		return nil, e
	}
	return v, tx.Commit()
}
func (d *DB) PauseTaskEgress(ctx context.Context, id int64, message string) error {
	tx, e := d.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := tx.ExecContext(ctx, `UPDATE task_egress_leases SET state='paused',updated_at=now() WHERE task_id=$1 AND state<>'paused'`, id)
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n > 0 {
		if _, e = tx.ExecContext(ctx, `INSERT INTO task_egress_events(task_id,kind,message) VALUES($1,'paused',$2)`, id, message); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (d *DB) EgressEvents(ctx context.Context, id int64) ([]EgressEvent, error) {
	rows, e := d.QueryContext(ctx, `SELECT id,kind,message,created_at FROM task_egress_events WHERE task_id=$1 ORDER BY id DESC LIMIT 100`, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []EgressEvent{}
	for rows.Next() {
		var v EgressEvent
		if e = rows.Scan(&v.ID, &v.Kind, &v.Message, &v.CreatedAt); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
