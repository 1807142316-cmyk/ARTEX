package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type CVESyncAsset struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256,omitempty"`
}

type CVESyncRun struct {
	ID            int64          `json:"run_id"`
	Status        string         `json:"status"`
	SourceVersion string         `json:"source_version"`
	BaselineName  string         `json:"baseline_name"`
	Assets        []CVESyncAsset `json:"assets"`
	Checkpoint    int            `json:"checkpoint"`
	Added         int            `json:"added"`
	Modified      int            `json:"modified"`
	Failed        int            `json:"failed"`
	LastError     string         `json:"last_error"`
	CreatedAt     time.Time      `json:"created_at"`
	FinishedAt    *time.Time     `json:"finished_at"`
}

type CVESyncStatus struct {
	Enabled         bool        `json:"enabled"`
	IntervalMinutes int         `json:"interval_minutes"`
	NextCheck       time.Time   `json:"next_check"`
	LastCheck       *time.Time  `json:"last_check"`
	LastSuccess     *time.Time  `json:"last_success"`
	SourceVersion   string      `json:"source_version"`
	BaselineName    string      `json:"baseline_name"`
	Status          string      `json:"status"`
	Added           int         `json:"added"`
	Modified        int         `json:"modified"`
	Failed          int         `json:"failed"`
	LastError       string      `json:"last_error"`
	Run             *CVESyncRun `json:"run"`
}

func (d *DB) CVESyncStatus(ctx context.Context) (CVESyncStatus, error) {
	var s CVESyncStatus
	// The committed cursor and latest run must describe the same database
	// snapshot when a finish transaction commits between these reads.
	tx, err := d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return s, err
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx, `SELECT enabled,interval_minutes,next_check,last_check,last_success,source_version,baseline_name FROM cve_sync_state WHERE id=true`).Scan(&s.Enabled, &s.IntervalMinutes, &s.NextCheck, &s.LastCheck, &s.LastSuccess, &s.SourceVersion, &s.BaselineName)
	if err != nil {
		return s, err
	}
	r, err := scanCVESyncRun(tx.QueryRowContext(ctx, `SELECT id,status,source_version,baseline_name,assets,checkpoint,added,modified,failed,last_error,created_at,finished_at FROM cve_sync_runs ORDER BY id DESC LIMIT 1`))
	if errors.Is(err, sql.ErrNoRows) {
		s.Status = "idle"
		return s, tx.Commit()
	}
	if err != nil {
		return s, err
	}
	s.Run = &r
	s.Status = r.Status
	s.Added = r.Added
	s.Modified = r.Modified
	s.Failed = r.Failed
	s.LastError = r.LastError
	return s, tx.Commit()
}
func scanCVESyncRun(row interface{ Scan(...any) error }) (CVESyncRun, error) {
	var r CVESyncRun
	var assets []byte
	err := row.Scan(&r.ID, &r.Status, &r.SourceVersion, &r.BaselineName, &assets, &r.Checkpoint, &r.Added, &r.Modified, &r.Failed, &r.LastError, &r.CreatedAt, &r.FinishedAt)
	if err == nil {
		err = json.Unmarshal(assets, &r.Assets)
	}
	return r, err
}
func (d *DB) SetCVESyncSettings(ctx context.Context, enabled bool, minutes int) error {
	_, err := d.ExecContext(ctx, `UPDATE cve_sync_state SET enabled=$1,interval_minutes=$2,next_check=now()+make_interval(mins=>$2) WHERE id=true`, enabled, minutes)
	return err
}
func (d *DB) QueueCVESync(ctx context.Context, scheduled bool) (int64, error) {
	var id int64
	err := d.QueryRowContext(ctx, `INSERT INTO cve_sync_runs(status) SELECT 'queued' WHERE NOT $1 OR EXISTS(SELECT 1 FROM cve_sync_state WHERE enabled AND next_check<=now()) ON CONFLICT DO NOTHING RETURNING id`, scheduled).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return id, err
}
func (d *DB) ActiveCVESync(ctx context.Context) (CVESyncRun, error) {
	return scanCVESyncRun(d.QueryRowContext(ctx, `SELECT id,status,source_version,baseline_name,assets,checkpoint,added,modified,failed,last_error,created_at,finished_at FROM cve_sync_runs WHERE status IN ('queued','running') ORDER BY id LIMIT 1`))
}
func (d *DB) PrepareCVESync(ctx context.Context, r CVESyncRun) error {
	assets, err := json.Marshal(r.Assets)
	if err != nil {
		return err
	}
	_, err = d.ExecContext(ctx, `UPDATE cve_sync_runs SET status='running',source_version=$2,baseline_name=$3,assets=$4::jsonb,last_error='' WHERE id=$1`, r.ID, r.SourceVersion, r.BaselineName, string(assets))
	if err != nil {
		return err
	}
	_, err = d.ExecContext(ctx, `UPDATE cve_sync_state SET last_check=now() WHERE id=true`)
	return err
}
func (d *DB) FinishCVESync(ctx context.Context, id int64, runErr error) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if runErr != nil {
		_, err = tx.ExecContext(ctx, `UPDATE cve_sync_runs SET status='failed',failed=failed+1,last_error=$2,finished_at=now() WHERE id=$1`, id, runErr.Error())
		if err == nil {
			_, err = tx.ExecContext(ctx, `UPDATE cve_sync_state SET last_check=now(),next_check=now()+make_interval(mins=>LEAST(interval_minutes,15)) WHERE id=true`)
		}
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE cve_sync_runs SET status='succeeded',finished_at=now() WHERE id=$1`, id)
		if err == nil {
			_, err = tx.ExecContext(ctx, `UPDATE cve_sync_state SET last_check=now(),last_success=now(),source_version=r.source_version,baseline_name=r.baseline_name,next_check=now()+make_interval(mins=>interval_minutes) FROM cve_sync_runs r WHERE cve_sync_state.id=true AND r.id=$1`, id)
		}
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (d *DB) ApplyCVESyncBatch(ctx context.Context, id int64, checkpoint int, records []CVERecord) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := upsertCVERecordsTx(ctx, tx, records)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE cve_sync_runs SET checkpoint=$2,added=added+$3,modified=modified+$4 WHERE id=$1`, id, checkpoint, result.Added, result.Modified)
	if err != nil {
		return err
	}
	return tx.Commit()
}
