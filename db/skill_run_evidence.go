package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

var ErrSkillRunConflict = errors.New("client_run_id conflicts with existing immutable evidence")
var ErrSkillRunReference = errors.New("reported task reference does not exist")

type SkillRunEvidence struct {
	ID                 int64     `json:"id"`
	ClientRunID        string    `json:"client_run_id"`
	Skill              string    `json:"skill"`
	PackageVersion     string    `json:"package_version"`
	ScriptSHA256       string    `json:"script_sha256"`
	InstructionsSHA256 string    `json:"instructions_sha256"`
	TaskID             *int64    `json:"task_id,omitempty"`
	InputLabel         string    `json:"input_label"`
	InputSHA256        string    `json:"input_sha256"`
	InputKind          string    `json:"input_kind"`
	InputBytes         int64     `json:"input_bytes"`
	StartedAt          time.Time `json:"started_at"`
	FinishedAt         time.Time `json:"finished_at"`
	ExitCode           int       `json:"exit_code"`
	Outcome            string    `json:"outcome"`
	Stdout             string    `json:"stdout,omitempty"`
	Stderr             string    `json:"stderr,omitempty"`
	Truncated          bool      `json:"truncated"`
	Attestation        string    `json:"attestation"`
	ReceivedAt         time.Time `json:"received_at"`
}

func (d *DB) SaveSkillRun(ctx context.Context, evidence SkillRunEvidence, hash string) (SkillRunEvidence, bool, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return evidence, false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,3))`, evidence.ClientRunID); err != nil {
		return evidence, false, err
	}
	var previousHash string
	var previousRaw []byte
	var previousTask *int64
	var previousID int64
	var previousReceived time.Time
	err = tx.QueryRowContext(ctx, `SELECT id,content_hash,evidence,task_id,received_at FROM skill_run_evidence WHERE client_run_id=$1`, evidence.ClientRunID).Scan(&previousID, &previousHash, &previousRaw, &previousTask, &previousReceived)
	if err == nil {
		if previousHash != hash {
			return evidence, false, ErrSkillRunConflict
		}
		if err := json.Unmarshal(previousRaw, &evidence); err != nil {
			return evidence, false, err
		}
		evidence.ID, evidence.TaskID, evidence.ReceivedAt = previousID, previousTask, previousReceived
		return evidence, false, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return evidence, false, err
	}
	if evidence.TaskID != nil {
		var id int64
		if err = tx.QueryRowContext(ctx, `SELECT id FROM tasks WHERE id=$1 FOR KEY SHARE`, *evidence.TaskID).Scan(&id); errors.Is(err, sql.ErrNoRows) {
			return evidence, false, ErrSkillRunReference
		} else if err != nil {
			return evidence, false, err
		}
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		return evidence, false, err
	}
	var id int64
	var received time.Time
	err = tx.QueryRowContext(ctx, `INSERT INTO skill_run_evidence(client_run_id,skill,task_id,outcome,content_hash,evidence) VALUES($1,$2,$3,$4,$5,$6::jsonb) ON CONFLICT(client_run_id) DO NOTHING RETURNING id,received_at`, evidence.ClientRunID, evidence.Skill, evidence.TaskID, evidence.Outcome, hash, raw).Scan(&id, &received)
	created := err == nil
	if errors.Is(err, sql.ErrNoRows) {
		var previous string
		err = tx.QueryRowContext(ctx, `SELECT id,received_at,content_hash FROM skill_run_evidence WHERE client_run_id=$1`, evidence.ClientRunID).Scan(&id, &received, &previous)
		if err == nil && previous != hash {
			return evidence, false, ErrSkillRunConflict
		}
	}
	if err != nil {
		return evidence, false, err
	}
	evidence.ID, evidence.ReceivedAt = id, received
	return evidence, created, tx.Commit()
}
func (d *DB) SkillRun(ctx context.Context, id int64) (SkillRunEvidence, error) {
	var r SkillRunEvidence
	var raw []byte
	var task *int64
	var received time.Time
	err := d.QueryRowContext(ctx, `SELECT evidence,task_id,received_at FROM skill_run_evidence WHERE id=$1`, id).Scan(&raw, &task, &received)
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(raw, &r); err != nil {
		return r, err
	}
	r.ID, r.TaskID, r.ReceivedAt = id, task, received
	return r, nil
}
func (d *DB) SkillRuns(ctx context.Context, skill string, page, limit int) ([]SkillRunEvidence, int, error) {
	count := 0
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM skill_run_evidence WHERE ($1='' OR skill=$1)`, skill).Scan(&count); err != nil {
		return nil, 0, err
	}
	rows, err := d.QueryContext(ctx, `SELECT id,evidence-'stdout'-'stderr',task_id,received_at FROM skill_run_evidence WHERE ($1='' OR skill=$1) ORDER BY id DESC LIMIT $2 OFFSET $3`, skill, limit, (page-1)*limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []SkillRunEvidence{}
	for rows.Next() {
		var r SkillRunEvidence
		var raw []byte
		var id int64
		var task *int64
		var received time.Time
		if err = rows.Scan(&id, &raw, &task, &received); err != nil {
			return nil, 0, err
		}
		if err = json.Unmarshal(raw, &r); err != nil {
			return nil, 0, err
		}
		r.ID, r.TaskID, r.ReceivedAt = id, task, received
		out = append(out, r)
	}
	return out, count, rows.Err()
}
