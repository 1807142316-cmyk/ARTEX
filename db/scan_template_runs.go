package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Autumn-27/artex/scantemplate"
)

type ScanTemplateRun struct {
	ID              int64                `json:"id"`
	TemplateID      string               `json:"template_id"`
	TemplateHash    string               `json:"template_hash"`
	TemplateContent string               `json:"template_content"`
	SourceURL       string               `json:"source_url"`
	SourceVersion   string               `json:"source_version"`
	License         string               `json:"license"`
	Target          string               `json:"target"`
	TaskID          *int64               `json:"task_id"`
	EngineVersion   string               `json:"engine_version"`
	Status          string               `json:"status"`
	Error           string               `json:"error"`
	Matches         []scantemplate.Match `json:"matches"`
	CreatedAt       time.Time            `json:"created_at"`
	FinishedAt      *time.Time           `json:"finished_at"`
}

func (d *DB) CreateScanTemplateRun(ctx context.Context, templateID, hash, target string, taskID *int64) (ScanTemplateRun, error) {
	var run ScanTemplateRun
	err := d.QueryRowContext(ctx, `INSERT INTO scan_template_runs (template_id,template_hash,template_content,source_url,source_version,license,target,engine_version,task_id)
	SELECT template_id,content_hash,content,source_url,source_version,license,$3,$4,$5 FROM scan_templates WHERE template_id=$1 AND content_hash=$2
	RETURNING id`, templateID, hash, target, scantemplate.EngineVersion, taskID).Scan(&run.ID)
	if err != nil {
		return run, err
	}
	return d.GetScanTemplateRun(ctx, run.ID)
}

func (d *DB) GetScanTemplateRun(ctx context.Context, id int64) (ScanTemplateRun, error) {
	// An engine run is bounded to two minutes. A crashed application leaves a
	// visible interrupted result after the completion-write grace period.
	if err := d.RecoverScanTemplateRuns(ctx); err != nil {
		return ScanTemplateRun{}, err
	}
	var run ScanTemplateRun
	var matches []byte
	err := d.QueryRowContext(ctx, `SELECT id,template_id,template_hash,template_content,source_url,source_version,license,target,task_id,engine_version,status,error,matches,created_at,finished_at FROM scan_template_runs WHERE id=$1`, id).Scan(&run.ID, &run.TemplateID, &run.TemplateHash, &run.TemplateContent, &run.SourceURL, &run.SourceVersion, &run.License, &run.Target, &run.TaskID, &run.EngineVersion, &run.Status, &run.Error, &matches, &run.CreatedAt, &run.FinishedAt)
	if err != nil {
		return run, err
	}
	err = json.Unmarshal(matches, &run.Matches)
	return run, err
}

func (d *DB) RecoverScanTemplateRuns(ctx context.Context) error {
	_, err := d.ExecContext(ctx, `UPDATE scan_template_runs SET status='interrupted',error='Application stopped before execution completed',finished_at=now() WHERE status='running' AND created_at<now()-interval '5 minutes'`)
	return err
}

func (d *DB) ListScanTemplateRuns(ctx context.Context, templateID string, page, limit int) ([]ScanTemplateRun, int, error) {
	var total int
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM scan_template_runs WHERE ($1='' OR template_id=$1)`, templateID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := d.QueryContext(ctx, `SELECT id FROM scan_template_runs WHERE ($1='' OR template_id=$1) ORDER BY id DESC LIMIT $2 OFFSET $3`, templateID, limit, (page-1)*limit)
	if err != nil {
		return nil, 0, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, 0, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, 0, err
	}
	result := []ScanTemplateRun{}
	for _, id := range ids {
		run, err := d.GetScanTemplateRun(ctx, id)
		if err != nil {
			return nil, 0, err
		}
		run.TemplateContent = ""
		for i := range run.Matches {
			run.Matches[i].Request = ""
			run.Matches[i].Response = ""
		}
		result = append(result, run)
	}
	return result, total, nil
}

// Findings and their evidence are committed atomically with completion. A
// template match is a pending candidate and never a confirmation decision.
func (d *DB) FinishScanTemplateRun(ctx context.Context, run ScanTemplateRun, matches []scantemplate.Match, runErr error) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM scan_template_runs WHERE id=$1 FOR UPDATE`, run.ID).Scan(&status); err != nil {
		return err
	}
	if status != "running" {
		return nil
	}
	status = "completed"
	message := ""
	if runErr != nil {
		status = "failed"
		if errors.Is(runErr, context.DeadlineExceeded) {
			status = "timed_out"
		}
		if errors.Is(runErr, context.Canceled) {
			status = "interrupted"
		}
		message = runErr.Error()
	}
	if matches == nil {
		matches = []scantemplate.Match{}
	}
	metadata, err := scantemplate.Validate([]byte(run.TemplateContent))
	if err != nil {
		return err
	}
	for i := range matches {
		if !matches[i].Matched || runErr != nil {
			continue
		}
		evidence, _ := json.Marshal(map[string]any{"scan_run_id": run.ID, "template_id": run.TemplateID, "template_hash": run.TemplateHash, "engine_version": run.EngineVersion, "url": matches[i].URL, "request": matches[i].Request, "response": matches[i].Response})
		severity := metadata.Severity
		if severity == "info" || severity == "unknown" {
			severity = "low"
		}
		if err = tx.QueryRowContext(ctx, `INSERT INTO findings (task_id,vulnclass,name,severity,summary,evidence,worker,asset_ids,status) VALUES ($1,'configuration-check',$2,$3,$4,$5,'nuclei','[]','pending') RETURNING id`, run.TaskID, metadata.Name, severity, "Unverified template match ("+metadata.Severity+"): "+matches[i].URL, string(evidence)).Scan(&matches[i].FindingID); err != nil {
			return err
		}
	}
	encoded, _ := json.Marshal(matches)
	_, err = tx.ExecContext(ctx, `UPDATE scan_template_runs SET status=$2,error=$3,matches=$4::jsonb,finished_at=now() WHERE id=$1`, run.ID, status, message, string(encoded))
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) ScanTemplateVersion(ctx context.Context, id, hash string) (ScanTemplate, error) {
	var item ScanTemplate
	var tags, refs []byte
	err := d.QueryRowContext(ctx, `SELECT template_id,name,author,severity,description,tags,reference_urls,protocol,source_url,source_version,license,content_hash,content FROM scan_templates WHERE template_id=$1 AND (($2='' AND active) OR content_hash=$2)`, id, hash).Scan(&item.ID, &item.Name, &item.Author, &item.Severity, &item.Description, &tags, &refs, &item.Protocol, &item.SourceURL, &item.SourceVersion, &item.License, &item.ContentHash, &item.Content)
	if err != nil {
		return item, err
	}
	_ = json.Unmarshal(tags, &item.Tags)
	_ = json.Unmarshal(refs, &item.References)
	return item, nil
}
