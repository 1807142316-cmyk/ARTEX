package db

import (
	"context"
	_ "embed"
	"encoding/json"
	"math"
	"strings"

	"github.com/Autumn-27/artex/scantemplate"
)

//go:embed scan-templates/artex-robots-index.yaml
var robotsTemplateContent string

func (d *DB) SeedScanTemplates(ctx context.Context) error {
	metadata, err := scantemplate.Validate([]byte(robotsTemplateContent))
	if err != nil {
		return err
	}
	var exists bool
	if err := d.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM scan_templates WHERE template_id=$1)`, metadata.ID).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	return d.SaveScanTemplate(ctx, ScanTemplate{ID: metadata.ID, Name: metadata.Name, Author: metadata.Author, Severity: metadata.Severity,
		Description: metadata.Description, Tags: metadata.Tags, References: metadata.References, Protocol: metadata.Protocol,
		SourceURL: "https://github.com/1807142316-cmyk/ARTEX", SourceVersion: "artex-authored-v1", License: "AGPL-3.0-only",
		ContentHash: metadata.ContentHash, Content: robotsTemplateContent})
}

type ScanTemplate struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Author        string   `json:"author"`
	Severity      string   `json:"severity"`
	Description   string   `json:"description"`
	Tags          []string `json:"tags"`
	References    []string `json:"references"`
	Protocol      string   `json:"protocol"`
	SourceURL     string   `json:"source_url"`
	SourceVersion string   `json:"source_version"`
	License       string   `json:"license"`
	ContentHash   string   `json:"content_hash"`
	Content       string   `json:"content"`
}

type ScanTemplatePage struct {
	Items []ScanTemplate `json:"items"`
	Total int            `json:"total"`
	Page  int            `json:"page"`
	Limit int            `json:"limit"`
}

func (d *DB) SaveScanTemplate(ctx context.Context, template ScanTemplate) error {
	tags, _ := json.Marshal(template.Tags)
	refs, _ := json.Marshal(template.References)
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "scan-template:"+template.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE scan_templates SET active=false WHERE template_id=$1 AND active AND content_hash<>$2`, template.ID, template.ContentHash); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO scan_templates
		(template_id,name,author,severity,description,tags,reference_urls,protocol,source_url,source_version,license,content_hash,content)
		VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8,$9,$10,$11,$12,$13)
		ON CONFLICT (template_id,content_hash) DO UPDATE SET name=EXCLUDED.name,author=EXCLUDED.author,severity=EXCLUDED.severity,
		description=EXCLUDED.description,tags=EXCLUDED.tags,reference_urls=EXCLUDED.reference_urls,protocol=EXCLUDED.protocol,
		source_url=EXCLUDED.source_url,source_version=EXCLUDED.source_version,license=EXCLUDED.license,
		content=EXCLUDED.content,active=true,validated_at=now()`,
		template.ID, template.Name, template.Author, template.Severity, template.Description, string(tags), string(refs),
		template.Protocol, template.SourceURL, template.SourceVersion, template.License, template.ContentHash, template.Content)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) SearchScanTemplates(ctx context.Context, query, severity string, page, limit int) (ScanTemplatePage, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if page > math.MaxInt/limit {
		page = math.MaxInt / limit
	}
	query = strings.TrimSpace(query)
	severity = strings.TrimSpace(severity)
	pattern := "%" + strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(query) + "%"
	var result ScanTemplatePage
	result.Page = page
	result.Limit = limit
	where := `WHERE active AND ($1='' OR template_id ILIKE $2 ESCAPE '\' OR name ILIKE $2 ESCAPE '\' OR description ILIKE $2 ESCAPE '\' OR tags::text ILIKE $2 ESCAPE '\') AND ($3='' OR severity=$3)`
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM scan_templates `+where, query, pattern, severity).Scan(&result.Total); err != nil {
		return result, err
	}
	rows, err := d.QueryContext(ctx, `SELECT template_id,name,author,severity,description,tags,reference_urls,protocol,source_url,source_version,license,content_hash,content FROM scan_templates `+where+` ORDER BY template_id LIMIT $4 OFFSET $5`, query, pattern, severity, limit, (page-1)*limit)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	result.Items = []ScanTemplate{}
	for rows.Next() {
		var item ScanTemplate
		var tags, refs []byte
		if err := rows.Scan(&item.ID, &item.Name, &item.Author, &item.Severity, &item.Description, &tags, &refs, &item.Protocol, &item.SourceURL, &item.SourceVersion, &item.License, &item.ContentHash, &item.Content); err != nil {
			return result, err
		}
		if err := json.Unmarshal(tags, &item.Tags); err != nil {
			return result, err
		}
		if err := json.Unmarshal(refs, &item.References); err != nil {
			return result, err
		}
		result.Items = append(result.Items, item)
	}
	return result, rows.Err()
}
