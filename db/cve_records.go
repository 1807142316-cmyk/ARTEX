package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

type CVERecord struct {
	ID            string          `json:"cve_id"`
	State         string          `json:"state"`
	DataVersion   string          `json:"data_version"`
	Description   string          `json:"description"`
	Products      []string        `json:"products"`
	References    []string        `json:"references"`
	Published     string          `json:"date_published"`
	Updated       string          `json:"date_updated"`
	SourceVersion string          `json:"source_version"`
	ContentHash   string          `json:"content_hash"`
	Raw           json.RawMessage `json:"raw"`
}

type CVEImportResult struct {
	Added    int `json:"added"`
	Modified int `json:"modified"`
}

type CVEPage struct {
	Items []CVERecord `json:"items"`
	Total int         `json:"total"`
	Page  int         `json:"page"`
	Limit int         `json:"limit"`
}

func (d *DB) UpsertCVERecords(ctx context.Context, records []CVERecord) (CVEImportResult, error) {
	var result CVEImportResult
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	for _, record := range records {
		products, err := json.Marshal(record.Products)
		if err != nil {
			return result, err
		}
		references, err := json.Marshal(record.References)
		if err != nil {
			return result, err
		}
		var previousHash string
		err = tx.QueryRowContext(ctx, `SELECT content_hash FROM cve_records WHERE cve_id=$1 FOR UPDATE`, record.ID).Scan(&previousHash)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return result, err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO cve_records
			(cve_id,state,data_version,description,products,reference_urls,date_published,date_updated,source_version,content_hash,raw_record)
			VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8,$9,$10,$11::jsonb)
			ON CONFLICT (cve_id) DO UPDATE SET state=EXCLUDED.state,data_version=EXCLUDED.data_version,
			description=EXCLUDED.description,products=EXCLUDED.products,reference_urls=EXCLUDED.reference_urls,
			date_published=EXCLUDED.date_published,date_updated=EXCLUDED.date_updated,
			source_version=EXCLUDED.source_version,content_hash=EXCLUDED.content_hash,raw_record=EXCLUDED.raw_record,
			imported_at=now()`, record.ID, record.State, record.DataVersion, record.Description, string(products),
			string(references), record.Published, record.Updated, record.SourceVersion, record.ContentHash, string(record.Raw))
		if err != nil {
			return result, err
		}
		if previousHash == "" {
			result.Added++
		} else if previousHash != record.ContentHash {
			result.Modified++
		}
	}
	if err := tx.Commit(); err != nil {
		return CVEImportResult{}, err
	}
	return result, nil
}

func (d *DB) SearchCVERecords(ctx context.Context, query string, page, limit int) (CVEPage, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	query = strings.TrimSpace(query)
	var result CVEPage
	result.Page, result.Limit = page, limit
	pattern := "%" + strings.ReplaceAll(strings.ReplaceAll(query, "%", "\\%"), "_", "\\_") + "%"
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM cve_records WHERE $1='' OR cve_id ILIKE $2 ESCAPE '\' OR description ILIKE $2 ESCAPE '\' OR products::text ILIKE $2 ESCAPE '\' OR reference_urls::text ILIKE $2 ESCAPE '\'`, query, pattern).Scan(&result.Total); err != nil {
		return result, err
	}
	if result.Total == 0 || page > (result.Total-1)/limit+1 {
		result.Items = []CVERecord{}
		return result, nil
	}
	rows, err := d.QueryContext(ctx, `SELECT cve_id,state,data_version,description,products,reference_urls,date_published,date_updated,source_version,content_hash,raw_record
		FROM cve_records WHERE $1='' OR cve_id ILIKE $2 ESCAPE '\' OR description ILIKE $2 ESCAPE '\' OR products::text ILIKE $2 ESCAPE '\' OR reference_urls::text ILIKE $2 ESCAPE '\'
		ORDER BY date_published DESC,cve_id LIMIT $3 OFFSET $4`, query, pattern, limit, (page-1)*limit)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	result.Items = []CVERecord{}
	for rows.Next() {
		var item CVERecord
		var products, refs, raw []byte
		if err := rows.Scan(&item.ID, &item.State, &item.DataVersion, &item.Description, &products, &refs, &item.Published, &item.Updated, &item.SourceVersion, &item.ContentHash, &raw); err != nil {
			return result, err
		}
		if err := json.Unmarshal(products, &item.Products); err != nil {
			return result, err
		}
		if err := json.Unmarshal(refs, &item.References); err != nil {
			return result, err
		}
		item.Raw = append(json.RawMessage(nil), raw...)
		result.Items = append(result.Items, item)
	}
	return result, rows.Err()
}

type CVEStats struct {
	Total  int            `json:"total"`
	States map[string]int `json:"states"`
	Years  map[string]int `json:"years"`
}

func (d *DB) CVERecordStats(ctx context.Context) (CVEStats, error) {
	stats := CVEStats{States: map[string]int{}, Years: map[string]int{}}
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM cve_records`).Scan(&stats.Total); err != nil {
		return stats, err
	}
	rows, err := d.QueryContext(ctx, `SELECT state,count(*) FROM cve_records GROUP BY state`)
	if err != nil {
		return stats, err
	}
	for rows.Next() {
		var state string
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			rows.Close()
			return stats, err
		}
		stats.States[state] = count
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return stats, err
	}
	rows.Close()
	rows, err = d.QueryContext(ctx, `SELECT substring(date_published from 1 for 4),count(*) FROM cve_records WHERE date_published<>'' GROUP BY 1`)
	if err != nil {
		return stats, err
	}
	defer rows.Close()
	for rows.Next() {
		var year string
		var count int
		if err := rows.Scan(&year, &count); err != nil {
			return stats, err
		}
		stats.Years[year] = count
	}
	return stats, rows.Err()
}
