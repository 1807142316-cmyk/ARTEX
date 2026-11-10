package db

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed knowledge/baseline-v1.json
var knowledgeBaseline []byte

// SeedKnowledgeBaseline adds missing authored guidance as unreviewed drafts.
// Existing entries, including edited content and decisions, are preserved.
func (d *DB) SeedKnowledgeBaseline() error {
	var items []KnowledgeInput
	if err := json.Unmarshal(knowledgeBaseline, &items); err != nil {
		return fmt.Errorf("decode knowledge baseline: %w", err)
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, raw := range items {
		in, ncode, err := normalizeKnowledgeInput(raw)
		if err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM knowledge_entries WHERE ncode=$1)`, ncode).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := createKnowledgeEntryTx(tx, in, ncode); err != nil {
			return err
		}
	}
	return tx.Commit()
}
