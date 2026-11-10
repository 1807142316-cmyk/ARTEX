package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type KnowledgeEvidenceRef struct {
	BindingID  int64  `json:"binding_id"`
	SnapshotID string `json:"snapshot_id"`
}

type KnowledgeCandidate struct {
	ID             int64                  `json:"id"`
	FindingID      *int64                 `json:"finding_id"`
	TaskID         *int64                 `json:"task_id"`
	SourceIdentity string                 `json:"source_identity"`
	SourceVersion  int64                  `json:"source_version"`
	SourceHash     string                 `json:"source_hash"`
	EvidenceRefs   []KnowledgeEvidenceRef `json:"evidence_refs"`
	EntryID        *int64                 `json:"entry_id"`
	CreatedAt      time.Time              `json:"created_at"`
}

const knowledgeCandidateColumns = `id,finding_id,task_id,source_identity,source_version,source_hash,evidence_refs,entry_id,created_at`

// WithKnowledgeCandidateEvidence keeps the shared evidence lock while resolving
// retained source material, even when the original finding/binding was removed.
func (d *DB) WithKnowledgeCandidateEvidence(ctx context.Context, candidateID int64, snapshotID string, read func(TrafficEvidenceSnapshot) error) error {
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		var raw []byte
		err := tx.QueryRow(`SELECT to_jsonb(s) FROM traffic_evidence_snapshots s
JOIN knowledge_candidates c ON c.id=$1 AND c.evidence_refs @> jsonb_build_array(jsonb_build_object('snapshot_id',s.id))
WHERE s.id=$2`, candidateID, snapshotID).Scan(&raw)
		if err == sql.ErrNoRows {
			return ErrEvidenceNotFound
		}
		if err != nil {
			return err
		}
		var snapshot TrafficEvidenceSnapshot
		if err := json.Unmarshal(raw, &snapshot); err != nil {
			return err
		}
		return read(snapshot)
	})
}

func scanKnowledgeCandidate(row interface{ Scan(...any) error }) (*KnowledgeCandidate, error) {
	var c KnowledgeCandidate
	var raw []byte
	if err := row.Scan(&c.ID, &c.FindingID, &c.TaskID, &c.SourceIdentity, &c.SourceVersion, &c.SourceHash, &raw, &c.EntryID, &c.CreatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &c.EvidenceRefs); err != nil {
		return nil, err
	}
	return &c, nil
}

// CollectFindingKnowledgeCandidate uses the existing evidence lock and identifiers.
// The source digest covers changes to the finding as well as its evidence version;
// source text and snapshot headers are not copied to the candidate.
func (d *DB) CollectFindingKnowledgeCandidate(ctx context.Context, findingID int64) (out *KnowledgeCandidate, created bool, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockFindingEvidenceTx(tx, findingID, nil); err != nil {
			return err
		}
		var taskID sql.NullInt64
		var version int64
		var source []byte
		if err := tx.QueryRow(`SELECT task_id,evidence_version,jsonb_build_object('vulnclass',vulnclass,'name',name,'severity',severity,'summary',summary,'evidence',evidence,'report',report,'status',status) FROM findings WHERE id=$1`, findingID).Scan(&taskID, &version, &source); err != nil {
			return err
		}
		refs := []KnowledgeEvidenceRef{}
		rows, err := tx.Query(`SELECT id,snapshot_id FROM finding_traffic_bindings WHERE finding_id=$1 ORDER BY id`, findingID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var ref KnowledgeEvidenceRef
			if err := rows.Scan(&ref.BindingID, &ref.SnapshotID); err != nil {
				rows.Close()
				return err
			}
			refs = append(refs, ref)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		refsJSON, _ := json.Marshal(refs)
		hash := fmt.Sprintf("%x", sha256.Sum256(append(append(source, 0), refsJSON...)))
		identity := fmt.Sprintf("finding:%d", findingID)
		var tid *int64
		if taskID.Valid {
			tid = &taskID.Int64
		}
		var id int64
		err = tx.QueryRow(`INSERT INTO knowledge_candidates(finding_id,task_id,source_identity,source_version,source_hash,evidence_refs) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(source_identity,source_version,source_hash) DO NOTHING RETURNING id`, findingID, tid, identity, version, hash, refsJSON).Scan(&id)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		created = err == nil
		out, err = scanKnowledgeCandidate(tx.QueryRow(`SELECT `+knowledgeCandidateColumns+` FROM knowledge_candidates WHERE source_identity=$1 AND source_version=$2 AND source_hash=$3`, identity, version, hash))
		return err
	})
	return
}

func (d *DB) ListKnowledgeCandidates(entryID int64) ([]*KnowledgeCandidate, error) {
	items, _, err := d.ListKnowledgeCandidatesPage(entryID, 100, 0)
	return items, err
}

func (d *DB) ListKnowledgeCandidatesPage(entryID int64, limit, offset int) ([]*KnowledgeCandidate, int, error) {
	if limit < 1 || limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	var total int
	if err := d.QueryRow(`SELECT count(*) FROM knowledge_candidates WHERE ($1::bigint=0 OR entry_id=$1)`, entryID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := d.Query(`SELECT `+knowledgeCandidateColumns+` FROM knowledge_candidates WHERE ($1::bigint=0 OR entry_id=$1) ORDER BY id DESC LIMIT $2 OFFSET $3`, entryID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*KnowledgeCandidate{}
	for rows.Next() {
		c, err := scanKnowledgeCandidate(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// PromoteKnowledgeCandidate accepts human-authored reusable text only.
// Provenance stays in the candidate relationship, outside the retrievable body.
func (d *DB) PromoteKnowledgeCandidate(id int64, in KnowledgeInput, redacted bool) (*KnowledgeEntry, bool, error) {
	if !redacted {
		return nil, false, fmt.Errorf("%w: confirm reusable fields exclude target evidence and credentials", ErrKnowledgeInvalid)
	}
	in, ncode, err := normalizeKnowledgeInput(in)
	if err != nil {
		return nil, false, err
	}
	tx, err := d.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	c, err := scanKnowledgeCandidate(tx.QueryRow(`SELECT `+knowledgeCandidateColumns+` FROM knowledge_candidates WHERE id=$1 FOR UPDATE`, id))
	if err == sql.ErrNoRows {
		return nil, false, ErrKnowledgeNotFound
	}
	if err != nil {
		return nil, false, err
	}
	if c.EntryID != nil {
		entry, err := scanKnowledge(tx.QueryRow(knowledgeSelect+` WHERE e.id=$1`, *c.EntryID))
		return entry, false, err
	}
	entry, err := createKnowledgeEntryTx(tx, in, ncode)
	if err != nil {
		return nil, false, err
	}
	if _, err = tx.Exec(`UPDATE knowledge_candidates SET entry_id=$2 WHERE id=$1`, id, entry.ID); err != nil {
		return nil, false, err
	}
	if err = tx.Commit(); err != nil {
		return nil, false, err
	}
	return entry, true, nil
}
