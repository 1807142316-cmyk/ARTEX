package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
)

const (
	MaxKnowledgeCodeRunes     = 160
	MaxKnowledgeTextRunes     = 4000
	MaxKnowledgeBodyRunes     = 80000
	MaxKnowledgeEvidenceRunes = 20000
)

var (
	ErrKnowledgeInvalid      = errors.New("invalid knowledge entry")
	ErrKnowledgeCodeConflict = errors.New("knowledge code already exists")
	ErrKnowledgeNotFound     = errors.New("knowledge entry not found")
	ErrKnowledgeUnverified   = errors.New("current knowledge version must pass verification and a redaction review")
	ErrKnowledgeStaleVersion = errors.New("knowledge content changed; reload before recording a decision")
)

type KnowledgeEntry struct {
	ID             int64     `json:"id"`
	Code           string    `json:"code"`
	Category       string    `json:"category"`
	Kind           string    `json:"kind"`
	Tier           string    `json:"tier"`
	Summary        string    `json:"summary"`
	Body           string    `json:"body,omitempty"`
	SourceURL      string    `json:"source_url"`
	SourceVersion  string    `json:"source_version"`
	ContentVersion int       `json:"content_version"`
	Published      bool      `json:"published"`
	Verified       bool      `json:"verified"`
	Reviewed       bool      `json:"reviewed"`
	Verification   string    `json:"verification_result,omitempty"`
	Revoked        bool      `json:"revoked"`
	UseCount       int       `json:"use_count"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type KnowledgeInput struct {
	Code          string `json:"code"`
	Category      string `json:"category"`
	Kind          string `json:"kind"`
	Tier          string `json:"tier"`
	Summary       string `json:"summary"`
	Body          string `json:"body"`
	SourceURL     string `json:"source_url"`
	SourceVersion string `json:"source_version"`
}

type KnowledgePatch struct {
	Code          *string
	Category      *string
	Kind          *string
	Tier          *string
	Summary       *string
	Body          *string
	SourceURL     *string
	SourceVersion *string
}

type KnowledgeFilter struct {
	Query     string
	MatchBody *bool
	Category  string
	Kind      string
	Tier      string
	Verified  *bool
	Published *bool
	Limit     int
	Offset    int
}

func normalizeKnowledgeInput(in KnowledgeInput) (KnowledgeInput, string, error) {
	in.Code = strings.Join(strings.Fields(in.Code), " ")
	in.Category = strings.TrimSpace(in.Category)
	in.Kind = strings.TrimSpace(in.Kind)
	in.Tier = strings.TrimSpace(in.Tier)
	in.Summary = strings.TrimSpace(in.Summary)
	in.Body = strings.TrimSpace(in.Body)
	in.SourceURL = strings.TrimSpace(in.SourceURL)
	in.SourceVersion = strings.TrimSpace(in.SourceVersion)
	switch {
	case in.Code == "" || utf8.RuneCountInString(in.Code) > MaxKnowledgeCodeRunes:
		return in, "", fmt.Errorf("%w: code is required and limited to %d characters", ErrKnowledgeInvalid, MaxKnowledgeCodeRunes)
	case in.Summary == "" || utf8.RuneCountInString(in.Summary) > MaxKnowledgeTextRunes:
		return in, "", fmt.Errorf("%w: summary is required and limited to %d characters", ErrKnowledgeInvalid, MaxKnowledgeTextRunes)
	case in.Body == "" || utf8.RuneCountInString(in.Body) > MaxKnowledgeBodyRunes:
		return in, "", fmt.Errorf("%w: body is required and limited to %d characters", ErrKnowledgeInvalid, MaxKnowledgeBodyRunes)
	case utf8.RuneCountInString(in.Category) > 120 || utf8.RuneCountInString(in.Kind) > 120 || utf8.RuneCountInString(in.Tier) > 80:
		return in, "", fmt.Errorf("%w: category, kind, or tier is too long", ErrKnowledgeInvalid)
	case utf8.RuneCountInString(in.SourceVersion) > 240:
		return in, "", fmt.Errorf("%w: source version is too long", ErrKnowledgeInvalid)
	}
	if in.SourceURL != "" {
		u, err := url.ParseRequestURI(in.SourceURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return in, "", fmt.Errorf("%w: source_url must be an absolute HTTP(S) URL", ErrKnowledgeInvalid)
		}
	}
	return in, strings.ToLower(in.Code), nil
}

func knowledgeHash(in KnowledgeInput) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{in.Code, in.Category, in.Kind, in.Tier, in.Summary, in.Body, in.SourceURL, in.SourceVersion}, "\x00")))
	return hex.EncodeToString(sum[:])
}

const knowledgeSelect = `
SELECT e.id,e.code,e.category,e.kind,e.tier,e.summary,e.body,e.source_url,e.source_version,e.content_version,e.published,
       COALESCE(v.result='passed',false),COALESCE(a.approved AND a.redacted,false),COALESCE(v.result,''),e.revoked_at IS NOT NULL,
       (SELECT count(*)::int FROM knowledge_retrievals r WHERE r.entry_id=e.id),e.created_at,e.updated_at
FROM knowledge_entries e
LEFT JOIN LATERAL (SELECT id,result FROM knowledge_verifications WHERE entry_id=e.id AND version=e.content_version ORDER BY id DESC LIMIT 1) v ON true
LEFT JOIN LATERAL (SELECT approved,redacted FROM knowledge_reviews WHERE entry_id=e.id AND version=e.content_version ORDER BY id DESC LIMIT 1) a ON true`

func scanKnowledge(row interface{ Scan(...any) error }) (*KnowledgeEntry, error) {
	var e KnowledgeEntry
	var body sql.NullString
	if err := row.Scan(&e.ID, &e.Code, &e.Category, &e.Kind, &e.Tier, &e.Summary, &body, &e.SourceURL, &e.SourceVersion, &e.ContentVersion, &e.Published, &e.Verified, &e.Reviewed, &e.Verification, &e.Revoked, &e.UseCount, &e.CreatedAt, &e.UpdatedAt); err != nil {
		return nil, err
	}
	e.Body = body.String
	return &e, nil
}

func knowledgeNameConflict(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func (d *DB) CreateKnowledgeEntry(in KnowledgeInput) (*KnowledgeEntry, error) {
	in, ncode, err := normalizeKnowledgeInput(in)
	if err != nil {
		return nil, err
	}
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	entry, err := createKnowledgeEntryTx(tx, in, ncode)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return entry, nil
}

func createKnowledgeEntryTx(tx *sql.Tx, in KnowledgeInput, ncode string) (*KnowledgeEntry, error) {
	entry, err := scanKnowledge(tx.QueryRow(`INSERT INTO knowledge_entries(code,ncode,category,kind,tier,summary,body,source_url,source_version)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id,code,category,kind,tier,summary,body,source_url,source_version,content_version,published,false,false,'',false,0,created_at,updated_at`, in.Code, ncode, in.Category, in.Kind, in.Tier, in.Summary, in.Body, in.SourceURL, in.SourceVersion))
	if knowledgeNameConflict(err) {
		return nil, ErrKnowledgeCodeConflict
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`INSERT INTO knowledge_versions(entry_id,version,code,category,kind,tier,summary,body,source_url,source_version,content_hash) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, entry.ID, in.Code, in.Category, in.Kind, in.Tier, in.Summary, in.Body, in.SourceURL, in.SourceVersion, knowledgeHash(in)); err != nil {
		return nil, err
	}
	return entry, nil
}

// ImportKnowledgeEntries rejects conflicting content without overwriting existing versions.
func (d *DB) ImportKnowledgeEntries(items []KnowledgeInput) (created, skipped int, err error) {
	if len(items) < 1 || len(items) > 100 {
		return 0, 0, fmt.Errorf("%w: import requires 1 to 100 entries", ErrKnowledgeInvalid)
	}
	tx, err := d.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	for _, raw := range items {
		in, ncode, err := normalizeKnowledgeInput(raw)
		if err != nil {
			return 0, 0, err
		}
		// Serialize concurrent imports for the same code, including previously absent rows.
		if _, err = tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended($1,17))`, ncode); err != nil {
			return 0, 0, err
		}
		existing, err := scanKnowledge(tx.QueryRow(knowledgeSelect+` WHERE e.ncode=$1`, ncode))
		if err == sql.ErrNoRows {
			if _, err = createKnowledgeEntryTx(tx, in, ncode); err != nil {
				return 0, 0, err
			}
			created++
			continue
		}
		if err != nil {
			return 0, 0, err
		}
		old := KnowledgeInput{Code: existing.Code, Category: existing.Category, Kind: existing.Kind, Tier: existing.Tier, Summary: existing.Summary, Body: existing.Body, SourceURL: existing.SourceURL, SourceVersion: existing.SourceVersion}
		if knowledgeHash(in) != knowledgeHash(old) {
			return 0, 0, fmt.Errorf("%w: %s has different content; edit it explicitly", ErrKnowledgeCodeConflict, in.Code)
		}
		skipped++
	}
	if err = tx.Commit(); err != nil {
		return 0, 0, err
	}
	return created, skipped, nil
}

func (d *DB) GetKnowledgeEntry(id int64) (*KnowledgeEntry, error) {
	e, err := scanKnowledge(d.QueryRow(knowledgeSelect+` WHERE e.id=$1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return e, err
}

func (d *DB) GetKnowledgeEntryByCode(code string) (*KnowledgeEntry, error) {
	ncode := strings.ToLower(strings.Join(strings.Fields(code), " "))
	e, err := scanKnowledge(d.QueryRow(knowledgeSelect+` WHERE e.ncode=$1`, ncode))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return e, err
}

func (d *DB) ListKnowledgeEntries(filter KnowledgeFilter) ([]*KnowledgeEntry, int, error) {
	if filter.Limit < 1 || filter.Limit > 200 {
		filter.Limit = 50
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	query := strings.TrimSpace(filter.Query)
	where := ` WHERE ($1='' OR e.code ILIKE '%'||$1||'%' OR e.summary ILIKE '%'||$1||'%' OR (COALESCE($7::boolean,true) AND e.body ILIKE '%'||$1||'%') OR e.category ILIKE '%'||$1||'%' OR e.kind ILIKE '%'||$1||'%')
AND ($2='' OR e.category=$2) AND ($3='' OR e.kind=$3) AND ($4='' OR e.tier=$4)
AND ($5::boolean IS NULL OR (e.published AND e.revoked_at IS NULL AND COALESCE(a.approved AND a.redacted,false))=$5) AND ($6::boolean IS NULL OR COALESCE(v.result='passed',false)=$6)`
	var total int
	countSQL := `SELECT count(*) ` + knowledgeSelect[strings.Index(knowledgeSelect, "FROM knowledge_entries"):]
	if err := d.QueryRow(countSQL+where, query, filter.Category, filter.Kind, filter.Tier, filter.Published, filter.Verified, filter.MatchBody).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := d.Query(knowledgeSelect+where+` ORDER BY e.updated_at DESC,e.id DESC LIMIT $8 OFFSET $9`, query, filter.Category, filter.Kind, filter.Tier, filter.Published, filter.Verified, filter.MatchBody, filter.Limit, filter.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]*KnowledgeEntry, 0)
	for rows.Next() {
		e, err := scanKnowledge(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

func (d *DB) PatchKnowledgeEntry(id int64, patch KnowledgePatch) (*KnowledgeEntry, error) {
	if patch.Code == nil && patch.Category == nil && patch.Kind == nil && patch.Tier == nil && patch.Summary == nil && patch.Body == nil && patch.SourceURL == nil && patch.SourceVersion == nil {
		return nil, fmt.Errorf("%w: no fields supplied", ErrKnowledgeInvalid)
	}
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	current, err := scanKnowledge(tx.QueryRow(knowledgeSelect+` WHERE e.id=$1 FOR UPDATE OF e`, id))
	if err == sql.ErrNoRows {
		return nil, ErrKnowledgeNotFound
	}
	if err != nil {
		return nil, err
	}
	in := KnowledgeInput{Code: current.Code, Category: current.Category, Kind: current.Kind, Tier: current.Tier, Summary: current.Summary, Body: current.Body, SourceURL: current.SourceURL, SourceVersion: current.SourceVersion}
	if patch.Code != nil {
		in.Code = *patch.Code
	}
	if patch.Category != nil {
		in.Category = *patch.Category
	}
	if patch.Kind != nil {
		in.Kind = *patch.Kind
	}
	if patch.Tier != nil {
		in.Tier = *patch.Tier
	}
	if patch.Summary != nil {
		in.Summary = *patch.Summary
	}
	if patch.Body != nil {
		in.Body = *patch.Body
	}
	if patch.SourceURL != nil {
		in.SourceURL = *patch.SourceURL
	}
	if patch.SourceVersion != nil {
		in.SourceVersion = *patch.SourceVersion
	}
	in, ncode, err := normalizeKnowledgeInput(in)
	if err != nil {
		return nil, err
	}
	changed := knowledgeHash(in) != knowledgeHash(KnowledgeInput{Code: current.Code, Category: current.Category, Kind: current.Kind, Tier: current.Tier, Summary: current.Summary, Body: current.Body, SourceURL: current.SourceURL, SourceVersion: current.SourceVersion})
	if !changed {
		return current, nil
	}
	version := current.ContentVersion + 1
	_, err = tx.Exec(`UPDATE knowledge_entries SET code=$2,ncode=$3,category=$4,kind=$5,tier=$6,summary=$7,body=$8,source_url=$9,source_version=$10,content_version=$11,published=false,revoked_at=NULL,updated_at=now() WHERE id=$1`, id, in.Code, ncode, in.Category, in.Kind, in.Tier, in.Summary, in.Body, in.SourceURL, in.SourceVersion, version)
	if knowledgeNameConflict(err) {
		return nil, ErrKnowledgeCodeConflict
	}
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`INSERT INTO knowledge_versions(entry_id,version,code,category,kind,tier,summary,body,source_url,source_version,content_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, id, version, in.Code, in.Category, in.Kind, in.Tier, in.Summary, in.Body, in.SourceURL, in.SourceVersion, knowledgeHash(in)); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return d.GetKnowledgeEntry(id)
}

func (d *DB) RecordKnowledgeVerification(id int64, expectedVersion int, result, evidence, verifiedBy string) (*KnowledgeEntry, error) {
	result = strings.TrimSpace(result)
	evidence = strings.TrimSpace(evidence)
	verifiedBy = strings.TrimSpace(verifiedBy)
	if result != "passed" && result != "failed" {
		return nil, fmt.Errorf("%w: result must be passed or failed", ErrKnowledgeInvalid)
	}
	if evidence == "" || utf8.RuneCountInString(evidence) > MaxKnowledgeEvidenceRunes {
		return nil, fmt.Errorf("%w: verification evidence is required", ErrKnowledgeInvalid)
	}
	if len(verifiedBy) > 240 {
		return nil, fmt.Errorf("%w: verified_by is too long", ErrKnowledgeInvalid)
	}
	if verifiedBy == "" {
		verifiedBy = "operator"
	}
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow(`SELECT content_version FROM knowledge_entries WHERE id=$1 FOR UPDATE`, id).Scan(&version); err == sql.ErrNoRows {
		return nil, ErrKnowledgeNotFound
	} else if err != nil {
		return nil, err
	}
	if expectedVersion != version {
		return nil, ErrKnowledgeStaleVersion
	}
	if _, err = tx.Exec(`INSERT INTO knowledge_verifications(entry_id,version,result,evidence,verified_by) VALUES($1,$2,$3,$4,$5)`, id, version, result, evidence, verifiedBy); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`UPDATE knowledge_entries SET published=false,revoked_at=CASE WHEN $2='passed' THEN NULL ELSE revoked_at END,updated_at=now() WHERE id=$1`, id, result); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return d.GetKnowledgeEntry(id)
}

func (d *DB) PublishKnowledgeEntry(id int64) (*KnowledgeEntry, error) {
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var lockedID int64
	if err := tx.QueryRow(`SELECT id FROM knowledge_entries WHERE id=$1 FOR UPDATE`, id).Scan(&lockedID); err == sql.ErrNoRows {
		return nil, ErrKnowledgeNotFound
	} else if err != nil {
		return nil, err
	}
	entry, err := scanKnowledge(tx.QueryRow(knowledgeSelect+` WHERE e.id=$1`, id))
	if err != nil {
		return nil, err
	}
	if !entry.Verified || !entry.Reviewed || entry.Revoked {
		return nil, ErrKnowledgeUnverified
	}
	if err := tx.QueryRow(`UPDATE knowledge_entries SET published=true,updated_at=now() WHERE id=$1 RETURNING updated_at`, id).Scan(&entry.UpdatedAt); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	entry.Published = true
	return entry, nil
}

func (d *DB) RevokeKnowledgeEntry(id int64) (*KnowledgeEntry, error) {
	res, err := d.Exec(`UPDATE knowledge_entries SET published=false,revoked_at=now(),updated_at=now() WHERE id=$1`, id)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, ErrKnowledgeNotFound
	}
	return d.GetKnowledgeEntry(id)
}

func (d *DB) RetrieveKnowledgeEntry(id int64, callID, agentKey string, taskID int64) (*KnowledgeEntry, error) {
	callID = strings.TrimSpace(callID)
	if callID == "" || len(callID) > 240 {
		return nil, fmt.Errorf("%w: retrieval call id is required", ErrKnowledgeInvalid)
	}
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var lockedID int64
	if err := tx.QueryRow(`SELECT id FROM knowledge_entries WHERE id=$1 FOR UPDATE`, id).Scan(&lockedID); err == sql.ErrNoRows {
		return nil, ErrKnowledgeNotFound
	} else if err != nil {
		return nil, err
	}
	entry, err := scanKnowledge(tx.QueryRow(knowledgeSelect+` WHERE e.id=$1`, id))
	if err != nil {
		return nil, err
	}
	if !entry.Published || entry.Revoked || !entry.Verified || !entry.Reviewed {
		return nil, ErrKnowledgeNotFound
	}
	if _, err = tx.Exec(`INSERT INTO knowledge_retrievals(entry_id,version,call_id,agent_key,task_id) VALUES($1,$2,$3,$4,$5) ON CONFLICT(entry_id,call_id) DO NOTHING`, id, entry.ContentVersion, callID, agentKey, taskID); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	var count int
	if err := d.QueryRow(`SELECT count(*)::int FROM knowledge_retrievals WHERE entry_id=$1`, id).Scan(&count); err != nil {
		return nil, err
	}
	entry.UseCount = count
	return entry, nil
}

// RecordKnowledgeReview records an explicit review of the current reusable content.
// Verification evidence stays in a separate table and is never exposed by retrieval.
func (d *DB) RecordKnowledgeReview(id int64, expectedVersion int, approved, redacted bool, notes, reviewedBy string) (*KnowledgeEntry, error) {
	notes = strings.TrimSpace(notes)
	reviewedBy = strings.TrimSpace(reviewedBy)
	if notes == "" || utf8.RuneCountInString(notes) > MaxKnowledgeEvidenceRunes || len(reviewedBy) > 240 {
		return nil, fmt.Errorf("%w: bounded review notes are required", ErrKnowledgeInvalid)
	}
	if approved && !redacted {
		return nil, fmt.Errorf("%w: approve only after removing target-specific secrets and evidence from reusable text", ErrKnowledgeInvalid)
	}
	if reviewedBy == "" {
		reviewedBy = "operator"
	}
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow(`SELECT content_version FROM knowledge_entries WHERE id=$1 FOR UPDATE`, id).Scan(&version); err == sql.ErrNoRows {
		return nil, ErrKnowledgeNotFound
	} else if err != nil {
		return nil, err
	}
	if expectedVersion != version {
		return nil, ErrKnowledgeStaleVersion
	}
	if _, err = tx.Exec(`INSERT INTO knowledge_reviews(entry_id,version,approved,redacted,notes,reviewed_by) VALUES($1,$2,$3,$4,$5,$6)`, id, version, approved, redacted, notes, reviewedBy); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`UPDATE knowledge_entries SET published=false,updated_at=now() WHERE id=$1`, id); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return d.GetKnowledgeEntry(id)
}

type KnowledgeVersion struct {
	Version       int       `json:"version"`
	Code          string    `json:"code"`
	Category      string    `json:"category"`
	Kind          string    `json:"kind"`
	Tier          string    `json:"tier"`
	Summary       string    `json:"summary"`
	Body          string    `json:"body"`
	SourceURL     string    `json:"source_url"`
	SourceVersion string    `json:"source_version"`
	ContentHash   string    `json:"content_hash"`
	CreatedAt     time.Time `json:"created_at"`
}

type KnowledgeVerification struct {
	Version    int       `json:"version"`
	Result     string    `json:"result"`
	Evidence   string    `json:"evidence"`
	VerifiedBy string    `json:"verified_by"`
	CreatedAt  time.Time `json:"created_at"`
}

type KnowledgeReview struct {
	Version    int       `json:"version"`
	Approved   bool      `json:"approved"`
	Redacted   bool      `json:"redacted"`
	Notes      string    `json:"notes"`
	ReviewedBy string    `json:"reviewed_by"`
	CreatedAt  time.Time `json:"created_at"`
}

type KnowledgeHistory struct {
	Versions         []KnowledgeVersion      `json:"versions"`
	Verifications    []KnowledgeVerification `json:"verifications"`
	Reviews          []KnowledgeReview       `json:"reviews"`
	CandidateSources []*KnowledgeCandidate   `json:"candidate_sources"`
}

func (d *DB) KnowledgeHistory(id int64) (*KnowledgeHistory, error) {
	entry, err := d.GetKnowledgeEntry(id)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, ErrKnowledgeNotFound
	}
	h := &KnowledgeHistory{Versions: []KnowledgeVersion{}, Verifications: []KnowledgeVerification{}, Reviews: []KnowledgeReview{}}
	h.CandidateSources, err = d.ListKnowledgeCandidates(id)
	if err != nil {
		return nil, err
	}
	rows, err := d.Query(`SELECT version,code,category,kind,tier,summary,body,source_url,source_version,content_hash,created_at FROM knowledge_versions WHERE entry_id=$1 ORDER BY version DESC LIMIT 100`, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v KnowledgeVersion
		if err = rows.Scan(&v.Version, &v.Code, &v.Category, &v.Kind, &v.Tier, &v.Summary, &v.Body, &v.SourceURL, &v.SourceVersion, &v.ContentHash, &v.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		h.Versions = append(h.Versions, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = d.Query(`SELECT version,result,evidence,verified_by,created_at FROM knowledge_verifications WHERE entry_id=$1 ORDER BY id DESC LIMIT 100`, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v KnowledgeVerification
		if err = rows.Scan(&v.Version, &v.Result, &v.Evidence, &v.VerifiedBy, &v.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		h.Verifications = append(h.Verifications, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = d.Query(`SELECT version,approved,redacted,notes,reviewed_by,created_at FROM knowledge_reviews WHERE entry_id=$1 ORDER BY id DESC LIMIT 100`, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v KnowledgeReview
		if err = rows.Scan(&v.Version, &v.Approved, &v.Redacted, &v.Notes, &v.ReviewedBy, &v.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		h.Reviews = append(h.Reviews, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return h, nil
}
