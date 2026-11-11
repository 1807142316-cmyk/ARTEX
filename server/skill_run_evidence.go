package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

const maxSkillRunOutput = 64 << 10

var skillRunIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{8,128}$`)
var skillRunHashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var offlineWorkflowNames = map[string]bool{
	"saved-header-review": true, "evidence-inventory": true, "cve-record-review": true, "scope-asset-inventory": true, "har-api-inventory": true, "knowledge-package-check": true, "report-evidence-index": true,
	"tls-observation-review": true, "cors-policy-review": true, "cookie-attribute-review": true, "sshd-effective-config-review": true, "container-inspect-review": true, "iam-policy-review": true, "sbom-inventory-review": true,
	"python-source-review":     true,
	"binary-format-inspection": true,
}

type workflowManifest struct {
	Packages []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Files   []struct {
			Path   string `json:"path"`
			Bytes  int64  `json:"bytes"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	} `json:"packages"`
}

func readSkillRunPackageFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 {
		return nil, fmt.Errorf("installed workflow file exceeds limit")
	}
	return raw, nil
}

func (s *Server) validateReportedPackage(r db.SkillRunEvidence) error {
	if !offlineWorkflowNames[r.Skill] {
		return fmt.Errorf("workflow is not in the fixed offline catalog")
	}
	raw, err := readSkillRunPackageFile(filepath.Join(s.skillDir, "content-manifest.json"))
	if err != nil {
		return fmt.Errorf("installed content manifest unavailable")
	}
	var m workflowManifest
	if json.Unmarshal(raw, &m) != nil {
		return fmt.Errorf("invalid content manifest")
	}
	for _, p := range m.Packages {
		if p.Name != r.Skill {
			continue
		}
		if p.Version != r.PackageVersion {
			return fmt.Errorf("package version differs from installed content")
		}
		seen := map[string]bool{}
		for _, f := range p.Files {
			if f.Path != "SKILL.md" && f.Path != "scripts/run.py" {
				continue
			}
			if f.Bytes < 1 || f.Bytes > 1<<20 {
				return fmt.Errorf("invalid package file size")
			}
			b, err := readSkillRunPackageFile(filepath.Join(s.skillDir, r.Skill, filepath.FromSlash(f.Path)))
			if err != nil || int64(len(b)) != f.Bytes {
				return fmt.Errorf("installed package file unavailable or changed")
			}
			sum := sha256.Sum256(b)
			actual := hex.EncodeToString(sum[:])
			expected := r.ScriptSHA256
			if f.Path == "SKILL.md" {
				expected = r.InstructionsSHA256
			}
			if actual != f.SHA256 || actual != expected {
				return fmt.Errorf("package hash differs from installed manifest")
			}
			seen[f.Path] = true
		}
		if !seen["SKILL.md"] || !seen["scripts/run.py"] {
			return fmt.Errorf("manifest lacks workflow resources")
		}
		return nil
	}
	return fmt.Errorf("workflow absent from installed manifest")
}
func (s *Server) registerSkillRuns(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/skill-runs", s.reportSkillRun)
	mux.HandleFunc("GET /api/skill-runs", s.listSkillRuns)
	mux.HandleFunc("GET /api/skill-runs/{id}", s.getSkillRun)
}
func (s *Server) reportSkillRun(w http.ResponseWriter, r *http.Request) {
	// JSON escaping can expand both bounded output streams to six bytes per byte.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var in db.SkillRunEvidence
	if err := dec.Decode(&in); err != nil {
		writeErr(w, 400, "invalid skill run JSON")
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		writeErr(w, 400, "expected one JSON document")
		return
	}
	if in.ID != 0 || in.Attestation != "" || !in.ReceivedAt.IsZero() || !skillRunIDPattern.MatchString(in.ClientRunID) || !skillRunHashPattern.MatchString(in.InputSHA256) || !skillRunHashPattern.MatchString(in.ScriptSHA256) || !skillRunHashPattern.MatchString(in.InstructionsSHA256) {
		writeErr(w, 400, "invalid report identity or managed fields")
		return
	}
	if in.InputLabel == "" || len(in.InputLabel) > 256 || in.InputLabel == "." || in.InputLabel == ".." || strings.ContainsAny(in.InputLabel, `/\`) || strings.IndexFunc(in.InputLabel, unicode.IsControl) >= 0 || in.InputBytes < 0 || in.InputBytes > 1<<30 || (in.InputKind != "file" && in.InputKind != "directory") {
		writeErr(w, 400, "invalid input summary")
		return
	}
	if in.StartedAt.IsZero() || in.FinishedAt.Before(in.StartedAt) || in.FinishedAt.After(time.Now().Add(time.Minute)) || in.FinishedAt.Sub(in.StartedAt) > 5*time.Minute || in.ExitCode < -255 || in.ExitCode > 255 || len(in.Stdout) > maxSkillRunOutput || len(in.Stderr) > maxSkillRunOutput || !utf8.ValidString(in.Stdout) || !utf8.ValidString(in.Stderr) {
		writeErr(w, 400, "invalid duration, exit code or bounded output")
		return
	}
	switch in.Outcome {
	case "succeeded":
		if in.ExitCode != 0 || in.Truncated {
			writeErr(w, 400, "succeeded requires zero exit and complete output")
			return
		}
	case "failed":
		if in.ExitCode == 0 || in.Truncated {
			writeErr(w, 400, "failed requires a nonzero exit")
			return
		}
	case "timeout":
		if in.ExitCode == 0 {
			writeErr(w, 400, "timeout requires a nonzero exit")
			return
		}
	case "output_limit":
		if !in.Truncated {
			writeErr(w, 400, "output_limit requires truncated output")
			return
		}
	case "input_changed":
	default:
		writeErr(w, 400, "invalid outcome")
		return
	}
	if err := s.validateReportedPackage(in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	raw, _ := json.Marshal(in)
	sum := sha256.Sum256(raw)
	in.Attestation = "operator_reported"
	out, created, err := s.m.pg.SaveSkillRun(r.Context(), in, hex.EncodeToString(sum[:]))
	if err != nil {
		if errors.Is(err, db.ErrSkillRunConflict) {
			writeErr(w, 409, err.Error())
		} else if errors.Is(err, db.ErrSkillRunReference) {
			writeErr(w, 400, err.Error())
		} else {
			writeErr(w, 500, "skill run storage unavailable")
		}
		return
	}
	status := 200
	if created {
		status = 201
	}
	writeJSON(w, status, out)
}
func (s *Server) listSkillRuns(w http.ResponseWriter, r *http.Request) {
	skill := r.URL.Query().Get("skill")
	if skill != "" && !validSkillName(skill) {
		writeErr(w, 400, "invalid skill name")
		return
	}
	page := findingPaginationParam(r.URL.Query().Get("page"), 1, 1000000)
	limit := findingPaginationParam(r.URL.Query().Get("limit"), 20, 100)
	items, total, err := s.m.pg.SkillRuns(r.Context(), skill, page, limit)
	if err != nil {
		writeErr(w, 500, "skill run storage unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "page": page, "limit": limit})
}
func (s *Server) getSkillRun(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeErr(w, 400, "invalid run ID")
		return
	}
	out, err := s.m.pg.SkillRun(r.Context(), id)
	if err != nil {
		inventoryError(w, err)
		return
	}
	writeJSON(w, 200, out)
}
