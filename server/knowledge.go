package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

const maxKnowledgeRequestBytes = 256 << 10

type knowledgeRequest struct {
	Code           *string             `json:"code"`
	Category       *string             `json:"category"`
	Kind           *string             `json:"kind"`
	Tier           *string             `json:"tier"`
	Summary        *string             `json:"summary"`
	Body           *string             `json:"body"`
	SourceURL      *string             `json:"source_url"`
	SourceVersion  *string             `json:"source_version"`
	Result         string              `json:"result"`
	Evidence       string              `json:"evidence"`
	VerifiedBy     string              `json:"verified_by"`
	CallID         string              `json:"call_id"`
	Approved       bool                `json:"approved"`
	Redacted       bool                `json:"redacted"`
	Notes          string              `json:"notes"`
	ReviewedBy     string              `json:"reviewed_by"`
	Items          []db.KnowledgeInput `json:"items"`
	ContentVersion int                 `json:"content_version"`
}

func decodeKnowledgeRequest(w http.ResponseWriter, r *http.Request, req *knowledgeRequest) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxKnowledgeRequestBytes)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, "请求正文过大")
		} else {
			writeErr(w, http.StatusBadRequest, err.Error())
		}
		return false
	}
	if err := json.Unmarshal(data, req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return false
	}
	return true
}

func writeKnowledgeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, db.ErrKnowledgeInvalid):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, db.ErrKnowledgeCodeConflict):
		writeErr(w, http.StatusConflict, "知识条目编码已存在")
	case errors.Is(err, db.ErrKnowledgeNotFound):
		writeErr(w, http.StatusNotFound, "knowledge entry not found")
	case errors.Is(err, db.ErrKnowledgeUnverified):
		writeErr(w, http.StatusConflict, "当前版本必须先通过验证及脱敏审核才能发布")
	case errors.Is(err, db.ErrKnowledgeStaleVersion):
		writeErr(w, http.StatusConflict, "内容版本已变化，请重新加载后记录结论")
	default:
		writeErr(w, http.StatusInternalServerError, err.Error())
	}
}

func (s *Server) knowledgeList(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	page := findingPaginationParam(q.Get("page"), 1, 0)
	limit := findingPaginationParam(q.Get("limit"), 50, 200)
	filter := db.KnowledgeFilter{Query: strings.TrimSpace(q.Get("q")), Category: strings.TrimSpace(q.Get("category")), Kind: strings.TrimSpace(q.Get("kind")), Tier: strings.TrimSpace(q.Get("tier")), Limit: limit, Offset: (page - 1) * limit}
	if q.Has("match_body") {
		v := q.Get("match_body") == "true"
		filter.MatchBody = &v
	}
	if q.Has("verified") {
		v := q.Get("verified") == "true"
		filter.Verified = &v
	}
	if q.Has("published") {
		v := q.Get("published") == "true"
		filter.Published = &v
	}
	entries, total, err := pg.ListKnowledgeEntries(filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": entries, "total": total, "page": page, "limit": limit})
}

func (s *Server) knowledgeExecutionSearch(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	page := findingPaginationParam(q.Get("page"), 1, 0)
	limit := findingPaginationParam(q.Get("limit"), 20, 100)
	verified, published := true, true
	entries, total, err := pg.ListKnowledgeEntries(db.KnowledgeFilter{Query: strings.TrimSpace(q.Get("q")), Category: strings.TrimSpace(q.Get("category")), Kind: strings.TrimSpace(q.Get("kind")), Tier: strings.TrimSpace(q.Get("tier")), Verified: &verified, Published: &published, Limit: limit, Offset: (page - 1) * limit})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, entry := range entries {
		entry.Body = ""
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": entries, "total": total, "page": page, "limit": limit})
}

func (s *Server) knowledgeCreate(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req knowledgeRequest
	if !decodeKnowledgeRequest(w, r, &req) {
		return
	}
	entry, err := pg.CreateKnowledgeEntry(db.KnowledgeInput{Code: valueString(req.Code), Category: valueString(req.Category), Kind: valueString(req.Kind), Tier: valueString(req.Tier), Summary: valueString(req.Summary), Body: valueString(req.Body), SourceURL: valueString(req.SourceURL), SourceVersion: valueString(req.SourceVersion)})
	if err != nil {
		writeKnowledgeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) knowledgeGet(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad knowledge id")
		return
	}
	entry, err := pg.GetKnowledgeEntry(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entry == nil {
		writeErr(w, http.StatusNotFound, "knowledge entry not found")
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

func (s *Server) knowledgePatch(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad knowledge id")
		return
	}
	var req knowledgeRequest
	if !decodeKnowledgeRequest(w, r, &req) {
		return
	}
	entry, err := pg.PatchKnowledgeEntry(id, db.KnowledgePatch{Code: req.Code, Category: req.Category, Kind: req.Kind, Tier: req.Tier, Summary: req.Summary, Body: req.Body, SourceURL: req.SourceURL, SourceVersion: req.SourceVersion})
	if err != nil {
		writeKnowledgeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

func (s *Server) knowledgeVerify(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad knowledge id")
		return
	}
	var req knowledgeRequest
	if !decodeKnowledgeRequest(w, r, &req) {
		return
	}
	entry, err := pg.RecordKnowledgeVerification(id, req.ContentVersion, req.Result, req.Evidence, req.VerifiedBy)
	if err != nil {
		writeKnowledgeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) knowledgePublish(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad knowledge id")
		return
	}
	entry, err := pg.PublishKnowledgeEntry(id)
	if err != nil {
		writeKnowledgeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

func (s *Server) knowledgeRevoke(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad knowledge id")
		return
	}
	entry, err := pg.RevokeKnowledgeEntry(id)
	if err != nil {
		writeKnowledgeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

func (s *Server) knowledgeRetrieve(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad knowledge id")
		return
	}
	var req knowledgeRequest
	if !decodeKnowledgeRequest(w, r, &req) {
		return
	}
	agentKey := strings.TrimSpace(r.URL.Query().Get("agent_key"))
	if agentKey == "" {
		agentKey = "worker"
	}
	run := agent.RunInfoFrom(r.Context())
	entry, err := pg.RetrieveKnowledgeEntry(id, knowledgeCallKey(req.CallID, agentKey, run), agentKey, run.TaskID)
	if err != nil {
		writeKnowledgeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

func knowledgeToolSpecs() []actool.Spec {
	searchSchema := map[string]any{"type": "object", "properties": map[string]any{"query": map[string]any{"type": "string"}, "category": map[string]any{"type": "string"}, "kind": map[string]any{"type": "string"}, "tier": map[string]any{"type": "string"}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 20}}, "additionalProperties": false}
	getSchema := map[string]any{"type": "object", "properties": map[string]any{"id": map[string]any{"type": "integer", "minimum": 1}, "code": map[string]any{"type": "string"}}, "additionalProperties": false}
	return []actool.Spec{
		{Name: "kb_search", Description: "Search published, current-version verified and reviewed knowledge. Returns summaries and stable codes; use kb_get to retrieve full text.", Schema: searchSchema},
		{Name: "kb_get", Description: "Retrieve published, current-version verified and reviewed knowledge by id or code. Logical tool-call retries are deduplicated automatically.", Schema: getSchema},
	}
}

func knowledgeCallKey(callID, agentKey string, info agent.RunInfo) string {
	if strings.TrimSpace(callID) == "" || len(callID) > 240 {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d:%d:%s:%s:%s", info.TaskID, info.IntentID, info.SessionID, agentKey, callID))))
}

func knowledgeTools(pg *db.DB) []actool.CoreTool {
	specs := knowledgeToolSpecs()
	return []actool.CoreTool{
		actool.Build(actool.Spec{Name: "kb_search", Description: specs[0].Description, Schema: specs[0].Schema, ReadOnly: func(json.RawMessage) bool { return true }, Concurrent: func(json.RawMessage) bool { return true }, Permissions: func(_ context.Context, _ json.RawMessage, _ permission.Context) permission.Decision {
			return permission.Allowed()
		}, Run: func(_ context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var args struct {
				Query    string `json:"query"`
				Category string `json:"category"`
				Kind     string `json:"kind"`
				Tier     string `json:"tier"`
				Limit    int    `json:"limit"`
			}
			if err := json.Unmarshal(input, &args); err != nil {
				return actool.Errorf("invalid search request"), nil
			}
			limit := args.Limit
			if limit < 1 || limit > 20 {
				limit = 10
			}
			verified, published := true, true
			items, total, err := pg.ListKnowledgeEntries(db.KnowledgeFilter{Query: args.Query, Category: args.Category, Kind: args.Kind, Tier: args.Tier, Verified: &verified, Published: &published, Limit: limit})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			type summary struct {
				ID             int64  `json:"id"`
				Code           string `json:"code"`
				Category       string `json:"category"`
				Kind           string `json:"kind"`
				Tier           string `json:"tier"`
				Summary        string `json:"summary"`
				SourceURL      string `json:"source_url"`
				ContentVersion int    `json:"content_version"`
			}
			out := make([]summary, 0, len(items))
			for _, item := range items {
				out = append(out, summary{item.ID, item.Code, item.Category, item.Kind, item.Tier, item.Summary, item.SourceURL, item.ContentVersion})
			}
			data, err := json.Marshal(map[string]any{"items": out, "total": total})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(string(data)), nil
		}}),
		actool.Build(actool.Spec{Name: "kb_get", Description: specs[1].Description, Schema: specs[1].Schema, ReadOnly: func(json.RawMessage) bool { return true }, Concurrent: func(json.RawMessage) bool { return true }, Permissions: func(_ context.Context, _ json.RawMessage, _ permission.Context) permission.Decision {
			return permission.Allowed()
		}, Run: func(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			var args struct {
				ID   int64  `json:"id"`
				Code string `json:"code"`
			}
			if err := json.Unmarshal(input, &args); err != nil {
				return actool.Errorf("invalid retrieval request"), nil
			}
			id := args.ID
			if id < 1 && strings.TrimSpace(args.Code) != "" {
				entry, err := pg.GetKnowledgeEntryByCode(args.Code)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if entry == nil {
					return actool.Errorf("knowledge entry not found"), nil
				}
				id = entry.ID
			}
			if id < 1 {
				return actool.Errorf("id or code is required"), nil
			}
			info := agent.RunInfoFrom(ctx)
			agentKey, callID := "", ""
			if tc != nil {
				agentKey = strings.TrimSpace(tc.AgentID)
				callID = tc.ToolUseID
			}
			if agentKey == "" {
				agentKey = "worker"
			}
			entry, err := pg.RetrieveKnowledgeEntry(id, knowledgeCallKey(callID, agentKey, info), agentKey, info.TaskID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			data, err := json.Marshal(entry)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(string(data)), nil
		}}),
	}
}

func valueString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (s *Server) knowledgeImport(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req knowledgeRequest
	if !decodeKnowledgeRequest(w, r, &req) {
		return
	}
	created, skipped, err := pg.ImportKnowledgeEntries(req.Items)
	if err != nil {
		writeKnowledgeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"created": created, "skipped": skipped})
}

func (s *Server) knowledgeReview(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad knowledge id")
		return
	}
	var req knowledgeRequest
	if !decodeKnowledgeRequest(w, r, &req) {
		return
	}
	entry, err := pg.RecordKnowledgeReview(id, req.ContentVersion, req.Approved, req.Redacted, req.Notes, req.ReviewedBy)
	if err != nil {
		writeKnowledgeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) knowledgeHistory(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad knowledge id")
		return
	}
	history, err := pg.KnowledgeHistory(id)
	if err != nil {
		writeKnowledgeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, history)
}
