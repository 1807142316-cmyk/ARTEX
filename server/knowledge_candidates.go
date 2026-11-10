package server

import (
	"errors"
	"net/http"

	"github.com/Autumn-27/artex/db"
)

func (s *Server) collectFindingKnowledgeCandidate(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad finding id")
		return
	}
	c, created, err := pg.CollectFindingKnowledgeCandidate(r.Context(), id)
	if errors.Is(err, db.ErrFindingNotFound) {
		writeErr(w, http.StatusNotFound, "finding not found")
		return
	}
	if err != nil {
		writeKnowledgeErr(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, c)
}

func (s *Server) knowledgeCandidates(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	items, err := pg.ListKnowledgeCandidates(0)
	if err != nil {
		writeKnowledgeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) promoteKnowledgeCandidate(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad candidate id")
		return
	}
	var req knowledgeRequest
	if !decodeKnowledgeRequest(w, r, &req) {
		return
	}
	entry, created, err := pg.PromoteKnowledgeCandidate(id, db.KnowledgeInput{Code: valueString(req.Code), Category: valueString(req.Category), Kind: valueString(req.Kind), Tier: valueString(req.Tier), Summary: valueString(req.Summary), Body: valueString(req.Body), SourceURL: valueString(req.SourceURL), SourceVersion: valueString(req.SourceVersion)}, req.Redacted)
	if err != nil {
		writeKnowledgeErr(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, entry)
}
