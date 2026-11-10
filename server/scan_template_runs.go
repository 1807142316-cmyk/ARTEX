package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/scantemplate"
)

func (s *Server) scanTemplateEngine(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, scantemplate.CheckEngine(r.Context()))
}

func (s *Server) startScanTemplateRun(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var input struct {
		TemplateID   string `json:"template_id"`
		TemplateHash string `json:"template_hash"`
		Target       string `json:"target"`
		TaskID       string `json:"task_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeErr(w, 400, "invalid run JSON")
		return
	}
	var taskID *int64
	if input.TaskID != "" {
		id, err := strconv.ParseInt(input.TaskID, 10, 64)
		if err != nil || id < 1 {
			writeErr(w, 400, "invalid task_id")
			return
		}
		task, err := s.m.pg.GetTask(id)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if task == nil {
			writeErr(w, 404, "task not found")
			return
		}
		taskID = &id
	}
	target, err := scantemplate.ValidateTarget(input.Target)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	template, err := s.m.pg.ScanTemplateVersion(r.Context(), input.TemplateID, input.TemplateHash)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "template version not found")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if _, err = scantemplate.Validate([]byte(template.Content)); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	status := scantemplate.CheckEngine(r.Context())
	if !status.Available {
		writeErr(w, 503, status.Error)
		return
	}
	select {
	case s.templateRunSlots <- struct{}{}:
	default:
		writeErr(w, 429, "two template runs are already active")
		return
	}
	run, err := s.m.pg.CreateScanTemplateRun(r.Context(), template.ID, template.ContentHash, target, taskID)
	if err != nil {
		<-s.templateRunSlots
		writeErr(w, 500, err.Error())
		return
	}
	go func() {
		defer func() { <-s.templateRunSlots }()
		ctx, cancel := context.WithTimeout(s.ctx, 2*time.Minute)
		defer cancel()
		matches, runErr := scantemplate.Run(ctx, run.TemplateContent, run.Target)
		persist, cancelPersist := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelPersist()
		if err := s.m.pg.FinishScanTemplateRun(persist, run, matches, runErr); err != nil {
			log.Printf("template run %d completion: %v", run.ID, err)
		}
	}()
	writeJSON(w, 202, run)
}

func (s *Server) getScanTemplateRun(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeErr(w, 400, "invalid run id")
		return
	}
	run, err := s.m.pg.GetScanTemplateRun(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "run not found")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, run)
}

func (s *Server) listScanTemplateRuns(w http.ResponseWriter, r *http.Request) {
	page := findingPaginationParam(r.URL.Query().Get("page"), 1, 1000000)
	limit := findingPaginationParam(r.URL.Query().Get("limit"), 20, 100)
	items, total, err := s.m.pg.ListScanTemplateRuns(r.Context(), r.URL.Query().Get("template_id"), page, limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "page": page, "limit": limit})
}
