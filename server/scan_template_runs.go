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
	if s.m.pg.GetBool(settingProxyPool, false) && input.TaskID == "" {
		writeErr(w, 400, "task_id is required while proxy pool is enabled")
		return
	}
	var taskID *int64
	// Registering the running context is serialized with task lifecycle commits,
	// so a pause cannot land between validation and cancellation registration.
	if input.TaskID != "" {
		s.m.taskStateMu.Lock()
		defer s.m.taskStateMu.Unlock()
	}
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
		if task.Paused || isTerminalStatus(task.Status) {
			writeErr(w, 409, "task is paused or terminal")
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
	proxyURL, caFile := s.taskProxyAddress(input.TaskID)
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
	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Minute)
	if taskID != nil {
		s.templateRunsMu.Lock()
		if s.templateTaskRuns[input.TaskID] == nil {
			s.templateTaskRuns[input.TaskID] = map[int64]context.CancelFunc{}
		}
		s.templateTaskRuns[input.TaskID][run.ID] = cancel
		s.templateRunsMu.Unlock()
	}
	go func() {
		defer func() { <-s.templateRunSlots }()
		defer cancel()
		defer s.unregisterTaskTemplateRun(input.TaskID, run.ID)
		matches, runErr := scantemplate.RunWithProxy(ctx, run.TemplateContent, run.Target, proxyURL, caFile)
		if input.TaskID != "" {
			s.m.taskStateMu.Lock()
			defer s.m.taskStateMu.Unlock()
		}
		if ctx.Err() != nil {
			runErr = ctx.Err()
			matches = nil
		}
		persist, cancelPersist := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelPersist()
		if err := s.m.pg.FinishScanTemplateRun(persist, run, matches, runErr); err != nil {
			log.Printf("template run %d completion: %v", run.ID, err)
		}
	}()
	writeJSON(w, 202, run)
}

func (s *Server) cancelTaskTemplateRuns(taskID string) {
	s.templateRunsMu.Lock()
	defer s.templateRunsMu.Unlock()
	for _, cancel := range s.templateTaskRuns[taskID] {
		cancel()
	}
}

func (s *Server) unregisterTaskTemplateRun(taskID string, id int64) {
	s.templateRunsMu.Lock()
	defer s.templateRunsMu.Unlock()
	delete(s.templateTaskRuns[taskID], id)
	if len(s.templateTaskRuns[taskID]) == 0 {
		delete(s.templateTaskRuns, taskID)
	}
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
