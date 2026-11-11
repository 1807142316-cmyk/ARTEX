package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Autumn-27/artex/db"
)

func (s *Server) registerSessionInventory(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/session-inventory/observations", s.observeInventorySession)
	mux.HandleFunc("GET /api/session-inventory/sessions", s.listInventorySessions)
	mux.HandleFunc("GET /api/session-inventory/sessions/{id}", s.getInventorySession)
	mux.HandleFunc("POST /api/session-inventory/sessions/{id}/annotate", s.annotateInventorySession)
	mux.HandleFunc("POST /api/session-inventory/sessions/{id}/disconnect", s.disconnectInventorySession)
}
func inventoryJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writeErr(w, 400, "invalid inventory JSON: "+err.Error())
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeErr(w, 400, "expected one JSON document")
		return false
	}
	return true
}
func inventoryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		writeErr(w, 404, "inventory record not found")
	case errors.Is(err, db.ErrInventoryConflict):
		writeErr(w, 409, err.Error())
	case errors.Is(err, db.ErrInventoryReference):
		writeErr(w, 400, err.Error())
	default:
		writeErr(w, 500, "inventory storage unavailable")
	}
}
func validInventoryText(text string, max int) bool {
	return len(text) <= max && strings.IndexFunc(text, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }) < 0
}
func (s *Server) observeInventorySession(w http.ResponseWriter, r *http.Request) {
	var input db.SessionObservation
	if !inventoryJSON(w, r, &input) {
		return
	}
	input.Source = strings.TrimSpace(input.Source)
	input.SourceID = strings.TrimSpace(input.SourceID)
	input.Host = strings.TrimSpace(input.Host)
	if input.Source == "" || input.SourceID == "" || !validInventoryText(input.Source, 128) || !validInventoryText(input.SourceID, 256) || input.Sequence < 1 || input.Sequence > 9007199254740991 || (input.Kind != "c2" && input.Kind != "webshell") || (input.State != "connected" && input.State != "disconnected" && input.State != "unknown") {
		writeErr(w, 400, "source, source_id, positive sequence, c2/webshell kind and connected/disconnected/unknown state are required")
		return
	}
	if !validInventoryText(input.ProtocolLabel, 128) || !validInventoryText(input.Host, 256) || !validInventoryText(input.DisconnectReason, 2000) {
		writeErr(w, 400, "inventory fields exceed limits or contain control characters")
		return
	}
	if input.URL != "" {
		parsed, err := url.Parse(input.URL)
		if err != nil || len(input.URL) > 2048 || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			writeErr(w, 400, "url must be HTTP(S) without credentials, query or fragment")
			return
		}
	}
	if input.HeartbeatTTLSeconds == 0 {
		input.HeartbeatTTLSeconds = 120
	}
	if input.HeartbeatTTLSeconds < 1 || input.HeartbeatTTLSeconds > 86400 {
		writeErr(w, 400, "heartbeat_ttl_seconds must be between 1 and 86400")
		return
	}
	if input.HeartbeatAt != nil && input.HeartbeatAt.After(time.Now().Add(30*time.Second)) {
		writeErr(w, 400, "heartbeat_at is in the future")
		return
	}
	result, created, replayed, err := s.m.pg.ObserveSession(r.Context(), input)
	if err != nil {
		inventoryError(w, err)
		return
	}
	status := 200
	if created {
		status = 201
	}
	writeJSON(w, status, map[string]any{"session": result, "replayed": replayed})
}
func inventoryID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeErr(w, 400, "invalid inventory id")
		return 0, false
	}
	return id, true
}
func (s *Server) getInventorySession(w http.ResponseWriter, r *http.Request) {
	id, ok := inventoryID(w, r)
	if !ok {
		return
	}
	item, audit, err := s.m.pg.GetInventorySession(r.Context(), id)
	if err != nil {
		inventoryError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"session": item, "audit": audit, "capabilities": []string{"read_status", "annotate_inventory", "disconnect_inventory"}})
}
func (s *Server) listInventorySessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := db.InventoryFilter{Source: q.Get("source"), Kind: q.Get("kind"), State: q.Get("state"), Query: q.Get("q"), Page: findingPaginationParam(q.Get("page"), 1, 1000000), Limit: findingPaginationParam(q.Get("limit"), 20, 100)}
	if raw := q.Get("task_id"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id < 1 {
			writeErr(w, 400, "invalid task_id")
			return
		}
		f.TaskID = &id
	}
	if len(f.Query) > 256 || len(f.Source) > 128 {
		writeErr(w, 400, "filter exceeds limit")
		return
	}
	items, total, err := s.m.pg.ListInventorySessions(r.Context(), f)
	if err != nil {
		inventoryError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "page": f.Page, "limit": f.Limit, "mode": "observer"})
}
func (s *Server) annotateInventorySession(w http.ResponseWriter, r *http.Request) {
	s.inventoryAction(w, r, "annotate")
}
func (s *Server) disconnectInventorySession(w http.ResponseWriter, r *http.Request) {
	s.inventoryAction(w, r, "disconnect")
}
func (s *Server) inventoryAction(w http.ResponseWriter, r *http.Request, action string) {
	id, ok := inventoryID(w, r)
	if !ok {
		return
	}
	var input struct {
		Detail string `json:"detail"`
	}
	if !inventoryJSON(w, r, &input) {
		return
	}
	input.Detail = strings.TrimSpace(input.Detail)
	if input.Detail == "" || !validInventoryText(input.Detail, 2000) {
		writeErr(w, 400, "detail is required and limited to 2000 bytes")
		return
	}
	result, err := s.m.pg.AnnotateInventorySession(r.Context(), id, action, input.Detail)
	if err != nil {
		inventoryError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
