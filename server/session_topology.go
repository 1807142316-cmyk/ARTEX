package server

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

func (s *Server) registerSessionTopology(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/session-inventory/nodes", s.saveInventoryNode)
	mux.HandleFunc("GET /api/session-inventory/nodes/{id}", s.inventoryNodeDetail)
	mux.HandleFunc("POST /api/session-inventory/edges", s.saveInventoryEdge)
	mux.HandleFunc("GET /api/session-inventory/edges/{id}/audit", s.inventoryEdgeAudit)
	mux.HandleFunc("GET /api/session-inventory/topology", s.inventoryTopology)
}

func (s *Server) inventoryEdgeAudit(w http.ResponseWriter, r *http.Request) {
	id, ok := inventoryID(w, r)
	if !ok {
		return
	}
	items, err := s.m.pg.InventoryEdgeAudit(r.Context(), id)
	if err != nil {
		inventoryError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) saveInventoryNode(w http.ResponseWriter, r *http.Request) {
	var n db.InventoryNode
	if !inventoryJSON(w, r, &n) {
		return
	}
	n.ExternalRef = strings.TrimSpace(n.ExternalRef)
	n.Label = strings.TrimSpace(n.Label)
	if n.ID != 0 || n.Ref != "" || !n.UpdatedAt.IsZero() {
		writeErr(w, 400, "id/ref/updated_at are server managed")
		return
	}
	if n.ExternalRef == "" || n.Label == "" || !validInventoryText(n.ExternalRef, 256) || !validInventoryText(n.Label, 256) || !validInventoryText(n.Address, 256) || (n.State != "active" && n.State != "invalid" && n.State != "expired") {
		writeErr(w, 400, "external_ref, label and active/invalid/expired state are required")
		return
	}
	switch n.Kind {
	case "host":
		if n.Address != "" && net.ParseIP(n.Address) == nil {
			writeErr(w, 400, "host address must be an IP address")
			return
		}
	case "subnet":
		_, network, err := net.ParseCIDR(n.Address)
		if err != nil {
			writeErr(w, 400, "subnet address must be CIDR")
			return
		}
		n.Address = network.String()
	case "tunnel", "credential_ref":
		if n.Address != "" {
			writeErr(w, 400, "tunnel/credential nodes accept metadata references only, no address or secret")
			return
		}
	default:
		writeErr(w, 400, "kind must be host/subnet/tunnel/credential_ref")
		return
	}
	saved, created, err := s.m.pg.SaveInventoryNode(r.Context(), n)
	if err != nil {
		inventoryError(w, err)
		return
	}
	status := 200
	if created {
		status = 201
	}
	writeJSON(w, status, saved)
}
func (s *Server) inventoryNodeDetail(w http.ResponseWriter, r *http.Request) {
	id, ok := inventoryID(w, r)
	if !ok {
		return
	}
	n, audit, err := s.m.pg.InventoryNodeDetail(r.Context(), id)
	if err != nil {
		inventoryError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"node": n, "audit": audit})
}
func (s *Server) saveInventoryEdge(w http.ResponseWriter, r *http.Request) {
	var e db.InventoryEdge
	if !inventoryJSON(w, r, &e) {
		return
	}
	if e.ID != 0 || e.EffectiveState != "" || !e.UpdatedAt.IsZero() || e.SourceRef == e.TargetRef || !validInventoryText(e.SourceRef, 64) || !validInventoryText(e.TargetRef, 64) || !validInventoryText(e.Note, 2000) || (e.State != "active" && e.State != "inactive") {
		writeErr(w, 400, "invalid relationship metadata")
		return
	}
	saved, created, err := s.m.pg.SaveInventoryEdge(r.Context(), e)
	if err != nil {
		inventoryError(w, err)
		return
	}
	status := 200
	if created {
		status = 201
	}
	writeJSON(w, status, saved)
}
func (s *Server) inventoryTopology(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if len(q) > 256 {
		writeErr(w, 400, "query exceeds limit")
		return
	}
	var task *int64
	if raw := r.URL.Query().Get("task_id"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id < 1 {
			writeErr(w, 400, "invalid task_id")
			return
		}
		task = &id
	}
	graph, err := s.m.pg.InventoryTopology(r.Context(), q, task)
	if err != nil {
		inventoryError(w, err)
		return
	}
	writeJSON(w, 200, graph)
}
