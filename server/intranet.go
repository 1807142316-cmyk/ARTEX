package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/Autumn-27/artex/db"
)

// registerIntranetContext registers the task-scoped intranet context endpoint.
//
// The endpoint is read-only: it reports what the worker WOULD be given for this
// task, so the operator can see the same view the model sees. Execution is a
// separate concern handled by the task-scoped tools.
func (s *Server) registerIntranetContext(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/tasks/{id}/intranet-context", s.taskIntranetContext)
}

// taskIntranetResolver is the agent-side seam: it answers "does this task have a
// usable intranet context right now?" for the worker prompt block and the two
// task-scoped tools. A storage error is reported as unavailable rather than
// propagating, because a failing database must not silently hand the worker a
// stale context.
func (s *Server) taskIntranetResolver(ctx context.Context, taskID int64) (db.IntranetContext, bool) {
	ictx, err := s.m.pg.TaskIntranetContext(ctx, taskID)
	if err != nil {
		return db.IntranetUnavailable(db.IntranetReasonIntegrationUnreachable), false
	}
	return ictx, ictx.Available
}

func (s *Server) taskIntranetContext(w http.ResponseWriter, r *http.Request) {
	taskID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || taskID < 1 {
		writeErr(w, 400, "invalid task id")
		return
	}
	// Unknown tasks are a 404, not an empty context: the difference between
	// "this task has no intranet" and "this task does not exist" matters to
	// anyone reading the panel.
	if _, ok := s.m.Task(r.PathValue("id")); !ok {
		writeErr(w, 404, "task not found")
		return
	}
	ctx, err := s.m.pg.TaskIntranetContext(r.Context(), taskID)
	if errors.Is(err, db.ErrInventoryReference) {
		writeErr(w, 404, "task not found")
		return
	}
	if err != nil {
		writeErr(w, 500, "intranet context unavailable")
		return
	}
	writeJSON(w, 200, ctx)
}
