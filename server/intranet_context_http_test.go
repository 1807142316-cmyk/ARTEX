package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// intranetHarness drives the real HTTP surface with an authenticated JWT against
// the configured PostgreSQL database. Every assertion goes through the API; the
// only direct database access is unique-suffix fixture naming.
type intranetHarness struct {
	t       *testing.T
	handler http.Handler
	token   string
	prefix  string
}

func newIntranetHarness(t *testing.T) *intranetHarness {
	t.Helper()
	m := newParityTestManager(t)
	t.Cleanup(func() { _ = m.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	return &intranetHarness{t: t, handler: s.Handler(), token: token, prefix: fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())}
}

// do issues one authenticated request and returns the status plus the decoded body.
func (h *intranetHarness) do(method, path string, payload, out any) int {
	h.t.Helper()
	var body bytes.Buffer
	if payload != nil {
		if err := json.NewEncoder(&body).Encode(payload); err != nil {
			h.t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, path, &body)
	r.Header.Set("Authorization", "Bearer "+h.token)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	if out != nil && w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			h.t.Fatalf("%s %s: decode %s: %v", method, path, w.Body, err)
		}
	}
	return w.Code
}

// must runs a request and fails the test unless it succeeded.
func (h *intranetHarness) must(method, path string, payload, out any) {
	h.t.Helper()
	if code := h.do(method, path, payload, out); code < 200 || code >= 300 {
		h.t.Fatalf("%s %s: %d", method, path, code)
	}
}

// task creates a task and returns its numeric id.
func (h *intranetHarness) task(name string) int64 {
	h.t.Helper()
	var created struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	h.must("POST", "/api/tasks", map[string]any{
		"name":        h.prefix + " " + name,
		"description": "intranet context fixture",
		"goal":        "record explicit topology relationships",
	}, &created)
	id, err := strconv.ParseInt(created.ID, 10, 64)
	if err != nil {
		h.t.Fatalf("task id %q: %v", created.ID, err)
	}
	h.t.Cleanup(func() { h.do("DELETE", "/api/tasks/"+created.ID, nil, nil) })
	return id
}

// observer records one connected inventory session owned by taskID.
func (h *intranetHarness) session(taskID int64, name string, state string, ttl int) int64 {
	h.t.Helper()
	var created struct {
		Session struct {
			ID int64 `json:"id"`
		} `json:"session"`
	}
	payload := map[string]any{
		"source": h.prefix + "-" + name, "source_id": "observed-1", "sequence": 1,
		"kind": "c2", "protocol_label": "http_observer", "state": state,
		"host": name + ".internal", "url": "https://" + name + ".internal/status",
		"heartbeat_ttl_seconds": ttl, "task_id": taskID,
	}
	h.must("POST", "/api/session-inventory/observations", payload, &created)
	return created.Session.ID
}

// node registers one topology node owned by taskID.
func (h *intranetHarness) node(taskID int64, payload map[string]any) int64 {
	h.t.Helper()
	body := map[string]any{"state": "active", "task_id": taskID}
	for k, v := range payload {
		body[k] = v
	}
	var created struct {
		ID int64 `json:"id"`
	}
	h.must("POST", "/api/session-inventory/nodes", body, &created)
	return created.ID
}

// edge links two refs and returns the edge id.
func (h *intranetHarness) edge(source, target, relation string) int64 {
	h.t.Helper()
	var created struct {
		ID int64 `json:"id"`
	}
	h.must("POST", "/api/session-inventory/edges", map[string]any{
		"source_ref": source, "target_ref": target, "relation": relation, "state": "active",
	}, &created)
	return created.ID
}

type topologyNode struct {
	Ref            string  `json:"ref"`
	ID             int64   `json:"id"`
	Kind           string  `json:"kind"`
	Label          string  `json:"label"`
	State          string  `json:"state"`
	EffectiveState string  `json:"effective_state"`
	ExpiresAt      *string `json:"expires_at"`
}

type topologyEdge struct {
	ID             int64  `json:"id"`
	SourceRef      string `json:"source_ref"`
	TargetRef      string `json:"target_ref"`
	Relation       string `json:"relation"`
	State          string `json:"state"`
	EffectiveState string `json:"effective_state"`
	Reason         string `json:"reason"`
}

type topologySummary struct {
	Hosts       int `json:"hosts"`
	Subnets     int `json:"subnets"`
	Sessions    int `json:"sessions"`
	Tunnels     int `json:"tunnels"`
	Credentials int `json:"credentials"`
	ActiveEdges int `json:"active_edges"`
	Inactive    int `json:"inactive_edges"`
}

type topologyEmpty struct {
	Nodes       bool `json:"nodes"`
	Edges       bool `json:"edges"`
	Sessions    bool `json:"sessions"`
	Tunnels     bool `json:"tunnels"`
	Credentials bool `json:"credentials"`
}

type topologyGraph struct {
	Nodes   []topologyNode  `json:"nodes"`
	Edges   []topologyEdge  `json:"edges"`
	Summary topologySummary `json:"summary"`
	Empty   topologyEmpty   `json:"empty"`
	Mode    string          `json:"mode"`
}

// graph fetches the topology for a task and indexes the result for assertions.
func (h *intranetHarness) graph(taskID int64) (topologyGraph, map[string]topologyNode, map[int64]topologyEdge) {
	h.t.Helper()
	var g topologyGraph
	h.must("GET", fmt.Sprintf("/api/session-inventory/topology?task_id=%d", taskID), nil, &g)
	nodes := map[string]topologyNode{}
	for _, n := range g.Nodes {
		nodes[n.Ref] = n
	}
	edges := map[int64]topologyEdge{}
	for _, e := range g.Edges {
		edges[e.ID] = e
	}
	return g, nodes, edges
}

// TestTopologyExpiresCredentialsAndExplainsInactiveEdges covers the reason codes
// that come from node-level state: a credential past expires_at becomes expired
// even though its stored state is active, and the edge that references it turns
// inactive with a machine-readable reason.
func TestTopologyExpiresCredentialsAndExplainsInactiveEdges(t *testing.T) {
	h := newIntranetHarness(t)
	taskID := h.task("credential expiry")
	sessionID := h.session(taskID, "app", "connected", 3600)
	hostID := h.node(taskID, map[string]any{"kind": "host", "external_ref": h.prefix + "-host", "label": "app host", "address": "10.10.0.5"})
	tunnelID := h.node(taskID, map[string]any{"kind": "tunnel", "external_ref": h.prefix + "-tunnel", "label": "socks tunnel"})
	credID := h.node(taskID, map[string]any{
		"kind": "credential_ref", "external_ref": h.prefix + "-cred", "label": "svc account",
		"expires_at": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	})
	liveCredID := h.node(taskID, map[string]any{
		"kind": "credential_ref", "external_ref": h.prefix + "-cred-live", "label": "ops account",
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})

	sessionRef := fmt.Sprintf("session:%d", sessionID)
	hostEdge := h.edge(sessionRef, fmt.Sprintf("node:%d", hostID), "hosted_on")
	credEdge := h.edge(sessionRef, fmt.Sprintf("node:%d", credID), "credential_reference")
	liveEdge := h.edge(sessionRef, fmt.Sprintf("node:%d", liveCredID), "credential_reference")
	tunnelEdge := h.edge(sessionRef, fmt.Sprintf("node:%d", tunnelID), "tunnel_metadata")

	_, nodes, edges := h.graph(taskID)

	if got := nodes[fmt.Sprintf("node:%d", credID)].EffectiveState; got != "expired" {
		t.Fatalf("expired credential effective_state=%q", got)
	}
	if got := nodes[fmt.Sprintf("node:%d", liveCredID)].EffectiveState; got != "active" {
		t.Fatalf("live credential effective_state=%q", got)
	}
	if got := edges[hostEdge]; got.EffectiveState != "active" || got.Reason != "" {
		t.Fatalf("host edge=%+v", got)
	}
	if got := edges[credEdge]; got.EffectiveState != "inactive" || got.Reason != "credential_expired" {
		t.Fatalf("expired credential edge=%+v", got)
	}
	if got := edges[liveEdge]; got.EffectiveState != "active" || got.Reason != "" {
		t.Fatalf("live credential edge=%+v", got)
	}
	if got := edges[tunnelEdge]; got.EffectiveState != "active" || got.Reason != "" {
		t.Fatalf("active tunnel edge=%+v", got)
	}
}

// TestTopologyDerivesReasonsFromSessionAndTunnelState covers the reasons that
// come from the session heartbeat and from the tunnel node, plus the summary
// counters and the explicit empty-state flags for a task with no graph.
func TestTopologyDerivesReasonsFromSessionAndTunnelState(t *testing.T) {
	h := newIntranetHarness(t)
	taskID := h.task("session and tunnel state")

	// Stale session: reported connected with a 1s TTL, then aged past it.
	staleID := h.session(taskID, "stale-svc", "connected", 1)
	deadID := h.session(taskID, "dead-svc", "disconnected", 3600)
	liveID := h.session(taskID, "live-svc", "connected", 3600)
	time.Sleep(1100 * time.Millisecond)

	hostID := h.node(taskID, map[string]any{"kind": "host", "external_ref": h.prefix + "-host-a", "label": "host a", "address": "10.10.1.5"})
	tunnelID := h.node(taskID, map[string]any{"kind": "tunnel", "external_ref": h.prefix + "-tunnel-b", "label": "tunnel b"})
	subnetID := h.node(taskID, map[string]any{"kind": "subnet", "external_ref": h.prefix + "-subnet", "label": "10.10.1.0/24", "address": "10.10.1.0/24", "state": "invalid"})

	staleEdge := h.edge(fmt.Sprintf("session:%d", staleID), fmt.Sprintf("node:%d", hostID), "hosted_on")
	deadEdge := h.edge(fmt.Sprintf("session:%d", deadID), fmt.Sprintf("node:%d", hostID), "hosted_on")
	liveEdge := h.edge(fmt.Sprintf("session:%d", liveID), fmt.Sprintf("node:%d", hostID), "hosted_on")
	tunnelEdge := h.edge(fmt.Sprintf("session:%d", liveID), fmt.Sprintf("node:%d", tunnelID), "tunnel_metadata")
	subnetEdge := h.edge(fmt.Sprintf("node:%d", hostID), fmt.Sprintf("node:%d", subnetID), "member_of")

	// Deactivating the tunnel node must flip the tunnel edge inactive.
	h.must("POST", "/api/session-inventory/nodes", map[string]any{
		"kind": "tunnel", "external_ref": h.prefix + "-tunnel-b", "label": "tunnel b", "state": "invalid",
		"task_id": taskID,
	}, nil)

	g, nodes, edges := h.graph(taskID)

	if got := edges[staleEdge].Reason; got != "session_stale" {
		t.Fatalf("stale session edge reason=%q", got)
	}
	if got := edges[deadEdge].Reason; got != "session_disconnected" {
		t.Fatalf("disconnected session edge reason=%q", got)
	}
	if got := edges[liveEdge]; got.EffectiveState != "active" || got.Reason != "" {
		t.Fatalf("live session edge=%+v", got)
	}
	if got := edges[tunnelEdge].Reason; got != "tunnel_inactive" {
		t.Fatalf("tunnel edge reason=%q", got)
	}
	if got := edges[subnetEdge].Reason; got != "node_invalid" {
		t.Fatalf("invalid subnet edge reason=%q", got)
	}
	if got := nodes[fmt.Sprintf("session:%d", staleID)].EffectiveState; got != "stale" {
		t.Fatalf("stale session effective_state=%q", got)
	}
	if got := nodes[fmt.Sprintf("node:%d", subnetID)].EffectiveState; got != "invalid" {
		t.Fatalf("invalid subnet effective_state=%q", got)
	}

	if g.Summary.Sessions != 3 {
		t.Fatalf("summary sessions=%d", g.Summary.Sessions)
	}
	if g.Summary.Hosts != 1 || g.Summary.Subnets != 1 || g.Summary.Tunnels != 1 {
		t.Fatalf("summary kinds=%+v", g.Summary)
	}
	if g.Summary.ActiveEdges != 1 {
		t.Fatalf("summary active_edges=%d", g.Summary.ActiveEdges)
	}
	if g.Summary.Inactive != 4 {
		t.Fatalf("summary inactive_edges=%d", g.Summary.Inactive)
	}
	if g.Empty.Nodes || g.Empty.Edges {
		t.Fatalf("populated graph reported empty: %+v", g.Empty)
	}

	// A task with nothing recorded must say so explicitly rather than look empty.
	blankTask := h.task("no topology")
	blank, _, _ := h.graph(blankTask)
	if blank.Summary.ActiveEdges != 0 || blank.Summary.Sessions != 0 {
		t.Fatalf("blank summary=%+v", blank.Summary)
	}
	if !blank.Empty.Nodes || !blank.Empty.Edges || !blank.Empty.Sessions || !blank.Empty.Credentials || !blank.Empty.Tunnels {
		t.Fatalf("blank empty flags=%+v", blank.Empty)
	}
}

// TestTopologyTaskFilterRejectsCrossTaskEdges covers the ownership reason: an
// edge that was valid when written stops being valid if a node is later moved to
// another task. The task filter must return only its own nodes, and the dangling
// relationship must surface as inactive with task_mismatch rather than vanish.
func TestTopologyTaskFilterRejectsCrossTaskEdges(t *testing.T) {
	h := newIntranetHarness(t)
	ownerTask := h.task("owner")
	otherTask := h.task("other")

	sessionID := h.session(ownerTask, "pivot", "connected", 3600)
	hostExternal := h.prefix + "-shared-host"
	hostID := h.node(ownerTask, map[string]any{"kind": "host", "external_ref": hostExternal, "label": "shared host", "address": "10.10.2.9"})
	edgeID := h.edge(fmt.Sprintf("session:%d", sessionID), fmt.Sprintf("node:%d", hostID), "hosted_on")

	// Creating an edge across tasks is refused outright: no silent cross-task link.
	if code := h.do("POST", "/api/session-inventory/edges", map[string]any{
		"source_ref": fmt.Sprintf("session:%d", sessionID), "target_ref": fmt.Sprintf("node:%d", h.node(otherTask, map[string]any{"kind": "host", "external_ref": h.prefix + "-foreign", "label": "foreign host", "address": "10.10.3.9"})),
		"relation": "hosted_on", "state": "active",
	}, nil); code != 400 {
		t.Fatalf("cross-task edge status=%d", code)
	}

	// Re-registering the host under the other task keeps the same node identity.
	h.must("POST", "/api/session-inventory/nodes", map[string]any{
		"kind": "host", "external_ref": hostExternal, "label": "shared host", "address": "10.10.2.9",
		"state": "active", "task_id": otherTask,
	}, nil)

	owned, nodes, edges := h.graph(ownerTask)
	if got := edges[edgeID]; got.EffectiveState != "inactive" || got.Reason != "task_mismatch" {
		t.Fatalf("reassigned node edge=%+v", got)
	}
	if _, present := nodes[fmt.Sprintf("node:%d", hostID)]; present {
		t.Fatalf("owner task graph leaked a node reassigned to another task")
	}
	if len(owned.Nodes) != 1 || owned.Nodes[0].Kind != "session" {
		t.Fatalf("owner task nodes=%+v", owned.Nodes)
	}
	if owned.Summary.Hosts != 0 || owned.Summary.Sessions != 1 {
		t.Fatalf("owner summary=%+v", owned.Summary)
	}

	foreign, foreignNodes, _ := h.graph(otherTask)
	if _, present := foreignNodes[fmt.Sprintf("session:%d", sessionID)]; present {
		t.Fatalf("other task graph leaked a session it does not own")
	}
	// The shared host plus the node the refused edge tried to introduce.
	if foreign.Summary.Sessions != 0 || foreign.Summary.Hosts != 2 {
		t.Fatalf("other summary=%+v", foreign.Summary)
	}
}

type intranetSessionRef struct {
	ID          int64  `json:"id"`
	Host        string `json:"host"`
	URL         string `json:"url"`
	Protocol    string `json:"protocol"`
	State       string `json:"state"`
	HeartbeatAt string `json:"heartbeat_at"`
}

type intranetCredentialRef struct {
	Ref       string  `json:"ref"`
	Label     string  `json:"label"`
	Scope     string  `json:"scope"`
	State     string  `json:"state"`
	ExpiresAt *string `json:"expires_at"`
}

type intranetContext struct {
	Variant     string                  `json:"variant"`
	Available   bool                    `json:"available"`
	Reason      string                  `json:"reason"`
	Sessions    []intranetSessionRef    `json:"sessions"`
	Credentials []intranetCredentialRef `json:"credentials"`
}

func (h *intranetHarness) intranet(taskID int64) intranetContext {
	h.t.Helper()
	var ctx intranetContext
	h.must("GET", fmt.Sprintf("/api/tasks/%d/intranet-context", taskID), nil, &ctx)
	return ctx
}

// TestIntranetContextRequiresValidSessionAndCredential walks the unavailable
// reasons in order and then shows the available payload. Sessions are the gate:
// a live session with no credential node at all is available (the adapter needs
// none), and a live credential reference is attached as enrichment when present.
func TestIntranetContextRequiresValidSessionAndCredential(t *testing.T) {
	h := newIntranetHarness(t)

	// No session and no credential at all.
	blank := h.task("blank intranet")
	if got := h.intranet(blank); got.Available || got.Reason != "no_session" || got.Variant != "worker" {
		t.Fatalf("blank context=%+v", got)
	}

	// Session present but never usable: reported connected with a 1s TTL.
	staleTask := h.task("stale intranet")
	h.session(staleTask, "stale-only", "connected", 1)
	time.Sleep(1100 * time.Millisecond)
	stale := h.intranet(staleTask)
	if stale.Available || stale.Reason != "session_stale" || stale.Variant != "worker" {
		t.Fatalf("stale context=%+v", stale)
	}
	if len(stale.Sessions) != 0 || len(stale.Credentials) != 0 {
		t.Fatalf("stale context leaked entries: %+v", stale)
	}

	// Live session with no credential recorded at all: available. The
	// http_phpcmd adapter needs no credential_ref node, so requiring one made
	// every session-only task permanently unusable.
	noCredTask := h.task("no credential")
	noCredSession := h.session(noCredTask, "no-cred-svc", "connected", 3600)
	noCred := h.intranet(noCredTask)
	if !noCred.Available || noCred.Reason != "" || noCred.Variant != "worker_intranet" {
		t.Fatalf("no-credential context=%+v", noCred)
	}
	if len(noCred.Sessions) != 1 || noCred.Sessions[0].ID != noCredSession {
		t.Fatalf("no-credential sessions=%+v", noCred.Sessions)
	}
	if len(noCred.Credentials) != 0 {
		t.Fatalf("no-credential context invented credentials: %+v", noCred.Credentials)
	}

	// Live session, but the only credential for this task is expired: the
	// context stays available and the expired credential is simply left out.
	expiredTask := h.task("expired credential")
	expiredSession := h.session(expiredTask, "expired-cred-svc", "connected", 3600)
	h.node(expiredTask, map[string]any{
		"kind": "credential_ref", "external_ref": h.prefix + "-expired", "label": "old account", "scope": "domain",
		"expires_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
	})
	expired := h.intranet(expiredTask)
	if !expired.Available || expired.Reason != "" || expired.Variant != "worker_intranet" {
		t.Fatalf("expired context=%+v", expired)
	}
	if len(expired.Sessions) != 1 || expired.Sessions[0].ID != expiredSession {
		t.Fatalf("expired-credential sessions=%+v", expired.Sessions)
	}
	if len(expired.Credentials) != 0 {
		t.Fatalf("expired credential was returned: %+v", expired.Credentials)
	}

	// Live session + live credential: the worker_intranet variant becomes usable.
	readyTask := h.task("ready intranet")
	sessionID := h.session(readyTask, "ready-svc", "connected", 3600)
	credID := h.node(readyTask, map[string]any{
		"kind": "credential_ref", "external_ref": h.prefix + "-ready-cred", "label": "svc account", "scope": "host",
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	ready := h.intranet(readyTask)
	if !ready.Available || ready.Reason != "" || ready.Variant != "worker_intranet" {
		t.Fatalf("ready context=%+v", ready)
	}
	if len(ready.Sessions) != 1 || ready.Sessions[0].ID != sessionID {
		t.Fatalf("ready sessions=%+v", ready.Sessions)
	}
	if ready.Sessions[0].Host != "ready-svc.internal" || ready.Sessions[0].Protocol != "http_observer" || ready.Sessions[0].State != "connected" {
		t.Fatalf("ready session fields=%+v", ready.Sessions[0])
	}
	if ready.Sessions[0].HeartbeatAt == "" {
		t.Fatalf("ready session missing heartbeat_at")
	}
	wantRef := fmt.Sprintf("node:%d", credID)
	if len(ready.Credentials) != 1 || ready.Credentials[0].Ref != wantRef || ready.Credentials[0].Label != "svc account" || ready.Credentials[0].Scope != "host" || ready.Credentials[0].State != "active" {
		t.Fatalf("ready credentials=%+v", ready.Credentials)
	}
	if ready.Credentials[0].ExpiresAt == nil {
		t.Fatalf("ready credential missing expires_at")
	}

	// Cross-task: another task's context never shows this task's session.
	other := h.intranet(h.task("someone else"))
	if other.Available || len(other.Sessions) != 0 {
		t.Fatalf("cross-task context leaked: %+v", other)
	}

	// Unknown task and missing auth are ordinary HTTP errors, not empty contexts.
	if code := h.do("GET", "/api/tasks/999999999/intranet-context", nil, nil); code != 404 {
		t.Fatalf("unknown task status=%d", code)
	}
	unauth := httptest.NewRequest("GET", fmt.Sprintf("/api/tasks/%d/intranet-context", readyTask), nil)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, unauth)
	if rec.Code != 401 {
		t.Fatalf("unauthorized status=%d", rec.Code)
	}
}

// TestSessionListFiltersFollowEffectiveStateAndTopology covers the other half of
// "state change updates topology and filters": the list filter's effective state
// must agree with the graph, an operator disconnect must flip that session's
// edges to session_disconnected, and the session must leave the intranet context.
func TestSessionListFiltersFollowEffectiveStateAndTopology(t *testing.T) {
	h := newIntranetHarness(t)
	taskID := h.task("filters follow state")
	staleID := h.session(taskID, "aging", "connected", 1)
	liveID := h.session(taskID, "healthy", "connected", 3600)
	hostID := h.node(taskID, map[string]any{"kind": "host", "external_ref": h.prefix + "-filter-host", "label": "filter host", "address": "10.20.0.7"})
	liveEdge := h.edge(fmt.Sprintf("session:%d", liveID), fmt.Sprintf("node:%d", hostID), "hosted_on")
	time.Sleep(1100 * time.Millisecond)

	var staleList struct {
		Items []struct {
			ID             int64  `json:"id"`
			EffectiveState string `json:"effective_state"`
		} `json:"items"`
	}
	h.must("GET", fmt.Sprintf("/api/session-inventory/sessions?state=stale&task_id=%d", taskID), nil, &staleList)
	if len(staleList.Items) != 1 || staleList.Items[0].ID != staleID {
		t.Fatalf("stale filter=%+v", staleList.Items)
	}
	var liveList struct {
		Items []struct {
			ID int64 `json:"id"`
		} `json:"items"`
	}
	h.must("GET", fmt.Sprintf("/api/session-inventory/sessions?state=connected&task_id=%d", taskID), nil, &liveList)
	if len(liveList.Items) != 1 || liveList.Items[0].ID != liveID {
		t.Fatalf("connected filter=%+v", liveList.Items)
	}

	// While connected, the live session's edge is active and its context usable.
	if _, _, edges := h.graph(taskID); edges[liveEdge].EffectiveState != "active" {
		t.Fatalf("pre-disconnect edge=%+v", edges[liveEdge])
	}

	h.must("POST", fmt.Sprintf("/api/session-inventory/sessions/%d/disconnect", liveID), map[string]any{"detail": "operator ended the session"}, nil)

	_, _, edges := h.graph(taskID)
	if got := edges[liveEdge]; got.EffectiveState != "inactive" || got.Reason != "session_disconnected" {
		t.Fatalf("post-disconnect edge=%+v", got)
	}
	// A stale session and a disconnected one leave nothing usable for the task.
	if got := h.intranet(taskID); got.Available || got.Reason != "session_stale" {
		t.Fatalf("post-disconnect context=%+v", got)
	}
	var disconnected struct {
		Items []struct {
			ID             int64  `json:"id"`
			EffectiveState string `json:"effective_state"`
		} `json:"items"`
	}
	h.must("GET", fmt.Sprintf("/api/session-inventory/sessions?state=disconnected&task_id=%d", taskID), nil, &disconnected)
	if len(disconnected.Items) != 1 || disconnected.Items[0].ID != liveID {
		t.Fatalf("disconnected filter=%+v", disconnected.Items)
	}
}

// TestServerIntranetResolverFeedsWorkerSeam closes the loop between the HTTP
// resolver and the agent seam: the same function that answers the API is the one
// wired into the per-task worker, so what the panel shows is what the worker sees.
// It deliberately avoids building a full agent bundle (which needs an LLM
// provider) by calling the resolver directly on the wired field.
func TestServerIntranetResolverFeedsWorkerSeam(t *testing.T) {
	m := newParityTestManager(t)
	defer func() { _ = m.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	h := &intranetHarness{t: t, handler: s.Handler(), token: token, prefix: fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())}

	taskID := h.task("worker seam")
	h.session(taskID, "seam-svc", "connected", 3600)
	h.node(taskID, map[string]any{
		"kind": "credential_ref", "external_ref": h.prefix + "-seam-cred", "label": "seam account", "scope": "host",
	})

	// The resolver wired into task_llm's worker reports the same context.
	ictx, ok := s.taskIntranetResolver(ctx, taskID)
	if !ok || !ictx.Available || ictx.Variant != "worker_intranet" || len(ictx.Sessions) != 1 || len(ictx.Credentials) != 1 {
		t.Fatalf("resolver context=%+v ok=%v", ictx, ok)
	}
	// And the HTTP endpoint agrees field for field on what it exposes.
	overHTTP := h.intranet(taskID)
	if overHTTP.Available != ictx.Available || overHTTP.Variant != ictx.Variant {
		t.Fatalf("http=%+v resolver=%+v", overHTTP, ictx)
	}
	if len(overHTTP.Sessions) != len(ictx.Sessions) || len(overHTTP.Credentials) != len(ictx.Credentials) {
		t.Fatalf("http sizes=%d/%d resolver sizes=%d/%d", len(overHTTP.Sessions), len(overHTTP.Credentials), len(ictx.Sessions), len(ictx.Credentials))
	}
	if overHTTP.Sessions[0].ID != ictx.Sessions[0].ID || overHTTP.Credentials[0].Ref != ictx.Credentials[0].Ref {
		t.Fatalf("http entries=%+v/%+v resolver entries=%+v/%+v", overHTTP.Sessions[0], overHTTP.Credentials[0], ictx.Sessions[0], ictx.Credentials[0])
	}

	// A task with nothing recorded resolves unavailable, not an error.
	empty, ok := s.taskIntranetResolver(ctx, h.task("worker seam empty"))
	if ok || empty.Available || empty.Reason != "no_session" {
		t.Fatalf("empty resolver=%+v ok=%v", empty, ok)
	}
}

// TestInventoryNodeWritesRejectCredentialOnlyFields keeps derived and
// credential-only fields honest: expires_at/scope on a non-credential node, and a
// client-supplied derived state on an edge, are refused instead of dropped.
func TestInventoryNodeWritesRejectCredentialOnlyFields(t *testing.T) {
	h := newIntranetHarness(t)
	taskID := h.task("node field validation")
	base := map[string]any{"kind": "host", "external_ref": h.prefix + "-field-host", "label": "field host", "address": "10.30.0.1", "task_id": taskID}

	withExpiry := map[string]any{}
	for k, v := range base {
		withExpiry[k] = v
	}
	withExpiry["expires_at"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if code := h.do("POST", "/api/session-inventory/nodes", withExpiry, nil); code != 400 {
		t.Fatalf("host with expires_at status=%d", code)
	}
	withScope := map[string]any{}
	for k, v := range base {
		withScope[k] = v
	}
	withScope["scope"] = "domain"
	if code := h.do("POST", "/api/session-inventory/nodes", withScope, nil); code != 400 {
		t.Fatalf("host with scope status=%d", code)
	}

	sessionID := h.session(taskID, "field-svc", "connected", 3600)
	if code := h.do("POST", "/api/session-inventory/edges", map[string]any{
		"source_ref": fmt.Sprintf("session:%d", sessionID), "target_ref": fmt.Sprintf("node:%d", h.node(taskID, map[string]any{"kind": "host", "external_ref": h.prefix + "-field-host-2", "label": "h2", "address": "10.30.0.2"})),
		"relation": "hosted_on", "state": "active", "reason": "session_stale",
	}, nil); code != 400 {
		t.Fatalf("client-supplied reason status=%d", code)
	}
}

// TestIntranetContextReportsIntegrationUnreachable covers the last contract
// reason: when the platform cannot read its own intranet integration, the answer
// is an explicit unavailability state the panel can display — not a 500 and not a
// misleading no_session. A closed pool is the honest way to produce that failure.
func TestIntranetContextReportsIntegrationUnreachable(t *testing.T) {
	m := newParityTestManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	h := &intranetHarness{t: t, handler: s.Handler(), token: token, prefix: fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())}
	taskID := h.task("unreachable integration")
	// The task handle is cached at creation, so /api/tasks/{id}/intranet-context
	// still resolves the task while the database underneath is gone.
	if err := m.pg.Close(); err != nil {
		t.Fatalf("close pool: %v", err)
	}
	defer func() { _ = m.Close() }()

	got := h.intranet(taskID)
	if got.Available || got.Reason != "integration_unreachable" || got.Variant != "worker" {
		t.Fatalf("unreachable context=%+v", got)
	}
	if len(got.Sessions) != 0 || len(got.Credentials) != 0 {
		t.Fatalf("unreachable context leaked entries: %+v", got)
	}

	// The worker seam takes the same view: no context, so no block and no tools.
	if ictx, ok := s.taskIntranetResolver(ctx, taskID); ok || ictx.Available || ictx.Reason != "integration_unreachable" {
		t.Fatalf("resolver on dead pool=%+v ok=%v", ictx, ok)
	}
}
