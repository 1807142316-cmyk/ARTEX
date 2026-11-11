package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

// connectionCapabilities is the adapter-declared operation set. Any other
// action is refused explicitly before a request leaves the process.
var connectionCapabilities = []string{"ping", "info", "exec"}

const (
	connectionKeyHeader   = "X-Shell-Key"
	connectionKeyHeaderV1 = "X-Artex-Key"
	connectionOutputCap   = 64 << 10
	connectionMaxTimeout  = 30 * time.Second
	connectionDefaultTTL  = 120
	connectionMinSecret   = 32
)

type connectionService struct {
	s     *Server
	mu    sync.Mutex
	locks map[int64]*sync.Mutex
}

func (s *Server) initConnections() {
	s.connections = &connectionService{s: s, locks: map[int64]*sync.Mutex{}}
}

func (c *connectionService) lock(adapterID int64) func() {
	c.mu.Lock()
	l := c.locks[adapterID]
	if l == nil {
		l = &sync.Mutex{}
		c.locks[adapterID] = l
	}
	c.mu.Unlock()
	l.Lock()
	return l.Unlock
}

// seal/open encrypt adapter credentials through the shared secretBox. The
// derivation is shared with the proxy pool and keeps the legacy fallback, so
// credentials sealed before the helper existed keep opening.
func (c *connectionService) seal(raw string) (string, error) {
	return c.s.secrets.seal(raw)
}

func (c *connectionService) open(sealed string) (string, error) {
	return c.s.secrets.open(sealed)
}

func (s *Server) registerConnections(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/connections/adapters", s.listConnectionAdapters)
	mux.HandleFunc("POST /api/connections/adapters", s.saveConnectionAdapter)
	mux.HandleFunc("GET /api/connections/adapters/{id}", s.getConnectionAdapter)
	mux.HandleFunc("PUT /api/connections/adapters/{id}", s.saveConnectionAdapter)
	mux.HandleFunc("DELETE /api/connections/adapters/{id}", s.deleteConnectionAdapter)
	mux.HandleFunc("POST /api/connections/adapters/{id}/check", s.checkConnectionAdapter)
	mux.HandleFunc("POST /api/connections/adapters/{id}/sync", s.syncConnectionAdapter)
	mux.HandleFunc("GET /api/connections/sessions", s.listConnectionSessions)
	mux.HandleFunc("GET /api/connections/sessions/{id}/operations", s.listConnectionOperations)
	mux.HandleFunc("POST /api/connections/sessions/{id}/operations", s.runConnectionOperation)
}

func connectionAdapterID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeErr(w, 400, "invalid adapter id")
		return 0, false
	}
	return id, true
}

func connectionBody(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writeErr(w, 400, "invalid connection JSON: "+err.Error())
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeErr(w, 400, "expected one JSON document")
		return false
	}
	return true
}

func validConnectionURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return true
}

type connectionAdapterInput struct {
	Name           string `json:"name"`
	Kind           string `json:"kind"`
	BaseURL        string `json:"base_url"`
	Secret         string `json:"secret"`
	SecretRef      string `json:"secret_ref"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	HeartbeatTTL   int    `json:"heartbeat_ttl_seconds"`
	Enabled        *bool  `json:"enabled"`
	TaskID         *int64 `json:"task_id"`
	AssetID        *int64 `json:"asset_id"`
}

func adapterView(a *db.ConnectionAdapter) map[string]any {
	return map[string]any{
		"id":                    a.ID,
		"name":                  a.Name,
		"kind":                  a.Kind,
		"base_url":              a.BaseURL,
		"secret_ref":            a.SecretRef,
		"timeout_seconds":       a.TimeoutSeconds,
		"heartbeat_ttl_seconds": a.HeartbeatTTL,
		"enabled":               a.Enabled,
		"state":                 a.State,
		"last_error":            a.LastError,
		"checked_at":            a.CheckedAt,
		"task_id":               a.TaskID,
		"asset_id":              a.AssetID,
		"session_id":            a.SessionID,
		"created_at":            a.CreatedAt,
		"updated_at":            a.UpdatedAt,
		"capabilities":          connectionCapabilities,
	}
}

// adapterSession resolves the inventory row an adapter owns through the source
// prefix. It never queries by URL, so two adapters pointing at one host stay
// distinct sessions.
func (s *Server) adapterSession(ctx context.Context, a *db.ConnectionAdapter) (*db.InventorySession, error) {
	prefix := fmt.Sprintf("connection:%d", a.ID)
	a.SessionID = nil
	session, err := s.m.pg.ConnectionSessionBySource(ctx, prefix, connectionSourceID(a))
	if err != nil {
		return nil, err
	}
	if session != nil {
		a.SessionID = &session.ID
	}
	return session, nil
}

func connectionSourceID(a *db.ConnectionAdapter) string {
	u, err := url.Parse(a.BaseURL)
	if err != nil || u.Hostname() == "" {
		return fmt.Sprintf("adapter-%d", a.ID)
	}
	return u.Hostname()
}

func (s *Server) listConnectionAdapters(w http.ResponseWriter, r *http.Request) {
	items, err := s.m.pg.ConnectionAdapters(r.Context())
	if err != nil {
		writeErr(w, 500, "list adapters failed")
		return
	}
	for _, a := range items {
		_, _ = s.adapterSession(r.Context(), a)
	}
	views := make([]map[string]any, 0, len(items))
	for _, a := range items {
		views = append(views, adapterView(a))
	}
	writeJSON(w, 200, map[string]any{"items": views, "capabilities": connectionCapabilities, "kinds": []string{"http_phpcmd"}})
}

func (s *Server) getConnectionAdapter(w http.ResponseWriter, r *http.Request) {
	id, ok := connectionAdapterID(w, r)
	if !ok {
		return
	}
	a, err := s.m.pg.ConnectionAdapter(r.Context(), id)
	if err != nil {
		writeErr(w, 500, "read adapter failed")
		return
	}
	if a == nil {
		writeErr(w, 404, "adapter not found")
		return
	}
	if _, err = s.adapterSession(r.Context(), a); err != nil {
		writeErr(w, 500, "adapter session lookup failed")
		return
	}
	writeJSON(w, 200, adapterView(a))
}

func (s *Server) saveConnectionAdapter(w http.ResponseWriter, r *http.Request) {
	var input connectionAdapterInput
	if !connectionBody(w, r, &input) {
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	input.BaseURL = strings.TrimSpace(input.BaseURL)
	input.Secret = strings.TrimSpace(input.Secret)
	input.SecretRef = strings.TrimSpace(input.SecretRef)
	if input.Name == "" || len(input.Name) > 128 {
		writeErr(w, 400, "name is required and limited to 128 bytes")
		return
	}
	if input.Kind == "" {
		input.Kind = "http_phpcmd"
	}
	if input.Kind != "http_phpcmd" {
		writeErr(w, 400, "only the http_phpcmd adapter is implemented")
		return
	}
	if !validConnectionURL(input.BaseURL) {
		writeErr(w, 400, "base_url must be an absolute HTTP(S) URL without credentials, query or fragment")
		return
	}
	if input.SecretRef == "" || len(input.SecretRef) > 128 {
		writeErr(w, 400, "secret_ref is a required display label (max 128 bytes)")
		return
	}
	if input.Secret != "" && len(input.Secret) < connectionMinSecret {
		writeErr(w, 400, fmt.Sprintf("secret must be at least %d bytes", connectionMinSecret))
		return
	}
	if input.TimeoutSeconds == 0 {
		input.TimeoutSeconds = 10
	}
	if input.TimeoutSeconds < 1 || input.TimeoutSeconds > 120 {
		writeErr(w, 400, "timeout_seconds must be between 1 and 120")
		return
	}
	if input.HeartbeatTTL == 0 {
		input.HeartbeatTTL = connectionDefaultTTL
	}
	if input.HeartbeatTTL < 1 || input.HeartbeatTTL > 86400 {
		writeErr(w, 400, "heartbeat_ttl_seconds must be between 1 and 86400")
		return
	}
	if err := s.m.pg.CheckConnectionAssociation(r.Context(), input.TaskID, input.AssetID); err != nil {
		writeErr(w, 400, "task/asset reference is missing or the asset does not belong to the task")
		return
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	id := int64(0)
	if r.Method == "PUT" {
		parsed, ok := connectionAdapterID(w, r)
		if !ok {
			return
		}
		id = parsed
	}
	adapter := &db.ConnectionAdapter{ID: id, Name: input.Name, Kind: input.Kind, BaseURL: input.BaseURL, SecretRef: input.SecretRef, TimeoutSeconds: input.TimeoutSeconds, HeartbeatTTL: input.HeartbeatTTL, Enabled: enabled, TaskID: input.TaskID, AssetID: input.AssetID}
	if id > 0 {
		existing, err := s.m.pg.ConnectionAdapter(r.Context(), id)
		if err != nil {
			writeErr(w, 500, "read adapter failed")
			return
		}
		if existing == nil {
			writeErr(w, 404, "adapter not found")
			return
		}
		adapter.SealedSecret = existing.SealedSecret
	}
	if input.Secret != "" {
		sealed, err := s.connections.seal(input.Secret)
		if err != nil {
			writeErr(w, 500, "encrypt credential failed")
			return
		}
		adapter.SealedSecret = sealed
	}
	if adapter.SealedSecret == "" {
		writeErr(w, 400, "secret is required for a new adapter")
		return
	}
	if err := s.m.pg.SaveConnectionAdapter(r.Context(), adapter); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, 404, "adapter not found")
			return
		}
		if strings.Contains(err.Error(), "idx_connection_adapters_name") {
			writeErr(w, 409, "adapter name already exists")
			return
		}
		writeErr(w, 500, "save adapter failed")
		return
	}
	code := 201
	if id > 0 {
		code = 200
	}
	writeJSON(w, code, adapterView(adapter))
}

func (s *Server) deleteConnectionAdapter(w http.ResponseWriter, r *http.Request) {
	id, ok := connectionAdapterID(w, r)
	if !ok {
		return
	}
	if err := s.m.pg.DeleteConnectionAdapter(r.Context(), id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, 404, "adapter not found")
			return
		}
		writeErr(w, 500, "delete adapter failed")
		return
	}
	w.WriteHeader(204)
}

// shellExchange is the protocol result the adapter maps onto explicit states.
// It is a self-authored protocol; the PHP fixture implements exactly this shape.
type shellExchange struct {
	OK        bool   `json:"ok"`
	Action    string `json:"action"`
	Output    string `json:"output"`
	StdoutB64 string `json:"stdout_b64"`
	StderrB64 string `json:"stderr_b64"`
	ExitCode  *int   `json:"exit_code"`
	TimedOut  bool   `json:"timed_out"`
	Truncated bool   `json:"truncated"`
	ErrorText string `json:"-"`
	ErrorCode string `json:"-"`
}

type shellError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type shellResponse struct {
	OK        bool        `json:"ok"`
	Action    string      `json:"action"`
	Output    string      `json:"output"`
	StdoutB64 string      `json:"stdout_b64"`
	StderrB64 string      `json:"stderr_b64"`
	ExitCode  *int        `json:"exit_code"`
	TimedOut  bool        `json:"timed_out"`
	Truncated bool        `json:"truncated"`
	Error     *shellError `json:"error"`
}

type shellRequest struct {
	V      int            `json:"v"`
	ID     string         `json:"id"`
	Action string         `json:"action"`
	Cmd    string         `json:"cmd,omitempty"`
	Nonce  string         `json:"nonce"`
	TS     int64          `json:"ts"`
	Args   map[string]any `json:"args,omitempty"`
}

// shellClient performs one bounded request against a configured adapter. The
// credential only ever travels in a header, never in the URL.
type shellClient struct {
	baseURL string
	secret  string
	timeout time.Duration
}

func (s *Server) shellClientFor(ctx context.Context, a *db.ConnectionAdapter) (*shellClient, error) {
	secret, err := s.connections.open(a.SealedSecret)
	if err != nil {
		return nil, err
	}
	return &shellClient{baseURL: a.BaseURL, secret: secret, timeout: time.Duration(a.TimeoutSeconds) * time.Second}, nil
}

// exchange sends one request. The returned error is either a transport failure
// or a deadline; protocol-level failures are reported in the exchange itself.
func (c *shellClient) exchange(ctx context.Context, request shellRequest) (shellExchange, error) {
	var result shellExchange
	if c.timeout <= 0 {
		c.timeout = 10 * time.Second
	}
	if c.timeout > connectionMaxTimeout {
		c.timeout = connectionMaxTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	body, err := json.Marshal(request)
	if err != nil {
		return result, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(connectionKeyHeader, c.secret)
	req.Header.Set(connectionKeyHeaderV1, c.secret)
	client := &http.Client{Timeout: c.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (connectionOutputCap*2)+4096))
	if err != nil {
		return result, err
	}
	var decoded shellResponse
	if jsonErr := json.Unmarshal(raw, &decoded); jsonErr != nil {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			result.ErrorCode = "unauthorized"
			result.ErrorText = fmt.Sprintf("remote shell rejected the credential (HTTP %d)", resp.StatusCode)
			return result, nil
		}
		result.ErrorText = fmt.Sprintf("remote shell returned HTTP %d without a protocol body", resp.StatusCode)
		result.ErrorCode = "bad_response"
		return result, nil
	}
	result.OK = decoded.OK
	result.Action = decoded.Action
	result.Output = decoded.Output
	result.ExitCode = decoded.ExitCode
	result.TimedOut = decoded.TimedOut
	result.Truncated = decoded.Truncated
	if decoded.Error != nil {
		result.ErrorCode = decoded.Error.Code
		result.ErrorText = decoded.Error.Message
	}
	// The protocol carries stdout base64-encoded. stdout_b64 is the explicit
	// field; the contract's single "output" field is also base64, so decode it
	// and only fall back to the literal text when it is not valid base64.
	switch {
	case decoded.StdoutB64 != "":
		decodedOut, decodeErr := base64.StdEncoding.DecodeString(decoded.StdoutB64)
		if decodeErr != nil {
			result.ErrorCode = "bad_response"
			result.ErrorText = "remote shell returned undecodable output"
			return result, nil
		}
		result.Output = string(decodedOut)
	case decoded.Output != "":
		if decodedOut, decodeErr := base64.StdEncoding.DecodeString(decoded.Output); decodeErr == nil {
			result.Output = string(decodedOut)
		}
	}
	if decoded.StderrB64 != "" {
		stderr, decodeErr := base64.StdEncoding.DecodeString(decoded.StderrB64)
		if decodeErr == nil && len(stderr) > 0 && result.ErrorText == "" {
			result.ErrorText = string(stderr)
		}
	}
	if !decoded.OK && result.ErrorText == "" {
		result.ErrorText = "remote shell reported failure"
		if result.ErrorCode == "" {
			result.ErrorCode = "remote_error"
		}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		if result.ErrorCode == "" || result.ErrorCode == "remote_error" {
			result.ErrorCode = "unauthorized"
		}
	}
	return result, nil
}

func (s *Server) checkConnectionAdapter(w http.ResponseWriter, r *http.Request) {
	id, ok := connectionAdapterID(w, r)
	if !ok {
		return
	}
	a, err := s.m.pg.ConnectionAdapter(r.Context(), id)
	if err != nil {
		writeErr(w, 500, "read adapter failed")
		return
	}
	if a == nil {
		writeErr(w, 404, "adapter not found")
		return
	}
	if !a.Enabled {
		writeErr(w, 409, "adapter is disabled; enable it before checking")
		return
	}
	state, lastError := s.probeConnection(r.Context(), a)
	if _, err = s.m.pg.SetConnectionAdapterState(r.Context(), a.ID, state, lastError); err != nil {
		writeErr(w, 500, "record check result failed")
		return
	}
	updated, err := s.m.pg.ConnectionAdapter(r.Context(), a.ID)
	if err != nil || updated == nil {
		writeErr(w, 500, "read adapter failed")
		return
	}
	_, _ = s.adapterSession(r.Context(), updated)
	writeJSON(w, 200, adapterView(updated))
}

// probeConnection performs the real ping and maps the result onto the four
// adapter states. No other code path fabricates reachability.
func (s *Server) probeConnection(ctx context.Context, a *db.ConnectionAdapter) (string, string) {
	client, err := s.shellClientFor(ctx, a)
	if err != nil {
		return "unreachable", "stored credential could not be opened"
	}
	result, err := client.exchange(ctx, shellRequest{V: 1, ID: connectionNonce(), Action: "ping", Nonce: connectionNonce(), TS: time.Now().Unix()})
	if err != nil {
		return "unreachable", connectionErrorText(err)
	}
	if result.ErrorCode == "unauthorized" {
		return "auth_failed", result.ErrorText
	}
	if !result.OK {
		return "unreachable", result.ErrorText
	}
	return "reachable", ""
}

func connectionNonce() string {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func connectionErrorText(err error) string {
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout() {
		return "connection timed out"
	}
	return "connection failed: " + err.Error()
}

// syncConnectionAdapter writes one inventory observation through the existing
// ObserveSession path. A reachable shell becomes connected; a failed check
// records the observable disconnect reason instead of pretending to be online.
func (s *Server) syncConnectionAdapter(w http.ResponseWriter, r *http.Request) {
	id, ok := connectionAdapterID(w, r)
	if !ok {
		return
	}
	unlock := s.connections.lock(id)
	defer unlock()
	a, err := s.m.pg.ConnectionAdapter(r.Context(), id)
	if err != nil {
		writeErr(w, 500, "read adapter failed")
		return
	}
	if a == nil {
		writeErr(w, 404, "adapter not found")
		return
	}
	if !a.Enabled {
		writeErr(w, 409, "adapter is disabled; enable it before syncing")
		return
	}
	state, lastError := s.probeConnection(r.Context(), a)
	if _, err = s.m.pg.SetConnectionAdapterState(r.Context(), a.ID, state, lastError); err != nil {
		writeErr(w, 500, "record check result failed")
		return
	}
	source := fmt.Sprintf("connection:%d", a.ID)
	sourceID := connectionSourceID(a)
	sequence, err := s.m.pg.NextInventorySequence(r.Context(), source, sourceID)
	if err != nil {
		writeErr(w, 500, "inventory sequence lookup failed")
		return
	}
	observation := db.SessionObservation{
		Source:              source,
		SourceID:            sourceID,
		Sequence:            sequence,
		Kind:                "webshell",
		ProtocolLabel:       "http_phpcmd",
		State:               "connected",
		Host:                sourceID,
		URL:                 a.BaseURL,
		TaskID:              a.TaskID,
		AssetID:             a.AssetID,
		HeartbeatTTLSeconds: a.HeartbeatTTL,
	}
	if state != "reachable" {
		observation.State = "disconnected"
		observation.DisconnectReason = "adapter check: " + state
		if lastError != "" {
			observation.DisconnectReason += " (" + trimConnectionText(lastError, 300) + ")"
		}
	}
	session, _, replayed, err := s.m.pg.ObserveSession(r.Context(), observation)
	if err != nil {
		if errors.Is(err, db.ErrInventoryConflict) {
			writeErr(w, 409, "inventory observation conflicted with a concurrent sync")
			return
		}
		if errors.Is(err, db.ErrInventoryReference) {
			writeErr(w, 400, "adapter task/asset association is no longer valid")
			return
		}
		writeErr(w, 500, "inventory observation failed")
		return
	}
	session.Mode = "adapter"
	writeJSON(w, 200, map[string]any{"adapter": adapterView(a), "session": connectionSessionView(session, a), "replayed": replayed, "state": state})
}

// trimConnectionText clips text to at most max bytes without splitting a
// multi-byte rune. Remote output and error text are arbitrary UTF-8, and a byte
// slice would produce invalid sequences that the UI renders as mojibake.
func trimConnectionText(text string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(text) <= max {
		return text
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut]
}

func connectionSessionView(session db.InventorySession, a *db.ConnectionAdapter) map[string]any {
	view := map[string]any{
		"id":                    session.ID,
		"source":                session.Source,
		"source_id":             session.SourceID,
		"sequence":              session.Sequence,
		"kind":                  session.Kind,
		"protocol_label":        session.ProtocolLabel,
		"state":                 session.State,
		"effective_state":       session.EffectiveState,
		"host":                  session.Host,
		"url":                   session.URL,
		"mode":                  "adapter",
		"task_id":               session.TaskID,
		"asset_id":              session.AssetID,
		"heartbeat_at":          session.HeartbeatAt,
		"heartbeat_ttl_seconds": session.HeartbeatTTLSeconds,
		"disconnect_reason":     session.DisconnectReason,
		"annotation":            session.Annotation,
		"updated_at":            session.UpdatedAt,
		"capabilities":          connectionCapabilities,
		"adapter": map[string]any{
			"id":              a.ID,
			"name":            a.Name,
			"kind":            a.Kind,
			"secret_ref":      a.SecretRef,
			"state":           a.State,
			"enabled":         a.Enabled,
			"capabilities":    connectionCapabilities,
			"last_error":      a.LastError,
			"checked_at":      a.CheckedAt,
			"base_url":        a.BaseURL,
			"timeout_seconds": a.TimeoutSeconds,
		},
	}
	return view
}

func (s *Server) listConnectionSessions(w http.ResponseWriter, r *http.Request) {
	items, err := s.m.pg.ConnectionSessions(r.Context(), strings.TrimSpace(r.URL.Query().Get("q")))
	if err != nil {
		writeErr(w, 500, "list sessions failed")
		return
	}
	adapters, err := s.m.pg.ConnectionAdapters(r.Context())
	if err != nil {
		writeErr(w, 500, "list adapters failed")
		return
	}
	byID := map[int64]*db.ConnectionAdapter{}
	for _, a := range adapters {
		byID[a.ID] = a
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		adapterID := connectionAdapterIDFromSource(item.Source)
		adapter := byID[adapterID]
		if adapter == nil {
			continue
		}
		out = append(out, connectionSessionView(item, adapter))
	}
	writeJSON(w, 200, map[string]any{"items": out, "capabilities": connectionCapabilities, "mode": "adapter"})
}

func connectionAdapterIDFromSource(source string) int64 {
	if !strings.HasPrefix(source, "connection:") {
		return 0
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(source, "connection:"), 10, 64)
	if err != nil {
		return 0
	}
	return id
}

func (s *Server) connectionSessionFor(w http.ResponseWriter, r *http.Request) (*db.InventorySession, *db.ConnectionAdapter, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeErr(w, 400, "invalid session id")
		return nil, nil, false
	}
	item, _, err := s.m.pg.GetInventorySession(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "session not found")
		return nil, nil, false
	}
	if err != nil {
		writeErr(w, 500, "read session failed")
		return nil, nil, false
	}
	adapterID := connectionAdapterIDFromSource(item.Source)
	if adapterID == 0 {
		writeErr(w, 409, "session is not linked to a connection adapter")
		return nil, nil, false
	}
	adapter, err := s.m.pg.ConnectionAdapter(r.Context(), adapterID)
	if err != nil {
		writeErr(w, 500, "read adapter failed")
		return nil, nil, false
	}
	if adapter == nil {
		writeErr(w, 409, "the adapter that created this session no longer exists")
		return nil, nil, false
	}
	return &item, adapter, true
}

func (s *Server) listConnectionOperations(w http.ResponseWriter, r *http.Request) {
	item, adapter, ok := s.connectionSessionFor(w, r)
	if !ok {
		return
	}
	ops, err := s.m.pg.ConnectionOperations(r.Context(), item.ID, 100)
	if err != nil {
		writeErr(w, 500, "list operations failed")
		return
	}
	writeJSON(w, 200, map[string]any{"items": ops, "session": connectionSessionView(*item, adapter), "capabilities": connectionCapabilities})
}

type connectionOperationInput struct {
	Action    string   `json:"action"`
	Cmd       string   `json:"cmd"`
	Argv      []string `json:"argv"`
	TimeoutMS int      `json:"timeout_ms"`
	RequestID string   `json:"request_id"`
	AdapterID *int64   `json:"adapter_id"`
}

func (s *Server) runConnectionOperation(w http.ResponseWriter, r *http.Request) {
	item, adapter, ok := s.connectionSessionFor(w, r)
	if !ok {
		return
	}
	var input connectionOperationInput
	if !connectionBody(w, r, &input) {
		return
	}
	if input.AdapterID != nil && *input.AdapterID != adapter.ID {
		writeErr(w, 409, "session belongs to a different adapter")
		return
	}
	record, replayed, err := s.executeConnectionOperation(r.Context(), item.ID, connectionOpRequest{
		Action:    input.Action,
		Cmd:       input.Cmd,
		Argv:      input.Argv,
		TimeoutMS: input.TimeoutMS,
		RequestID: input.RequestID,
	})
	if err != nil {
		var opErr *connectionOpError
		if errors.As(err, &opErr) {
			writeErr(w, opErr.status, opErr.message)
			return
		}
		writeErr(w, 500, "record operation failed")
		return
	}
	// A rejected capability is still a recorded outcome, so it carries the
	// stored record. A replayed request keeps the plain 200 a retry deserves.
	if record.Status == "unsupported" && !replayed {
		writeJSON(w, 422, record)
		return
	}
	writeJSON(w, 200, record)
}

// connectionOpError is a validation or lookup failure with the HTTP status the
// API contract assigns it. Keeping the status on the error lets the same code
// path serve the HTTP handler and the worker's intranet executor.
type connectionOpError struct {
	status  int
	message string
}

func (e *connectionOpError) Error() string { return e.message }

func opErrorf(status int, format string, args ...any) *connectionOpError {
	return &connectionOpError{status: status, message: fmt.Sprintf(format, args...)}
}

// connectionOpRequest is the normalized form of one operation. The HTTP handler
// builds it from the request body; the intranet executor builds it from a tool
// call. Everything downstream treats them identically.
type connectionOpRequest struct {
	Action    string
	Cmd       string
	Argv      []string
	TimeoutMS int
	RequestID string
}

// executeConnectionOperation validates, records and performs one operation on a
// session. Every outcome — including a refused capability — is written to
// connection_operations before it is returned, so neither caller can report an
// action that left no trace.
func (s *Server) executeConnectionOperation(ctx context.Context, sessionID int64, req connectionOpRequest) (db.ConnectionOperation, bool, error) {
	req.RequestID = strings.TrimSpace(req.RequestID)
	req.Cmd = strings.TrimSpace(req.Cmd)
	if req.RequestID == "" || len(req.RequestID) > 128 {
		return db.ConnectionOperation{}, false, opErrorf(400, "request_id is required and limited to 128 bytes")
	}
	if sessionID < 1 {
		return db.ConnectionOperation{}, false, opErrorf(400, "invalid session id")
	}
	item, _, err := s.m.pg.GetInventorySession(ctx, sessionID)
	if errors.Is(err, sql.ErrNoRows) {
		return db.ConnectionOperation{}, false, opErrorf(404, "session not found")
	}
	if err != nil {
		return db.ConnectionOperation{}, false, err
	}
	adapterID := connectionAdapterIDFromSource(item.Source)
	if adapterID == 0 {
		return db.ConnectionOperation{}, false, opErrorf(409, "session is not linked to a connection adapter")
	}
	adapter, err := s.m.pg.ConnectionAdapter(ctx, adapterID)
	if err != nil {
		return db.ConnectionOperation{}, false, err
	}
	if adapter == nil {
		return db.ConnectionOperation{}, false, opErrorf(409, "the adapter that created this session no longer exists")
	}
	input := connectionOperationInput{Action: req.Action, Cmd: req.Cmd, Argv: req.Argv, TimeoutMS: req.TimeoutMS, RequestID: req.RequestID}
	action := strings.TrimSpace(req.Action)
	if !connectionSupports(action) {
		record, replayed, err := s.m.pg.StartConnectionOperation(ctx, adapter.ID, item.ID, req.RequestID, action, connectionArgsSummary(input))
		if err != nil {
			return db.ConnectionOperation{}, false, err
		}
		if replayed {
			return record, true, nil
		}
		record, err = s.m.pg.FinishConnectionOperation(ctx, record.ID, "unsupported", nil, "", fmt.Sprintf("action %q is not declared by the http_phpcmd adapter", action))
		if err != nil {
			return db.ConnectionOperation{}, false, err
		}
		return record, false, nil
	}
	if err := validateConnectionArgs(input); err != nil {
		return db.ConnectionOperation{}, false, opErrorf(400, "%s", err.Error())
	}
	if !adapter.Enabled {
		return db.ConnectionOperation{}, false, opErrorf(409, "adapter is disabled")
	}
	if item.EffectiveState != "connected" {
		return db.ConnectionOperation{}, false, opErrorf(409, "session is %s; run a sync before executing", item.EffectiveState)
	}
	record, replayed, err := s.m.pg.StartConnectionOperation(ctx, adapter.ID, item.ID, req.RequestID, action, connectionArgsSummary(input))
	if err != nil {
		return db.ConnectionOperation{}, false, err
	}
	if replayed {
		return record, true, nil
	}
	client, err := s.shellClientFor(ctx, adapter)
	if err != nil {
		finished, ferr := s.m.pg.FinishConnectionOperation(ctx, record.ID, "failed", nil, "", "stored credential could not be opened")
		if ferr != nil {
			return db.ConnectionOperation{}, false, ferr
		}
		return finished, false, nil
	}
	request := shellRequest{V: 1, ID: req.RequestID, Action: action, Nonce: connectionNonce(), TS: time.Now().Unix()}
	args := map[string]any{}
	if req.TimeoutMS > 0 {
		args["timeout_ms"] = req.TimeoutMS
	}
	if action == "exec" {
		if len(req.Argv) > 0 {
			args["argv"] = req.Argv
		} else {
			request.Cmd = req.Cmd
			args["cmd"] = req.Cmd
		}
	}
	if len(args) > 0 {
		request.Args = args
	}
	deadline := client.timeout
	if req.TimeoutMS > 0 {
		requested := time.Duration(req.TimeoutMS) * time.Millisecond
		if requested < deadline {
			deadline = requested
		}
	}
	if deadline > connectionMaxTimeout {
		deadline = connectionMaxTimeout
	}
	exchangeCtx, cancel := context.WithTimeout(ctx, deadline)
	result, exchangeErr := client.exchange(exchangeCtx, request)
	cancel()
	if exchangeErr != nil {
		status := "failed"
		message := connectionErrorText(exchangeErr)
		if errors.Is(exchangeErr, context.DeadlineExceeded) {
			status = "timeout"
			message = fmt.Sprintf("operation exceeded %s", deadline)
		}
		finished, ferr := s.m.pg.FinishConnectionOperation(ctx, record.ID, status, nil, "", message)
		if ferr != nil {
			return db.ConnectionOperation{}, false, ferr
		}
		return finished, false, nil
	}
	status := "succeeded"
	if result.TimedOut {
		status = "timeout"
	}
	output := trimConnectionText(result.Output, connectionOutputCap)
	errorText := trimConnectionText(result.ErrorText, 2000)
	if status == "succeeded" && !result.OK {
		status = "failed"
	}
	if status == "succeeded" && result.ExitCode != nil && *result.ExitCode != 0 {
		status = "failed"
	}
	if status == "timeout" && errorText == "" {
		errorText = "remote shell reported a timeout"
	}
	finished, err := s.m.pg.FinishConnectionOperation(ctx, record.ID, status, result.ExitCode, output, errorText)
	if err != nil {
		return db.ConnectionOperation{}, false, err
	}
	return finished, false, nil
}

func connectionSupports(action string) bool {
	for _, capability := range connectionCapabilities {
		if capability == action {
			return true
		}
	}
	return false
}

func validateConnectionArgs(input connectionOperationInput) error {
	if input.Action == "ping" || input.Action == "info" {
		if input.Cmd != "" || len(input.Argv) > 0 {
			return errors.New("ping/info do not accept a command")
		}
		return nil
	}
	if input.Cmd != "" && len(input.Argv) > 0 {
		return errors.New("supply either cmd or argv, not both")
	}
	if input.Cmd == "" && len(input.Argv) == 0 {
		return errors.New("exec requires cmd or argv")
	}
	if len(input.Cmd) > 4096 {
		return errors.New("cmd is limited to 4096 bytes")
	}
	if len(input.Argv) > 32 {
		return errors.New("argv is limited to 32 items")
	}
	total := 0
	for _, item := range input.Argv {
		if len(item) > 512 || strings.ContainsRune(item, 0) {
			return errors.New("each argv item is limited to 512 bytes and must not contain NUL")
		}
		total += len(item)
	}
	if total > 4096 {
		return errors.New("argv is limited to 4096 bytes in total")
	}
	if input.TimeoutMS < 0 || input.TimeoutMS > int(connectionMaxTimeout/time.Millisecond) {
		return errors.New("timeout_ms must be between 0 and 30000")
	}
	return nil
}

func connectionArgsSummary(input connectionOperationInput) string {
	if len(input.Argv) > 0 {
		raw, _ := json.Marshal(input.Argv)
		return trimConnectionText("argv="+string(raw), 500)
	}
	if input.Cmd != "" {
		return trimConnectionText("cmd="+input.Cmd, 500)
	}
	return ""
}
