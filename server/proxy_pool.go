package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
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

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/enrich"
	"github.com/Autumn-27/artex/traffic"
)

const settingProxyPool = "proxy_pool_enabled"

type taskProxyGateway struct {
	server         *http.Server
	address, token string
	taskID         int64
	mu             sync.Mutex
	requests       map[*context.CancelFunc]struct{}
	changing       int
}
type proxyPoolService struct {
	s          *Server
	mu         sync.Mutex
	gateways   map[int64]*taskProxyGateway
	recordings map[string]string
	egress     *egressSandbox
}

func (s *Server) initProxyPool() {
	p := &proxyPoolService{s: s, gateways: map[int64]*taskProxyGateway{}, recordings: map[string]string{}, egress: &egressSandbox{s: s}}
	s.proxyPool = p
	s.m.invalidateTaskEgress = func(id string) { n, _ := strconv.ParseInt(id, 10, 64); p.invalidate(n) }
	s.m.taskEnrich = func(id string) agent.EnrichTrigger {
		if !s.m.pg.GetBool(settingProxyPool, false) {
			return s.m.enrich
		}
		address, _ := s.taskProxyAddress(id)
		return taskEgressEnricher{engine: s.m.enrich, proxy: address}
	}
	if s.m.traffic != nil {
		s.m.traffic.SetTaskUpstreamResolver(func(token string) (*url.URL, error) {
			p.mu.Lock()
			address := p.recordings[token]
			p.mu.Unlock()
			if address == "" {
				return nil, errors.New("unknown task egress token")
			}
			u, _ := url.Parse(address)
			u.User = url.UserPassword("artex-recorded", token)
			return u, nil
		})
	}
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				p.mu.Lock()
				for _, g := range p.gateways {
					g.cancelRequests()
					_ = g.server.Close()
				}
				p.mu.Unlock()
				return
			case <-ticker.C:
				if s.m.pg.GetBool(settingProxyPool, false) {
					p.checkActive()
				}
			}
		}
	}()
}

func (g *taskProxyGateway) cancelRequests() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for cancel := range g.requests {
		(*cancel)()
	}
	g.requests = map[*context.CancelFunc]struct{}{}
}
func (p *proxyPoolService) invalidate(id int64) {
	p.mu.Lock()
	g := p.gateways[id]
	p.mu.Unlock()
	if g != nil {
		g.cancelRequests()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = p.s.m.pg.PauseTaskEgress(ctx, id, "task lifecycle changed")
}
func (p *proxyPoolService) changeRoute(id int64) func() {
	_, _ = p.gateway(id)
	p.mu.Lock()
	g := p.gateways[id]
	p.mu.Unlock()
	if g == nil {
		return func() {}
	}
	g.mu.Lock()
	g.changing++
	for cancel := range g.requests {
		(*cancel)()
	}
	g.requests = map[*context.CancelFunc]struct{}{}
	g.mu.Unlock()
	return func() { g.mu.Lock(); g.changing--; g.mu.Unlock() }
}
func (g *taskProxyGateway) requestContext(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	g.mu.Lock()
	if g.changing > 0 {
		cancel()
	}
	g.requests[&cancel] = struct{}{}
	g.mu.Unlock()
	return ctx, func() { cancel(); g.mu.Lock(); delete(g.requests, &cancel); g.mu.Unlock() }
}

type taskEgressEnricher struct {
	engine *enrich.Engine
	proxy  string
}

func (e taskEgressEnricher) ResolveDomain(id int64, host string) { e.engine.ResolveDomain(id, host) }
func (e taskEgressEnricher) ProbeSite(id int64, raw string)      { e.engine.ProbeSiteVia(id, raw, e.proxy) }
func (p *proxyPoolService) seal(raw string) (string, error) {
	key := sha256.Sum256(p.s.jwtKey)
	block, e := aes.NewCipher(key[:])
	if e != nil {
		return "", e
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		return "", e
	}
	nonce := make([]byte, a.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return "", e
	}
	return base64.RawStdEncoding.EncodeToString(a.Seal(nonce, nonce, []byte(raw), nil)), nil
}
func (p *proxyPoolService) open(sealed string) (string, error) {
	data, e := base64.RawStdEncoding.DecodeString(sealed)
	if e != nil {
		return "", e
	}
	key := sha256.Sum256(p.s.jwtKey)
	block, e := aes.NewCipher(key[:])
	if e != nil {
		return "", e
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		return "", e
	}
	if len(data) < a.NonceSize() {
		return "", errors.New("invalid encrypted proxy URL")
	}
	plain, e := a.Open(nil, data[:a.NonceSize()], data[a.NonceSize():], nil)
	return string(plain), e
}
func (p *proxyPoolService) gateway(taskID int64) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if g := p.gateways[taskID]; g != nil {
		return g.address, nil
	}
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return "", e
	}
	tokenBytes := make([]byte, 32)
	if _, e = rand.Read(tokenBytes); e != nil {
		ln.Close()
		return "", e
	}
	g := &taskProxyGateway{address: "http://" + ln.Addr().String(), taskID: taskID, token: base64.RawURLEncoding.EncodeToString(tokenBytes), requests: map[*context.CancelFunc]struct{}{}}
	g.server = &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { p.forward(g, w, r) })}
	p.gateways[taskID] = g
	p.recordings[g.token] = g.address
	go g.server.Serve(ln)
	return g.address, nil
}
func (p *proxyPoolService) current(ctx context.Context, id int64) (*db.TaskEgress, error) {
	lease, e := p.s.m.pg.TaskEgress(ctx, id)
	if e != nil {
		return nil, e
	}
	if lease == nil {
		lease, e = p.s.m.pg.AssignTaskEgress(ctx, id, 0, "pause", "assigned")
		if e != nil {
			return nil, errors.New("no healthy unleased proxy is available")
		}
	}
	return lease, nil
}
func (p *proxyPoolService) route(ctx context.Context, id int64) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	lease, e := p.current(ctx, id)
	if e != nil {
		if ctx.Err() != nil || errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
			return "", e
		}
		p.pause(id, "no healthy task egress")
		return "", e
	}
	if lease.State == "paused" {
		return "", errors.New("task egress is paused; reassign and resume explicitly")
	}
	if lease.State == "direct" {
		return "", nil
	}
	if lease.ProxyID == nil {
		return "", errors.New("missing proxy lease")
	}
	endpoint, e := p.s.m.pg.ProxyEndpoint(ctx, *lease.ProxyID)
	if e != nil {
		return "", e
	}
	if endpoint == nil || !endpoint.Enabled || endpoint.Health != "healthy" {
		return p.failed(ctx, lease)
	}
	raw, e := p.open(endpoint.SealedURL)
	if e != nil {
		p.pause(id, "proxy credentials unavailable")
		return "", errors.New("proxy credentials cannot be decrypted")
	}
	return raw, nil
}
func (p *proxyPoolService) failed(ctx context.Context, lease *db.TaskEgress) (string, error) {
	finishChange := p.changeRoute(lease.TaskID)
	// Invalidating cancels the triggering request too; persist policy on a fresh bounded context.
	ctx, cancel := context.WithTimeout(p.s.ctx, 10*time.Second)
	defer cancel()
	var next *db.TaskEgress
	var e error
	switch lease.Policy {
	case "failover":
		next, e = p.s.m.pg.AssignTaskEgress(ctx, lease.TaskID, 0, lease.Policy, "failover")
	case "direct":
		next, e = p.s.m.pg.AssignTaskEgress(ctx, lease.TaskID, 0, lease.Policy, "direct")
	default:
		e = errors.New("proxy failed; fallback is disabled")
	}
	if e != nil || next == nil {
		p.pause(lease.TaskID, "proxy unavailable; task paused")
		finishChange()
		return "", errors.New("task proxy unavailable; task paused")
	}
	finishChange()
	return p.route(ctx, lease.TaskID)
}
func (p *proxyPoolService) pause(id int64, message string) {
	finishChange := p.changeRoute(id)
	defer finishChange()
	_ = p.s.m.pg.PauseTaskEgress(context.Background(), id, message)
	if t, ok := p.s.m.Task(strconv.FormatInt(id, 10)); ok {
		_, _ = p.s.applyTaskControlWithCause(t, "pause", errors.New(message))
	}
}
func (p *proxyPoolService) observeFailure(ctx context.Context, id int64) {
	lease, e := p.s.m.pg.TaskEgress(ctx, id)
	if e != nil || lease == nil || lease.ProxyID == nil {
		return
	}
	endpoint, e := p.s.m.pg.ProxyEndpoint(ctx, *lease.ProxyID)
	if e != nil || endpoint == nil {
		return
	}
	_ = p.check(ctx, endpoint)
	if endpoint.Health != "healthy" {
		_, _ = p.failed(ctx, lease)
	}
}
func (p *proxyPoolService) forward(g *taskProxyGateway, w http.ResponseWriter, r *http.Request) {
	ctx, finish := g.requestContext(r.Context())
	defer finish()
	r = r.WithContext(ctx)
	if ctx.Err() != nil {
		http.Error(w, "task route changed", 503)
		return
	}
	if !p.s.m.pg.GetBool(settingProxyPool, false) {
		http.Error(w, "task proxy pool is disabled", 503)
		return
	}
	task, e := p.s.m.pg.GetTask(g.taskID)
	if e != nil || task == nil || task.Paused || isTerminalStatus(task.Status) {
		http.Error(w, "task is unavailable or paused", 503)
		return
	}
	upstream, e := p.route(r.Context(), g.taskID)
	if e != nil {
		http.Error(w, e.Error(), 503)
		return
	}
	if r.Context().Err() != nil {
		http.Error(w, "task route changed", 503)
		return
	}
	recorded := false
	if auth := r.Header.Get("Proxy-Authorization"); auth != "" {
		q := &http.Request{Header: http.Header{"Authorization": []string{auth}}}
		user, secret, ok := q.BasicAuth()
		if !ok || user != "artex-recorded" || secret != g.token {
			http.Error(w, "invalid task proxy authentication", 407)
			return
		}
		recorded = true
	}
	r.Header.Del("Proxy-Authorization")
	if !recorded && p.s.m.TrafficEnabled() && p.s.m.traffic != nil {
		u, _ := url.Parse(p.s.m.traffic.ProxyAddr())
		u.User = url.UserPassword("artex-task", g.token)
		upstream = u.String()
	}
	if r.Method == http.MethodConnect {
		p.tunnel(g, w, r, upstream)
		return
	}
	if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
		http.Error(w, "absolute HTTP URL required", 400)
		return
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 15 * time.Second}
	if upstream != "" {
		u, _ := url.Parse(upstream)
		tr.Proxy = http.ProxyURL(u)
	}
	defer tr.CloseIdleConnections()
	request := r.Clone(r.Context())
	request.RequestURI = ""
	stripProxyHopHeaders(request.Header)
	response, e := tr.RoundTrip(request)
	if e != nil {
		p.observeFailure(r.Context(), g.taskID)
		http.Error(w, "task egress request failed", 502)
		return
	}
	defer response.Body.Close()
	if response.StatusCode == 502 || response.StatusCode == 407 {
		p.observeFailure(r.Context(), g.taskID)
	}
	stripProxyHopHeaders(response.Header)
	for k, values := range response.Header {
		for _, value := range values {
			w.Header().Add(k, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}
func stripProxyHopHeaders(h http.Header) {
	for _, v := range strings.Split(h.Get("Connection"), ",") {
		h.Del(strings.TrimSpace(v))
	}
	for _, k := range []string{"Proxy-Authorization", "Proxy-Authenticate", "Proxy-Connection", "Connection", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(k)
	}
}
func (p *proxyPoolService) tunnel(g *taskProxyGateway, w http.ResponseWriter, r *http.Request, upstream string) {
	if _, _, e := net.SplitHostPort(r.Host); e != nil {
		http.Error(w, "CONNECT requires host:port", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	remote, e := dialTaskProxy(ctx, upstream, r.Host)
	if e != nil {
		p.observeFailure(r.Context(), g.taskID)
		http.Error(w, "task egress connection failed", 502)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		remote.Close()
		http.Error(w, "tunnel transport unavailable", 500)
		return
	}
	local, buffer, e := hijacker.Hijack()
	if e != nil {
		remote.Close()
		return
	}
	defer local.Close()
	defer remote.Close()
	_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = buffer.Flush()
	done := make(chan struct{})
	stop := context.AfterFunc(r.Context(), func() { local.Close(); remote.Close() })
	defer stop()
	go func() { _, _ = io.Copy(remote, buffer); remote.Close(); close(done) }()
	_, _ = io.Copy(local, remote)
	local.Close()
	<-done
}
func (p *proxyPoolService) check(ctx context.Context, endpoint *db.ProxyEndpoint) error {
	raw, e := p.open(endpoint.SealedURL)
	if e != nil {
		return errors.New("proxy credentials cannot be decrypted")
	}
	u, e := url.Parse(raw)
	if e != nil {
		return e
	}
	tr := &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true, TLSHandshakeTimeout: 5 * time.Second}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, e := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.CheckURL, nil)
	if e != nil {
		return e
	}
	response, e := client.Do(request)
	if ctx.Err() != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		return ctx.Err()
	}
	exit := ""
	message := "proxy health check failed"
	if e == nil {
		defer response.Body.Close()
		if response.StatusCode == 200 {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
			if readErr == nil && len(body) <= 4096 {
				var result struct {
					IP string `json:"ip"`
				}
				if json.Unmarshal(body, &result) == nil {
					exit = result.IP
				} else {
					exit = strings.TrimSpace(string(body))
				}
				if net.ParseIP(exit) == nil {
					exit = ""
					message = "health response did not contain an IP address"
				}
			}
		} else {
			message = fmt.Sprintf("health check HTTP %d", response.StatusCode)
		}
	}
	healthy := exit != ""
	if healthy {
		message = ""
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if e = p.s.m.pg.SetProxyHealth(ctx, endpoint.ID, healthy, exit, message); e != nil {
		return e
	}
	endpoint.Health = "unhealthy"
	if healthy {
		endpoint.Health = "healthy"
	}
	endpoint.ExitIP, endpoint.LastError = exit, message
	now := time.Now()
	endpoint.CheckedAt = &now
	return nil
}
func (p *proxyPoolService) checkActive() {
	ctx, cancel := context.WithCancel(p.s.ctx)
	defer cancel()
	endpoints, e := p.s.m.pg.ProxyEndpoints(ctx)
	if e != nil {
		return
	}
	for _, endpoint := range endpoints {
		if !endpoint.Enabled {
			continue
		}
		_ = p.check(ctx, endpoint)
		if ctx.Err() != nil {
			return
		}
	}
	p.mu.Lock()
	var tasks []int64
	for id := range p.gateways {
		tasks = append(tasks, id)
	}
	p.mu.Unlock()
	for _, id := range tasks {
		if ctx.Err() != nil {
			return
		}
		task, err := p.s.m.pg.GetTask(id)
		if err != nil {
			continue
		}
		if task == nil || isTerminalStatus(task.Status) {
			p.mu.Lock()
			if g := p.gateways[id]; g != nil {
				g.cancelRequests()
				_ = g.server.Close()
				delete(p.recordings, g.token)
				delete(p.gateways, id)
			}
			p.mu.Unlock()
			continue
		}
		_, _ = p.route(ctx, id)
	}
}
func (s *Server) taskProxyAddress(id string) (string, string) {
	if s.proxyPool == nil || !s.m.pg.GetBool(settingProxyPool, false) {
		return s.m.ProxyAddr(), s.m.ProxyCACert()
	}
	n, _ := strconv.ParseInt(id, 10, 64)
	address, e := s.proxyPool.gateway(n)
	if e != nil {
		return "http://127.0.0.1:0", ""
	}
	return address, s.m.ProxyCACert()
}

func (s *Server) taskBrowserMCP(ctx context.Context, stored *db.MCPServer) *db.MCPServer {
	id := agent.RunInfoFrom(ctx).TaskID
	if id <= 0 || stored.Name != browserMCPName || !s.m.pg.GetBool(settingProxyPool, false) {
		return stored
	}
	copy := *stored
	address, cert := s.taskProxyAddress(strconv.FormatInt(id, 10))
	args := stripProxyArgs(decodeStrSlice(stored.Args))
	args = append(args, "--proxy-server", address, "--proxy-bypass", "<-loopback>")
	env := decodeStrMap(stored.Env)
	delete(env, "NODE_EXTRA_CA_CERTS")
	if cert != "" {
		env["NODE_EXTRA_CA_CERTS"] = cert
	}
	copy.Args, copy.Env = encodeJSON(args), encodeJSON(env)
	return &copy
}

func (s *Server) listProxyEndpoints(w http.ResponseWriter, r *http.Request) {
	items, e := s.m.pg.ProxyEndpoints(r.Context())
	if e != nil {
		writeErr(w, 500, "list proxies failed")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "enabled": s.m.pg.GetBool(settingProxyPool, false), "system_default_proxy": redactedProxy(s.m.GlobalProxy())})
}
func redactedProxy(raw string) string {
	u, e := url.Parse(raw)
	if e != nil {
		return ""
	}
	u.User = nil
	return u.String()
}
func (s *Server) saveProxyEndpoint(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var request struct {
		Name     string `json:"name"`
		URL      string `json:"url"`
		Enabled  bool   `json:"enabled"`
		CheckURL string `json:"check_url"`
	}
	if json.NewDecoder(r.Body).Decode(&request) != nil {
		writeErr(w, 400, "invalid proxy JSON")
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	request.URL = strings.TrimSpace(request.URL)
	id, _ := strconv.ParseInt(r.PathValue("proxyID"), 10, 64)
	var old *db.ProxyEndpoint
	if id > 0 {
		old, _ = s.m.pg.ProxyEndpoint(r.Context(), id)
		if old == nil {
			writeErr(w, 404, "proxy not found")
			return
		}
		if request.URL == "" {
			request.URL, _ = s.proxyPool.open(old.SealedURL)
		}
	}
	u, e := traffic.ValidateProxyURL(request.URL)
	if e != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || request.Name == "" {
		writeErr(w, 400, "name and valid HTTP/HTTPS/SOCKS5 proxy URL are required")
		return
	}
	check, e := url.Parse(request.CheckURL)
	if e != nil || check.Host == "" || (check.Scheme != "https" && check.Scheme != "http") || check.User != nil {
		writeErr(w, 400, "check_url must be an absolute HTTP URL returning an IP address")
		return
	}
	sealed, e := s.proxyPool.seal(request.URL)
	if e != nil {
		writeErr(w, 500, "encrypt proxy failed")
		return
	}
	endpoint := &db.ProxyEndpoint{ID: id, Name: request.Name, Address: redactedProxy(request.URL), SealedURL: sealed, Enabled: request.Enabled, CheckURL: request.CheckURL, Health: "unchecked"}
	if e = s.m.pg.SaveProxyEndpoint(r.Context(), endpoint); e != nil {
		writeErr(w, 409, e.Error())
		return
	}
	code := 201
	if id > 0 {
		code = 200
	}
	writeJSON(w, code, endpoint)
}
func (s *Server) checkProxyEndpoint(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("proxyID"), 10, 64)
	endpoint, e := s.m.pg.ProxyEndpoint(r.Context(), id)
	if e != nil || endpoint == nil {
		writeErr(w, 404, "proxy not found")
		return
	}
	if e = s.proxyPool.check(r.Context(), endpoint); e != nil {
		writeErr(w, 500, "health check failed")
		return
	}
	writeJSON(w, 200, endpoint)
}
func (s *Server) putProxySettings(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Enabled bool `json:"enabled"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&request) != nil {
		writeErr(w, 400, "invalid settings")
		return
	}
	if request.Enabled != s.m.pg.GetBool(settingProxyPool, false) {
		for _, task := range s.m.List() {
			state := task.lifecycleSnapshot()
			if state.Paused || isTerminalStatus(state.Status) {
				continue
			}
			if _, err := s.applyTaskControlWithCause(task, "pause", errors.New("task proxy configuration changed")); err != nil {
				writeErr(w, 409, "pause active tasks before changing the proxy pool")
				return
			}
		}
		s.proxyPool.mu.Lock()
		for _, g := range s.proxyPool.gateways {
			g.cancelRequests()
		}
		s.proxyPool.mu.Unlock()
	}
	if e := s.m.pg.SetBool(settingProxyPool, request.Enabled); e != nil {
		writeErr(w, 500, "save settings failed")
		return
	}
	s.invalidateTaskAgents()
	writeJSON(w, 200, map[string]any{"enabled": request.Enabled})
}
func (s *Server) taskEgress(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_, ok := s.m.Task(strconv.FormatInt(id, 10))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	lease, e := s.m.pg.TaskEgress(r.Context(), id)
	if r.Method == "POST" {
		if !s.m.pg.GetBool(settingProxyPool, false) {
			writeErr(w, 409, "enable proxy pool before assigning a task exit")
			return
		}
		var request struct {
			ProxyID int64  `json:"proxy_id"`
			Policy  string `json:"policy"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&request) != nil {
			writeErr(w, 400, "invalid lease JSON")
			return
		}
		if request.Policy == "" {
			request.Policy = "pause"
		}
		if request.Policy != "pause" && request.Policy != "failover" && request.Policy != "direct" {
			writeErr(w, 400, "policy must be pause, failover or direct")
			return
		}
		if request.ProxyID == 0 && lease != nil && lease.State == "active" && lease.Policy == request.Policy {
			e = nil
		} else {
			finishChange := s.proxyPool.changeRoute(id)
			lease, e = s.m.pg.AssignTaskEgress(r.Context(), id, request.ProxyID, request.Policy, "assigned")
			finishChange()
		}
	}
	if e != nil {
		writeErr(w, 409, "no healthy unleased proxy is available")
		return
	}
	if lease != nil {
		lease.ProxyURL, _ = s.proxyPool.gateway(id)
	}
	events, _ := s.m.pg.EgressEvents(r.Context(), id)
	if lease == nil {
		writeJSON(w, 200, map[string]any{"lease": nil, "events": events, "system_default_proxy": redactedProxy(s.m.GlobalProxy())})
		return
	}
	writeJSON(w, 200, struct {
		*db.TaskEgress
		Events []db.EgressEvent `json:"events"`
		System string           `json:"system_default_proxy"`
	}{lease, events, redactedProxy(s.m.GlobalProxy())})
}
