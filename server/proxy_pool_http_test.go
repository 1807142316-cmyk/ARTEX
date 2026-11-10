package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/traffic"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProxyPoolLeasesKeepConcurrentTaskTrafficSeparate(t *testing.T) {
	m := newProxyPoolTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, _ := signJWT(s.jwtKey)
	h := s.Handler()
	api := func(method, path string, payload any) (int, map[string]any) {
		b, _ := json.Marshal(payload)
		r := httptest.NewRequest(method, path, bytes.NewReader(b))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	var proxies []*httptest.Server
	for i := 1; i <= 2; i++ {
		exit := fmt.Sprintf("192.0.2.%d", i)
		p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/exit" {
				fmt.Fprintf(w, `{"ip":%q}`, exit)
				return
			}
			fmt.Fprint(w, exit)
		}))
		proxies = append(proxies, p)
		defer p.Close()
		code, out := api("POST", "/api/proxies", map[string]any{"name": exit, "url": p.URL, "check_url": "http://proxy-check.test/exit", "enabled": true})
		if code != 201 {
			t.Fatalf("create proxy: %d %v", code, out)
		}
		id := out["id"].(float64)
		if code, out = api("POST", fmt.Sprintf("/api/proxies/%.0f/check", id), nil); code != 200 || out["health"] != "healthy" || out["exit_ip"] != exit {
			t.Fatalf("health: %d %v", code, out)
		}
	}
	if code, out := api("PUT", "/api/proxies/settings", map[string]any{"enabled": true}); code != 200 {
		t.Fatalf("enable: %d %v", code, out)
	}
	defer api("PUT", "/api/proxies/settings", map[string]any{"enabled": false})
	type taskRoute struct{ id, proxy, exit string }
	var routes []taskRoute
	for i := 1; i <= 2; i++ {
		task, err := m.CreateTask("proxy isolation", "check route", nil, 0, 300)
		if err != nil {
			t.Fatal(err)
		}
		defer api("DELETE", "/api/tasks/"+task.ID, nil)
		code, out := api("POST", "/api/tasks/"+task.ID+"/egress", map[string]any{})
		if code != 200 {
			t.Fatalf("lease: %d %v", code, out)
		}
		routes = append(routes, taskRoute{task.ID, out["proxy_url"].(string), fmt.Sprintf("192.0.2.%d", i)})
	}
	var wg sync.WaitGroup
	for _, route := range routes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u, _ := url.Parse(route.proxy)
			client := http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
			for j := 0; j < 3; j++ {
				resp, err := client.Get("http://target.test/route")
				if err != nil {
					t.Error(err)
					return
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if strings.TrimSpace(string(body)) != route.exit {
					t.Errorf("task %s exit=%s want%s", route.id, body, route.exit)
				}
			}
		}()
	}
	wg.Wait()
	// Retrying assignment cannot replace a live task lease.
	for _, route := range routes {
		code, out := api("POST", "/api/tasks/"+route.id+"/egress", map[string]any{})
		if code != 200 || out["proxy_url"] != route.proxy {
			t.Fatalf("lease changed on retry: %d %v", code, out)
		}
	}
}

func TestProxyPoolRecordedAndUnrecordedHTTPUseSameLease(t *testing.T) {
	m := newProxyPoolTestManager(t)
	defer m.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	recorder, err := traffic.Open(t.TempDir(), address)
	if err != nil {
		t.Fatal(err)
	}
	m.traffic = recorder
	go recorder.Start()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, _ := signJWT(s.jwtKey)
	h := s.Handler()
	api := func(method, path string, payload any) (int, map[string]any) {
		b, _ := json.Marshal(payload)
		r := httptest.NewRequest(method, path, bytes.NewReader(b))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "same task exit") }))
	defer target.Close()
	var forwarded atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("task token leaked to upstream")
		}
		if r.URL.Path == "/exit" {
			fmt.Fprint(w, `{"ip":"192.0.2.71"}`)
			return
		}
		forwarded.Add(1)
		if r.Method == "CONNECT" {
			remote, e := net.Dial("tcp", r.Host)
			if e != nil {
				http.Error(w, e.Error(), 502)
				return
			}
			local, b, e := w.(http.Hijacker).Hijack()
			if e != nil {
				remote.Close()
				return
			}
			defer local.Close()
			defer remote.Close()
			b.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			b.Flush()
			go io.Copy(remote, b)
			io.Copy(local, remote)
			return
		}
		request := r.Clone(r.Context())
		request.RequestURI = ""
		response, e := http.DefaultTransport.RoundTrip(request)
		if e != nil {
			http.Error(w, e.Error(), 502)
			return
		}
		defer response.Body.Close()
		w.WriteHeader(response.StatusCode)
		io.Copy(w, response.Body)
	}))
	defer upstream.Close()
	code, out := api("POST", "/api/proxies", map[string]any{"name": "recorded route", "url": upstream.URL, "enabled": true, "check_url": "http://proxy-check.test/exit"})
	if code != 201 {
		t.Fatalf("create %d %v", code, out)
	}
	api("POST", fmt.Sprintf("/api/proxies/%.0f/check", out["id"]), nil)
	api("PUT", "/api/proxies/settings", map[string]any{"enabled": true})
	defer api("PUT", "/api/proxies/settings", map[string]any{"enabled": false})
	task, err := m.CreateTask("recorded exit", "egress", nil, 0, 300)
	if err != nil {
		t.Fatal(err)
	}
	defer api("DELETE", "/api/tasks/"+task.ID, nil)
	code, out = api("POST", "/api/tasks/"+task.ID+"/egress", map[string]any{})
	if code != 200 {
		t.Fatalf("lease %d %v", code, out)
	}
	u, _ := url.Parse(out["proxy_url"].(string))
	client := http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}, Timeout: 5 * time.Second}
	for _, capture := range []bool{false, true} {
		if err = m.SetTrafficEnabled(capture); err != nil {
			t.Fatal(err)
		}
		if capture {
			for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
				conn, e := net.Dial("tcp", address)
				if e == nil {
					conn.Close()
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		before := forwarded.Load()
		resp, e := client.Get(target.URL + "/route")
		if e != nil {
			t.Fatal(e)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "same task exit" || forwarded.Load() <= before {
			t.Fatalf("capture=%v status=%d body=%s", capture, resp.StatusCode, body)
		}
	}
}

func TestProxyPoolFailurePausesAndOnlyExplicitPolicyAllowsFallback(t *testing.T) {
	m := newProxyPoolTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, _ := signJWT(s.jwtKey)
	h := s.Handler()
	api := func(method, path string, payload any) (int, map[string]any) {
		b, _ := json.Marshal(payload)
		r := httptest.NewRequest(method, path, bytes.NewReader(b))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	proxies := make([]*httptest.Server, 3)
	var endpointIDs []int64
	for i := range proxies {
		exit := fmt.Sprintf("192.0.2.%d", i+11)
		proxies[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/exit" {
				fmt.Fprintf(w, `{"ip":%q}`, exit)
			} else {
				fmt.Fprint(w, exit)
			}
		}))
		defer proxies[i].Close()
		code, out := api("POST", "/api/proxies", map[string]any{"name": exit, "url": proxies[i].URL, "enabled": true, "check_url": "http://proxy-check.test/exit"})
		if code != 201 {
			t.Fatalf("create%d %v", code, out)
		}
		id := int64(out["id"].(float64))
		endpointIDs = append(endpointIDs, id)
		api("POST", fmt.Sprintf("/api/proxies/%d/check", id), nil)
	}
	api("PUT", "/api/proxies/settings", map[string]any{"enabled": true})
	defer api("PUT", "/api/proxies/settings", map[string]any{"enabled": false})
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "direct target") }))
	defer direct.Close()
	for i, policy := range []string{"pause", "failover", "direct"} {
		task, err := m.CreateTask("proxy failure "+policy, "egress", nil, 0, 300)
		if err != nil {
			t.Fatal(err)
		}
		defer api("DELETE", "/api/tasks/"+task.ID, nil)
		code, out := api("POST", "/api/tasks/"+task.ID+"/egress", map[string]any{"proxy_id": endpointIDs[i], "policy": policy})
		if code != 200 {
			t.Fatalf("assign%d %v", code, out)
		}
		u, _ := url.Parse(out["proxy_url"].(string))
		client := http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
		proxies[i].Close()
		resp, err := client.Get(direct.URL)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		_, after := api("GET", "/api/tasks/"+task.ID+"/egress", nil)
		if policy == "pause" {
			if after["state"] != "paused" {
				t.Fatalf("failed proxy should pause lease: %v", after)
			}
			_, taskState := api("GET", "/api/tasks/"+task.ID, nil)
			if taskState["paused"] != true {
				t.Fatalf("task not paused: %v", taskState)
			}
		}
		if policy == "direct" {
			if after["state"] != "direct" {
				t.Fatalf("explicit direct fallback missing: %v", after)
			}
			resp, err = client.Get(direct.URL)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) != "direct target" {
				t.Fatalf("direct fallback body=%s", body)
			}
		}
		if policy == "failover" {
			if after["proxy_id"] == float64(endpointIDs[i]) || after["state"] != "active" {
				t.Fatalf("explicit failover missing: %v", after)
			}
		}
		if len(after["events"].([]any)) < 2 {
			t.Fatalf("transition is not recorded: %v", after)
		}
		api("DELETE", "/api/tasks/"+task.ID, nil)
	}
}

func TestProxyPoolManagementDoesNotExposeCredentialsAndRejectsUnhealthyAssignment(t *testing.T) {
	m := newProxyPoolTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, _ := signJWT(s.jwtKey)
	h := s.Handler()
	request := func(method, path string, payload any, auth bool) *httptest.ResponseRecorder {
		body, _ := json.Marshal(payload)
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		if auth {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if got := request("GET", "/api/proxies", nil, false); got.Code != 401 {
		t.Fatalf("unauth list status%d", got.Code)
	}
	response := request("POST", "/api/proxies", map[string]any{"name": "credentials", "url": "socks5://task-user:secret-value@127.0.0.1:1", "enabled": true, "check_url": "http://proxy-check.test/exit"}, true)
	if response.Code != 201 || strings.Contains(response.Body.String(), "secret-value") || strings.Contains(response.Body.String(), "task-user") {
		t.Fatalf("credential response %d %s", response.Code, response.Body)
	}
	if response = request("GET", "/api/proxies", nil, true); strings.Contains(response.Body.String(), "secret-value") {
		t.Fatal("list leaked credentials")
	}
	task, err := m.CreateTask("unhealthy exit", "egress", nil, 0, 300)
	if err != nil {
		t.Fatal(err)
	}
	defer request("DELETE", "/api/tasks/"+task.ID, nil, true)
	request("PUT", "/api/proxies/settings", map[string]any{"enabled": true}, true)
	defer request("PUT", "/api/proxies/settings", map[string]any{"enabled": false}, true)
	if response = request("POST", "/api/tasks/"+task.ID+"/egress", map[string]any{}, true); response.Code != 409 {
		t.Fatalf("unchecked lease accepted %d %s", response.Code, response.Body)
	}
	if response = request("POST", "/api/proxies", map[string]any{"name": "invalid", "url": "file:///etc/hosts", "enabled": true, "check_url": "http://proxy-check.test/exit"}, true); response.Code != 400 {
		t.Fatalf("invalid scheme accepted%d", response.Code)
	}
}

func newProxyPoolTestManager(t *testing.T) *Manager {
	t.Helper()
	m := newParityTestManager(t)
	if _, err := m.pg.Exec(`DELETE FROM proxy_endpoints`); err != nil {
		m.Close()
		t.Fatal(err)
	}
	return m
}

func TestProxyPoolSOCKS5HealthAndHTTPForwarding(t *testing.T) {
	m := newProxyPoolTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, _ := signJWT(s.jwtKey)
	h := s.Handler()
	api := func(method, path string, payload any) (int, map[string]any) {
		b, _ := json.Marshal(payload)
		r := httptest.NewRequest(method, path, bytes.NewReader(b))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/exit" {
			fmt.Fprint(w, `{"ip":"192.0.2.91"}`)
		} else {
			fmt.Fprint(w, "socks route")
		}
	}))
	defer target.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var connections atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				header := make([]byte, 2)
				if _, e := io.ReadFull(conn, header); e != nil {
					return
				}
				methods := make([]byte, int(header[1]))
				if _, e := io.ReadFull(conn, methods); e != nil {
					return
				}
				conn.Write([]byte{5, 0})
				request := make([]byte, 4)
				if _, e := io.ReadFull(conn, request); e != nil {
					return
				}
				var host string
				switch request[3] {
				case 1:
					ip := make([]byte, 4)
					io.ReadFull(conn, ip)
					host = net.IP(ip).String()
				case 3:
					size := make([]byte, 1)
					io.ReadFull(conn, size)
					name := make([]byte, int(size[0]))
					io.ReadFull(conn, name)
					host = string(name)
				default:
					return
				}
				port := make([]byte, 2)
				if _, e := io.ReadFull(conn, port); e != nil {
					return
				}
				remote, e := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(int(port[0])*256+int(port[1]))))
				if e != nil {
					conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer remote.Close()
				connections.Add(1)
				conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go io.Copy(remote, conn)
				io.Copy(conn, remote)
			}()
		}
	}()
	code, out := api("POST", "/api/proxies", map[string]any{"name": "socks5", "url": "socks5://" + listener.Addr().String(), "enabled": true, "check_url": target.URL + "/exit"})
	if code != 201 {
		t.Fatalf("create %d %v", code, out)
	}
	code, out = api("POST", fmt.Sprintf("/api/proxies/%.0f/check", out["id"]), nil)
	if code != 200 || out["exit_ip"] != "192.0.2.91" {
		t.Fatalf("socks health %d %v", code, out)
	}
	api("PUT", "/api/proxies/settings", map[string]any{"enabled": true})
	defer api("PUT", "/api/proxies/settings", map[string]any{"enabled": false})
	task, err := m.CreateTask("socks route", "egress", nil, 0, 300)
	if err != nil {
		t.Fatal(err)
	}
	defer api("DELETE", "/api/tasks/"+task.ID, nil)
	code, out = api("POST", "/api/tasks/"+task.ID+"/egress", map[string]any{})
	if code != 200 {
		t.Fatalf("lease %d %v", code, out)
	}
	u, _ := url.Parse(out["proxy_url"].(string))
	client := http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}, Timeout: 5 * time.Second}
	resp, err := client.Get(target.URL + "/test")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "socks route" || connections.Load() < 2 {
		t.Fatalf("socks response %s,connections%d", body, connections.Load())
	}
}

func TestProxyPoolPauseClosesEstablishedTunnelBeforeEndpointReuse(t *testing.T) {
	m := newProxyPoolTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, _ := signJWT(s.jwtKey)
	h := s.Handler()
	api := func(method, path string, payload any) (int, map[string]any) {
		b, _ := json.Marshal(payload)
		r := httptest.NewRequest(method, path, bytes.NewReader(b))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			fmt.Fprint(w, `{"ip":"192.0.2.111"}`)
			return
		}
		conn, buffer, e := w.(http.Hijacker).Hijack()
		if e != nil {
			return
		}
		defer conn.Close()
		buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		buffer.Flush()
		io.Copy(conn, buffer)
	}))
	defer proxy.Close()
	code, out := api("POST", "/api/proxies", map[string]any{"name": "tunnel", "url": proxy.URL, "enabled": true, "check_url": "http://proxy-check.test/exit"})
	if code != 201 {
		t.Fatalf("create%d %v", code, out)
	}
	id := out["id"]
	api("POST", fmt.Sprintf("/api/proxies/%.0f/check", id), nil)
	api("PUT", "/api/proxies/settings", map[string]any{"enabled": true})
	defer api("PUT", "/api/proxies/settings", map[string]any{"enabled": false})
	task, err := m.CreateTask("tunnel pause", "egress", nil, 0, 300)
	if err != nil {
		t.Fatal(err)
	}
	defer api("DELETE", "/api/tasks/"+task.ID, nil)
	_, out = api("POST", "/api/tasks/"+task.ID+"/egress", map[string]any{})
	u, _ := url.Parse(out["proxy_url"].(string))
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "CONNECT target.test:443 HTTP/1.1\r\nHost: target.test:443\r\n\r\n")
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("CONNECT%v %v", response, err)
	}
	fmt.Fprint(conn, "before")
	got := make([]byte, 6)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err = io.ReadFull(reader, got); err != nil || string(got) != "before" {
		t.Fatalf("initial echo %q %v", got, err)
	}
	code, out = api("POST", "/api/tasks/"+task.ID+"/control", map[string]any{"action": "pause"})
	if code != 200 {
		t.Fatalf("pause%d %v", code, out)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	fmt.Fprint(conn, "after")
	_, err = reader.ReadByte()
	if err == nil {
		t.Fatal("paused task retained established tunnel")
	}
	if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
		t.Fatal("paused tunnel remained open until timeout")
	}
	other, e := m.CreateTask("reuse closed tunnel", "egress", nil, 0, 300)
	if e != nil {
		t.Fatal(e)
	}
	defer api("DELETE", "/api/tasks/"+other.ID, nil)
	code, out = api("POST", "/api/tasks/"+other.ID+"/egress", map[string]any{})
	if code != 200 || out["proxy_id"] != id {
		t.Fatalf("released endpoint not reusable: %d %v", code, out)
	}
}
