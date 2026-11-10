package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

func TestProxyRouteChangeRejectsCanceledRequestWithoutPausingNewRoute(t *testing.T) {
	m := newProxyPoolTestManager(t)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, _ := signJWT(s.jwtKey)
	do := func(method, path string, payload any) (int, map[string]any) {
		body, _ := json.Marshal(payload)
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/exit" {
			fmt.Fprint(w, `{"ip":"192.0.2.88"}`)
		} else {
			fmt.Fprint(w, "new-route-success")
		}
	}))
	defer proxy.Close()
	status, endpoint := do("POST", "/api/proxies", map[string]any{"name": "change-route", "url": proxy.URL, "check_url": "http://proxy-check.test/exit", "enabled": true})
	if status != 201 {
		t.Fatalf("create=%d %v", status, endpoint)
	}
	if status, out := do("POST", fmt.Sprintf("/api/proxies/%.0f/check", endpoint["id"].(float64)), nil); status != 200 {
		t.Fatalf("check=%d %v", status, out)
	}
	if status, out := do("PUT", "/api/proxies/settings", map[string]any{"enabled": true}); status != 200 {
		t.Fatalf("enable=%d %v", status, out)
	}
	defer do("PUT", "/api/proxies/settings", map[string]any{"enabled": false})
	task, err := m.CreateTask("route change", "keep new route", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer do("DELETE", "/api/tasks/"+task.ID, nil)
	status, lease := do("POST", "/api/tasks/"+task.ID+"/egress", map[string]any{})
	if status != 200 {
		t.Fatalf("assign=%d %v", status, lease)
	}
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	finish := s.proxyPool.changeRoute(id)
	u, _ := url.Parse(lease["proxy_url"].(string))
	client := http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
	resp, err := client.Get("http://target.test/during-change")
	if err != nil {
		finish()
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	finish()
	if resp.StatusCode != 503 {
		t.Fatalf("changing route status=%d", resp.StatusCode)
	}
	status, current := do("GET", "/api/tasks/"+task.ID, nil)
	if status != 200 || current["paused"] == true {
		t.Fatalf("route change paused task: %d %v", status, current)
	}
	resp, err = client.Get("http://target.test/after-change")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "new-route-success" {
		t.Fatalf("new route=%d %s", resp.StatusCode, body)
	}
}
