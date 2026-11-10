package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func TestTaskProxyBashOverridesInheritedNoProxyAndPreservesLegacyBypass(t *testing.T) {
	curl := "curl"
	if runtime.GOOS == "windows" {
		curl = "curl.exe"
	}
	if _, err := exec.LookPath(curl); err != nil {
		t.Skip("curl executable unavailable")
	}
	t.Setenv("NO_PROXY", "*")
	t.Setenv("no_proxy", "*")
	var proxied atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxied.Add(1); fmt.Fprint(w, "task-proxy-body") }))
	defer proxy.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "direct-target-body") }))
	defer target.Close()
	for _, clearBypass := range []bool{true, false} {
		input, _ := json.Marshal(map[string]any{"command": curl + " --silent --show-error --max-time 5 " + target.URL, "timeout_ms": 10000})
		result, err := actool.NewBash().Call(context.Background(), input, &actool.ToolContext{Env: taskProxyEnv(proxy.URL, "", clearBypass)})
		if err != nil {
			t.Fatal(err)
		}
		expected := "direct-target-body"
		if clearBypass {
			expected = "task-proxy-body"
		}
		if !strings.Contains(result.Flatten(), expected) {
			t.Fatalf("clearBypass=%t got=%s", clearBypass, result.Flatten())
		}
	}
	if proxied.Load() != 1 {
		t.Fatalf("proxy count=%d want1", proxied.Load())
	}
}
