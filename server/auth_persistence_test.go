package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateKeyStartupRejectsCorruptionAndBrowsableLocation(t *testing.T) {
	if os.Getenv("ARTEX_TEST_KEY_STARTUP") == "1" {
		New(context.Background(), nil, "", os.Getenv("ARTEX_TEST_DATA_DIR"), os.Getenv("ARTEX_TEST_KEY_DIR"), os.Getenv("ARTEX_TEST_LEGACY_DIR"))
		return
	}
	for _, scenario := range []string{"corrupt-private-key", "corrupt-legacy-key", "inside-workspace", "conflicting-legacy-key", "corrupt-legacy-with-private-key"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			dataDir, keyDir, legacyDir := filepath.Join(root, "data"), filepath.Join(root, "private"), filepath.Join(root, "legacy")
			if scenario == "inside-workspace" {
				keyDir = filepath.Join(dataDir, "private")
			}
			var corruptPath string
			if scenario != "inside-workspace" {
				dir := keyDir
				if scenario == "corrupt-legacy-key" || scenario == "conflicting-legacy-key" || scenario == "corrupt-legacy-with-private-key" {
					dir = legacyDir
				}
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				corruptPath = filepath.Join(dir, jwtKeyFilename)
				if err := os.WriteFile(corruptPath, []byte("broken"), 0600); err != nil {
					t.Fatal(err)
				}
				if scenario == "conflicting-legacy-key" || scenario == "corrupt-legacy-with-private-key" {
					if err := os.MkdirAll(keyDir, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(keyDir, jwtKeyFilename), []byte("retained-private-key-12345678901234567890"), 0600); err != nil {
						t.Fatal(err)
					}
					if scenario == "conflicting-legacy-key" {
						if err := os.WriteFile(corruptPath, []byte("conflicting-legacy-key-12345678901234567890"), 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestPrivateKeyStartupRejectsCorruptionAndBrowsableLocation$")
			// Startup rejects the key before using a manager. Avoid inheriting the
			// parent's suite-level PostgreSQL advisory lock in this subprocess.
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(strings.ToUpper(entry), "ARTEX_PG_DSN=") && !strings.HasPrefix(strings.ToUpper(entry), "ARTEX_CONFIG=") {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			cmd.Env = append(cmd.Env, "ARTEX_PG_DSN=", "ARTEX_CONFIG="+filepath.Join(root, "absent.json"), "ARTEX_TEST_KEY_STARTUP=1", "ARTEX_TEST_DATA_DIR="+dataDir, "ARTEX_TEST_KEY_DIR="+keyDir, "ARTEX_TEST_LEGACY_DIR="+legacyDir)
			output, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(output), "[auth] JWT key:") {
				t.Fatalf("startup did not fail on key configuration: %v %s", err, output)
			}
			if corruptPath != "" {
				unchanged, err := os.ReadFile(corruptPath)
				want := "broken"
				if scenario == "conflicting-legacy-key" {
					want = "conflicting-legacy-key-12345678901234567890"
				}
				if err != nil || string(unchanged) != want {
					t.Fatalf("invalid key overwritten: %v", err)
				}
				if scenario == "conflicting-legacy-key" || scenario == "corrupt-legacy-with-private-key" {
					private, err := os.ReadFile(filepath.Join(keyDir, jwtKeyFilename))
					if err != nil || string(private) != "retained-private-key-12345678901234567890" {
						t.Fatalf("retained private key overwritten: %v", err)
					}
				}
			}
		})
	}
}

func TestPersistentKeyKeepsLoginAndProxyCredentialsAfterRecreation(t *testing.T) {
	m := newProxyPoolTestManager(t)
	defer m.Close()
	dataDir := m.dir
	keyDir := filepath.Join(t.TempDir(), "private-runtime")
	legacyDir := t.TempDir()
	legacyKey := []byte("persistent-key-for-http-acceptance-123456789")
	if err := os.WriteFile(filepath.Join(legacyDir, jwtKeyFilename), legacyKey, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, m, t.TempDir(), dataDir, keyDir, legacyDir)
	token, err := signJWT(legacyKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(s *Server, method, path string, value any) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code < 200 || w.Code >= 300 {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body)
		}
		return w
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("persistent:secret")) {
			t.Error("stored proxy credentials were not restored")
		}
		fmt.Fprint(w, `{"ip":"192.0.2.91"}`)
	}))
	defer upstream.Close()
	w := request(s, "POST", "/api/proxies", map[string]any{
		"name": "persistent proxy", "url": strings.Replace(upstream.URL, "://", "://persistent:secret@", 1),
		"enabled": true, "check_url": "http://exit.invalid/check",
	})
	var endpoint struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &endpoint); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := os.Stat(filepath.Join(legacyDir, jwtKeyFilename)); !os.IsNotExist(err) {
		t.Fatalf("legacy signing key was not removed: %v", err)
	}
	// A crash after writing the destination can leave matching old copies.
	// The next startup must finish removing all browsable/executable copies.
	for _, dir := range []string{legacyDir, dataDir} {
		if err := os.WriteFile(filepath.Join(dir, jwtKeyFilename), legacyKey, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	recreated := New(ctx2, m, t.TempDir(), dataDir, keyDir, legacyDir)
	w = request(recreated, "POST", fmt.Sprintf("/api/proxies/%d/check", endpoint.ID), nil)
	if !strings.Contains(w.Body.String(), `"healthy"`) || !strings.Contains(w.Body.String(), "192.0.2.91") {
		t.Fatalf("recreated proxy health: %s", w.Body)
	}
	w = request(recreated, "GET", "/api/workspace/list", nil)
	if strings.Contains(w.Body.String(), jwtKeyFilename) {
		t.Fatal("signing key exposed in browsable workspace")
	}
	if _, err := os.Stat(filepath.Join(legacyDir, jwtKeyFilename)); !os.IsNotExist(err) {
		t.Fatalf("matching executable-side key was not removed on resumed migration: %v", err)
	}
}
