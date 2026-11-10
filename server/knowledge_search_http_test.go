package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

func TestKnowledgeSearchCanExcludeBodyWithoutHidingMetadata(t *testing.T) {
	m := newParityTestManager(t)
	defer m.Close()
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	request := func(method, path string, input any) map[string]any {
		t.Helper()
		var body bytes.Buffer
		if input != nil {
			if err := json.NewEncoder(&body).Encode(input); err != nil {
				t.Fatal(err)
			}
		}
		r := httptest.NewRequest(method, path, &body)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code < 200 || w.Code >= 300 {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body)
		}
		var result map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	marker := fmt.Sprintf("body-only-%d", time.Now().UnixNano())
	created := request("POST", "/api/knowledge", map[string]string{
		"code":    "metadata-" + marker,
		"summary": "A distinct metadata phrase",
		"body":    "Only the document body contains hidden-" + marker,
	})
	id := int64(created["id"].(float64))
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM knowledge_entries WHERE id=$1`, id) })
	for _, tc := range []struct {
		query string
		want  float64
	}{
		{"?q=hidden-" + marker, 1},
		{"?q=hidden-" + marker + "&match_body=true", 1},
		{"?q=hidden-" + marker + "&match_body=false", 0},
		{"?q=metadata-" + marker + "&match_body=false", 1},
	} {
		result := request("GET", "/api/knowledge"+tc.query, nil)
		if result["total"] != tc.want {
			t.Fatalf("%s: want total %v, got %v", tc.query, tc.want, result["total"])
		}
	}
}
