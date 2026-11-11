package server

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestTrimConnectionTextKeepsUTF8Intact: the error/output caps are byte caps, so
// slicing blindly can cut a multi-byte rune in half. A truncated message must
// still be valid UTF-8 (CJK and emoji included) or the UI renders mojibake.
func TestTrimConnectionTextKeepsUTF8Intact(t *testing.T) {
	cases := []struct {
		name string
		text string
		max  int
		want string
	}{
		{"ascii under cap", "hello", 10, "hello"},
		{"ascii over cap", "hello world", 5, "hello"},
		{"cjk boundary", strings.Repeat("测", 10), 7, strings.Repeat("测", 2)},
		{"emoji boundary", "🦀🦀🦀", 5, "🦀"},
		{"mixed", "cmd 输出 failed", 8, "cmd 输"},
		{"zero cap", "abc", 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := trimConnectionText(tc.text, tc.max)
			if !utf8.ValidString(got) {
				t.Fatalf("trim produced invalid UTF-8: %q", got)
			}
			if len(got) > tc.max {
				t.Fatalf("trim exceeded cap: %d > %d", len(got), tc.max)
			}
			if got != tc.want {
				t.Fatalf("trim=%q want %q", got, tc.want)
			}
		})
	}
}
