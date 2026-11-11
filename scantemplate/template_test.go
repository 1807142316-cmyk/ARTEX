package scantemplate

import (
	"strings"
	"testing"
)

func TestValidateTemplateAcceptsPassiveHTTPGetTemplate(t *testing.T) {
	input := `id: artex-robots-index
info:
  name: Public robots.txt availability
  author: ARTEX
  severity: info
  description: Detects whether a public robots.txt resource is available.
  reference:
    - https://www.rfc-editor.org/rfc/rfc9309
  tags: exposure,robots
http:
  - method: GET
    path:
      - "{{BaseURL}}/robots.txt"
    matchers:
      - type: status
        status:
          - 200
`

	got, err := Validate([]byte(input))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.ID != "artex-robots-index" || got.Name != "Public robots.txt availability" || got.Severity != "info" {
		t.Fatalf("unexpected metadata: %+v", got)
	}
	if !strings.Contains(got.Protocol, "http") || len(got.References) != 1 || got.References[0] != "https://www.rfc-editor.org/rfc/rfc9309" {
		t.Fatalf("protocol/reference metadata missing: %+v", got)
	}
	if len(got.Tags) != 2 || got.Tags[0] != "exposure" || got.Tags[1] != "robots" {
		t.Fatalf("comma-separated tags were not normalized: %+v", got.Tags)
	}
}

func TestValidateRejectsActiveOrUnsafeTemplateFeatures(t *testing.T) {
	cases := map[string]string{
		"post method": `id: unsafe-post
info: {name: Unsafe, severity: info}
http:
  - method: POST
    path: ["{{BaseURL}}/"]
    matchers: [{type: status, status: [200]}]
`,
		"raw request": `id: unsafe-raw
info: {name: Unsafe, severity: info}
http:
  - raw: ["GET / HTTP/1.1"]
    matchers: [{type: status, status: [200]}]
`,
		"code protocol": `id: unsafe-code
info: {name: Unsafe, severity: info}
code:
  - engine: sh
    source: echo unsafe
`,
		"payload attack": `id: unsafe-payload
info: {name: Unsafe, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    attack: pitchfork
    payloads: {q: [test]}
    matchers: [{type: status, status: [200]}]
`,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Validate([]byte(input)); err == nil {
				t.Fatal("expected unsafe template rejection")
			}
		})
	}
}

func TestValidateRejectsInvalidTemplateMetadata(t *testing.T) {
	for name, input := range map[string]string{
		"missing id": `info: {name: Unidentified, severity: info}
http: [{method: GET, path: ["{{BaseURL}}/"], matchers: [{type: status, status: [200]}]}]
`,
		"invalid severity": `id: wrong-severity
info: {name: Invalid severity, severity: catastrophic}
http: [{method: GET, path: ["{{BaseURL}}/"], matchers: [{type: status, status: [200]}]}]
`,
		"missing matcher": `id: no-matcher
info: {name: No matcher, severity: info}
http: [{method: GET, path: ["{{BaseURL}}/"]}]
`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Validate([]byte(input)); err == nil {
				t.Fatal("expected invalid template rejection")
			}
		})
	}
}

func TestValidateRejectsInvalidContentMatcherAndExtractorSyntax(t *testing.T) {
	for name, check := range map[string]string{
		"invalid regex":        `matchers: [{type: regex, regex: ['[']}]`,
		"dynamic word":         `matchers: [{type: word, words: ['{{randstr}}']}]`,
		"invalid part":         `matchers: [{type: word, part: request, words: [nginx]}]`,
		"invalid condition":    `matchers: [{type: word, condition: xor, words: [nginx]}]`,
		"invalid negative":     `matchers: [{type: word, negative: yes, words: [nginx]}]`,
		"invalid matcher name": `matchers: [{type: word, name: [nginx], words: [nginx]}]`,
		"invalid extraction group": `matchers: [{type: status, status: [200]}]
    extractors: [{type: regex, regex: ['nginx/[0-9.]+'], group: 1}]`,
		"invalid extractor type": `matchers: [{type: status, status: [200]}]
    extractors: [{type: dsl, dsl: [body]}]`,
	} {
		t.Run(name, func(t *testing.T) {
			input := "id: invalid-content\ninfo: {name: Invalid content, severity: info}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    " + check + "\n"
			if _, err := Validate([]byte(input)); err == nil {
				t.Fatal("invalid matcher/extractor was accepted")
			}
		})
	}
}
