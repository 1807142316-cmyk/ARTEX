package scantemplate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var ErrInvalidTemplate = errors.New("invalid scan template")

type Metadata struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Author      string   `json:"author"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	References  []string `json:"references"`
	Protocol    string   `json:"protocol"`
	ContentHash string   `json:"content_hash"`
}

var allowedSeverities = map[string]bool{
	"info": true, "low": true, "medium": true, "high": true, "critical": true, "unknown": true,
}

func Validate(content []byte) (Metadata, error) {
	var document map[string]any
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	if err := decoder.Decode(&document); err != nil {
		return Metadata{}, fmt.Errorf("%w: malformed YAML", ErrInvalidTemplate)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Metadata{}, fmt.Errorf("%w: exactly one YAML document is required", ErrInvalidTemplate)
	}
	if document == nil {
		return Metadata{}, fmt.Errorf("%w: document is empty", ErrInvalidTemplate)
	}
	if err := allowKeys(document, "id", "info", "http"); err != nil {
		return Metadata{}, err
	}
	metadata := Metadata{ID: text(document["id"]), Protocol: "http", Tags: []string{}, References: []string{}}
	info, ok := document["info"].(map[string]any)
	if metadata.ID == "" || !ok {
		return Metadata{}, fmt.Errorf("%w: id and info are required", ErrInvalidTemplate)
	}
	if err := allowKeys(info, "name", "author", "severity", "description", "reference", "tags", "metadata", "classification"); err != nil {
		return Metadata{}, err
	}
	for _, key := range []string{"metadata", "classification"} {
		if value, exists := info[key]; exists {
			if _, ok := value.(map[string]any); !ok {
				return Metadata{}, fmt.Errorf("%w: %s must be descriptive metadata", ErrInvalidTemplate, key)
			}
		}
	}
	metadata.Name = text(info["name"])
	metadata.Author = text(info["author"])
	metadata.Severity = strings.ToLower(text(info["severity"]))
	metadata.Description = text(info["description"])
	if metadata.Name == "" || !allowedSeverities[metadata.Severity] {
		return Metadata{}, fmt.Errorf("%w: name and a supported severity are required", ErrInvalidTemplate)
	}
	metadata.Tags = stringsFromYAML(info["tags"])
	if tags, ok := info["tags"].(string); ok {
		metadata.Tags = stringsFromYAML(strings.Split(tags, ","))
	}
	metadata.References = stringsFromYAML(info["reference"])
	for _, reference := range metadata.References {
		parsed, err := url.ParseRequestURI(reference)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
			return Metadata{}, fmt.Errorf("%w: references must be absolute HTTP URLs", ErrInvalidTemplate)
		}
	}
	requests, ok := document["http"].([]any)
	if !ok || len(requests) == 0 || len(requests) > 8 {
		return Metadata{}, fmt.Errorf("%w: at least one HTTP check is required", ErrInvalidTemplate)
	}
	pathCount := 0
	for _, requestValue := range requests {
		request, ok := requestValue.(map[string]any)
		if !ok {
			return Metadata{}, fmt.Errorf("%w: HTTP check must be a mapping", ErrInvalidTemplate)
		}
		if err := allowKeys(request, "method", "path", "matchers", "matchers-condition", "extractors", "stop-at-first-match"); err != nil {
			return Metadata{}, err
		}
		if err := validateCondition(request, "matchers-condition"); err != nil {
			return Metadata{}, err
		}
		if value, ok := request["stop-at-first-match"]; ok {
			if _, ok := value.(bool); !ok {
				return Metadata{}, fmt.Errorf("%w: stop-at-first-match must be boolean", ErrInvalidTemplate)
			}
		}
		if strings.ToUpper(text(request["method"])) != "GET" {
			return Metadata{}, fmt.Errorf("%w: only passive GET checks are accepted", ErrInvalidTemplate)
		}
		paths, ok := request["path"].([]any)
		if !ok || len(paths) == 0 {
			return Metadata{}, fmt.Errorf("%w: HTTP check requires a path", ErrInvalidTemplate)
		}
		for _, pathValue := range paths {
			pathCount++
			path := text(pathValue)
			remainder := strings.TrimPrefix(path, "{{BaseURL}}")
			if pathCount > 16 || len(path) > 2048 || (path != "{{BaseURL}}" && !strings.HasPrefix(path, "{{BaseURL}}/")) || strings.ContainsAny(path, "\r\n") || strings.Contains(remainder, "{{") || strings.Contains(remainder, "}}") {
				return Metadata{}, fmt.Errorf("%w: paths must be static paths under BaseURL", ErrInvalidTemplate)
			}
		}
		matchers, ok := request["matchers"].([]any)
		if !ok || len(matchers) == 0 || len(matchers) > 32 {
			return Metadata{}, fmt.Errorf("%w: HTTP check requires a matcher", ErrInvalidTemplate)
		}
		for _, matcherValue := range matchers {
			matcher, ok := matcherValue.(map[string]any)
			if !ok {
				return Metadata{}, fmt.Errorf("%w: matcher must be a mapping", ErrInvalidTemplate)
			}
			if err := validateMatcher(matcher); err != nil {
				return Metadata{}, err
			}
		}
		if values, exists := request["extractors"]; exists {
			extractors, ok := values.([]any)
			if !ok || len(extractors) > 16 {
				return Metadata{}, fmt.Errorf("%w: invalid extractors", ErrInvalidTemplate)
			}
			for _, value := range extractors {
				extractor, ok := value.(map[string]any)
				if !ok {
					return Metadata{}, fmt.Errorf("%w: extractor must be a mapping", ErrInvalidTemplate)
				}
				if err := validateExtractor(extractor); err != nil {
					return Metadata{}, err
				}
			}
		}
	}
	hash := sha256.Sum256(content)
	metadata.ContentHash = hex.EncodeToString(hash[:])
	return metadata, nil
}

func validateCondition(value map[string]any, key string) error {
	if condition, exists := value[key]; exists && condition != "and" && condition != "or" {
		return fmt.Errorf("%w: %s must be and or or", ErrInvalidTemplate, key)
	}
	return nil
}

func validatePart(value map[string]any) error {
	if part, exists := value["part"]; exists && part != "body" && part != "header" && part != "all" {
		return fmt.Errorf("%w: part must be body, header or all", ErrInvalidTemplate)
	}
	return nil
}

func validateStrings(value any, regex bool) error {
	values, ok := value.([]any)
	if !ok || len(values) == 0 || len(values) > 32 {
		return fmt.Errorf("%w: expected 1 to 32 string values", ErrInvalidTemplate)
	}
	for _, value := range values {
		item, ok := value.(string)
		if !ok || item == "" || len(item) > 4096 || strings.Contains(item, "{{") {
			return fmt.Errorf("%w: static string required", ErrInvalidTemplate)
		}
		if regex {
			if _, err := regexp.Compile(item); err != nil {
				return fmt.Errorf("%w: invalid regular expression: %v", ErrInvalidTemplate, err)
			}
		}
	}
	return nil
}

func validateMatcher(m map[string]any) error {
	if err := validateName(m); err != nil {
		return err
	}
	kind := text(m["type"])
	if err := validateCondition(m, "condition"); err != nil {
		return err
	}
	if err := validatePart(m); err != nil {
		return err
	}
	switch kind {
	case "status":
		if err := allowKeys(m, "type", "status", "condition", "name", "negative"); err != nil {
			return err
		}
		values, ok := m["status"].([]any)
		if !ok || len(values) == 0 || len(values) > 100 {
			return fmt.Errorf("%w: status matcher requires codes", ErrInvalidTemplate)
		}
		for _, value := range values {
			code, ok := value.(int)
			if !ok || code < 100 || code > 599 {
				return fmt.Errorf("%w: invalid status code", ErrInvalidTemplate)
			}
		}
	case "word", "regex":
		key := "words"
		if kind == "regex" {
			key = "regex"
		}
		if err := allowKeys(m, "type", key, "part", "condition", "name", "negative", "case-insensitive"); err != nil {
			return err
		}
		if err := validateStrings(m[key], kind == "regex"); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: supported matcher types are status, word and regex", ErrInvalidTemplate)
	}
	for _, key := range []string{"negative", "case-insensitive"} {
		if value, exists := m[key]; exists {
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("%w: %s must be boolean", ErrInvalidTemplate, key)
			}
		}
	}
	return nil
}

func validateExtractor(m map[string]any) error {
	if err := validateName(m); err != nil {
		return err
	}
	if err := validatePart(m); err != nil {
		return err
	}
	kind := text(m["type"])
	switch kind {
	case "regex":
		if err := allowKeys(m, "type", "regex", "part", "name", "group"); err != nil {
			return err
		}
		if err := validateStrings(m["regex"], true); err != nil {
			return err
		}
		if group, exists := m["group"]; exists {
			number, ok := group.(int)
			if !ok || number < 0 || number > 32 {
				return fmt.Errorf("%w: invalid extraction group", ErrInvalidTemplate)
			}
			for _, value := range m["regex"].([]any) {
				expression, _ := regexp.Compile(value.(string))
				if number > expression.NumSubexp() {
					return fmt.Errorf("%w: extraction group does not exist", ErrInvalidTemplate)
				}
			}
		}
	case "kval":
		if err := allowKeys(m, "type", "kval", "part", "name"); err != nil {
			return err
		}
		return validateStrings(m["kval"], false)
	default:
		return fmt.Errorf("%w: supported extractor types are regex and kval", ErrInvalidTemplate)
	}
	return nil
}

func validateName(value map[string]any) error {
	if name, exists := value["name"]; exists {
		text, ok := name.(string)
		if !ok || text == "" || len(text) > 256 || strings.Contains(text, "{{") {
			return fmt.Errorf("%w: matcher/extractor name must be a static string", ErrInvalidTemplate)
		}
	}
	return nil
}

func allowKeys(values map[string]any, allowed ...string) error {
	set := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		set[key] = struct{}{}
	}
	for key := range values {
		if _, ok := set[key]; !ok {
			return fmt.Errorf("%w: unsupported field %q", ErrInvalidTemplate, key)
		}
	}
	return nil
}

func text(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case int:
		return fmt.Sprintf("%d", typed)
	default:
		return ""
	}
}

func stringsFromYAML(value any) []string {
	if value == nil {
		return []string{}
	}
	if single, ok := value.(string); ok {
		return []string{strings.TrimSpace(single)}
	}
	if items, ok := value.([]string); ok {
		out := make([]string, 0, len(items))
		for _, item := range items {
			if item = strings.TrimSpace(item); item != "" {
				out = append(out, item)
			}
		}
		return out
	}
	items, ok := value.([]any)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if text := text(item); text != "" {
			out = append(out, text)
		}
	}
	return out
}
