package scantemplate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
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
	if err := yaml.Unmarshal(content, &document); err != nil {
		return Metadata{}, fmt.Errorf("%w: malformed YAML", ErrInvalidTemplate)
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
	if err := allowKeys(info, "name", "author", "severity", "description", "reference", "tags"); err != nil {
		return Metadata{}, err
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
	if !ok || len(requests) == 0 {
		return Metadata{}, fmt.Errorf("%w: at least one HTTP check is required", ErrInvalidTemplate)
	}
	for _, requestValue := range requests {
		request, ok := requestValue.(map[string]any)
		if !ok {
			return Metadata{}, fmt.Errorf("%w: HTTP check must be a mapping", ErrInvalidTemplate)
		}
		if err := allowKeys(request, "method", "path", "matchers"); err != nil {
			return Metadata{}, err
		}
		if strings.ToUpper(text(request["method"])) != "GET" {
			return Metadata{}, fmt.Errorf("%w: only passive GET checks are accepted", ErrInvalidTemplate)
		}
		paths, ok := request["path"].([]any)
		if !ok || len(paths) == 0 {
			return Metadata{}, fmt.Errorf("%w: HTTP check requires a path", ErrInvalidTemplate)
		}
		for _, pathValue := range paths {
			path := text(pathValue)
			remainder := strings.TrimPrefix(path, "{{BaseURL}}")
			if !strings.HasPrefix(path, "{{BaseURL}}/") || strings.ContainsAny(path, "\r\n") || strings.Contains(remainder, "{{") || strings.Contains(remainder, "}}") {
				return Metadata{}, fmt.Errorf("%w: paths must be static paths under BaseURL", ErrInvalidTemplate)
			}
		}
		matchers, ok := request["matchers"].([]any)
		if !ok || len(matchers) == 0 {
			return Metadata{}, fmt.Errorf("%w: HTTP check requires a matcher", ErrInvalidTemplate)
		}
		for _, matcherValue := range matchers {
			matcher, ok := matcherValue.(map[string]any)
			if !ok || allowKeys(matcher, "type", "status") != nil || text(matcher["type"]) != "status" {
				return Metadata{}, fmt.Errorf("%w: only status matchers are accepted", ErrInvalidTemplate)
			}
			statuses, ok := matcher["status"].([]any)
			if !ok || len(statuses) == 0 {
				return Metadata{}, fmt.Errorf("%w: status matcher requires status codes", ErrInvalidTemplate)
			}
			for _, status := range statuses {
				if number, ok := status.(int); !ok || number < 100 || number > 599 {
					return Metadata{}, fmt.Errorf("%w: status code is out of range", ErrInvalidTemplate)
				}
			}
		}
	}
	hash := sha256.Sum256(content)
	metadata.ContentHash = hex.EncodeToString(hash[:])
	return metadata, nil
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
