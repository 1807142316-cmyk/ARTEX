package scantemplate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const EngineVersion = "3.4.10"

type EngineStatus struct {
	Available    bool     `json:"available"`
	Version      string   `json:"version"`
	Error        string   `json:"error,omitempty"`
	Capabilities []string `json:"capabilities"`
}

type Match struct {
	Matched   bool   `json:"matched"`
	URL       string `json:"url"`
	Request   string `json:"request"`
	Response  string `json:"response"`
	FindingID int64  `json:"finding_id,omitempty"`
}

func EnginePath() string {
	if path := strings.TrimSpace(os.Getenv("ARTEX_NUCLEI_PATH")); path != "" {
		return path
	}
	return "nuclei"
}

func CheckEngine(ctx context.Context) EngineStatus {
	status := EngineStatus{Version: EngineVersion, Capabilities: []string{"http-static-get", "status-matchers", "request-response-evidence"}}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, EnginePath(), "-version", "-nc").CombinedOutput()
	if err != nil {
		status.Error = "Nuclei unavailable: " + err.Error()
		return status
	}
	version := regexp.MustCompile(`Nuclei Engine Version: v([0-9.]+)`).FindSubmatch(out)
	if len(version) != 2 || string(version[1]) != EngineVersion {
		status.Error = "Nuclei version must be " + EngineVersion
		return status
	}
	status.Available = true
	return status
}

func ValidateTarget(target string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(target))
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("target must be an absolute HTTP(S) URL without credentials, query or fragment")
	}
	if len(target) > 2048 {
		return "", errors.New("target exceeds 2048 characters")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

type limitedOutput struct {
	bytes.Buffer
	exceeded bool
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	const limit = 12 << 20
	n := len(p)
	remaining := limit - b.Len()
	if remaining < len(p) {
		p = p[:remaining]
		b.exceeded = true
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}

// Run invokes only a validated, locally supplied template. Auto downloads,
// external callbacks, redirects and configuration inheritance are disabled.
func Run(ctx context.Context, content, target string) ([]Match, error) {
	return RunWithProxy(ctx, content, target, "", "")
}

func RunWithProxy(ctx context.Context, content, target, proxyURL, caFile string) ([]Match, error) {
	if _, err := Validate([]byte(content)); err != nil {
		return nil, err
	}
	if _, err := ValidateTarget(target); err != nil {
		return nil, err
	}
	status := CheckEngine(ctx)
	if !status.Available {
		return nil, errors.New(status.Error)
	}
	dir, err := os.MkdirTemp("", "artex-template-run-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "check.yaml")
	if err = os.WriteFile(path, []byte(content), 0o600); err != nil {
		return nil, err
	}
	config := filepath.Join(dir, "config.yaml")
	if err = os.WriteFile(config, []byte("{}\n"), 0o600); err != nil {
		return nil, err
	}
	errorLog := filepath.Join(dir, "errors.jsonl")
	args := []string{"-config", config, "-t", path, "-u", target, "-jsonl", "-silent", "-nc", "-duc", "-ni", "-dr", "-no-stdin", "-nh", "-dc", "-ms", "-ot", "-rl", "2", "-c", "1", "-bs", "1", "-timeout", "10", "-retries", "0", "-rsr", "262144", "-rss", "262144", "-elog", errorLog}
	if proxyURL != "" {
		args = append(args, "-proxy", proxyURL)
	}
	cmd := exec.CommandContext(ctx, EnginePath(), args...)
	cmd.Dir = dir
	// Explicit environment avoids user proxy credentials and cloud upload settings.
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if strings.Contains(upper, "PROXY") || strings.HasPrefix(upper, "PDCP") || strings.HasPrefix(upper, "NUCLEI") {
			continue
		}
		cmd.Env = append(cmd.Env, entry)
	}
	cmd.Env = append(cmd.Env, "DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD=true")
	if caFile != "" {
		cmd.Env = append(cmd.Env, "SSL_CERT_FILE="+caFile)
	}
	var out, stderr limitedOutput
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err = cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("Nuclei execution failed: %w: %.2000s", err, stderr.String())
	}
	if out.exceeded || stderr.exceeded {
		return nil, errors.New("Nuclei output exceeded limit")
	}
	if log, err := os.ReadFile(errorLog); err == nil && len(bytes.TrimSpace(log)) != 0 {
		return nil, fmt.Errorf("Nuclei request failed: %.2000s", log)
	}
	decoder := json.NewDecoder(bytes.NewReader(out.Bytes()))
	results := []Match{}
	for {
		var event struct {
			URL      string `json:"matched-at"`
			Request  string `json:"request"`
			Response string `json:"response"`
			Matched  bool   `json:"matcher-status"`
		}
		if err := decoder.Decode(&event); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("decode Nuclei result: %w", err)
		}
		if len(results) >= 32 {
			return nil, errors.New("Nuclei result limit exceeded")
		}
		results = append(results, Match{Matched: event.Matched, URL: event.URL, Request: event.Request, Response: event.Response})
	}
	if len(results) == 0 {
		return nil, errors.New("Nuclei produced no result events; template compatibility or request execution failed")
	}
	return results, nil
}
