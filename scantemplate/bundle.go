package scantemplate

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
	"time"
)

//go:embed bundles/official/*
var officialBundle embed.FS

type BundleEntry struct {
	File         string `json:"file"`
	UpstreamPath string `json:"upstream_path"`
	SHA256       string `json:"sha256"`
}

type BundleManifest struct {
	Name          string        `json:"name"`
	Repository    string        `json:"repository"`
	Version       string        `json:"version"`
	EngineVersion string        `json:"engine_version"`
	License       string        `json:"license"`
	LicenseFile   string        `json:"license_file"`
	LicenseSHA256 string        `json:"license_sha256"`
	AcquiredAt    string        `json:"acquired_at"`
	Entries       []BundleEntry `json:"entries"`
}

type BundledTemplate struct {
	Metadata                                   Metadata
	Content, SourceURL, SourceVersion, License string
}

func OfficialBundle() (BundleManifest, []BundledTemplate, error) {
	files, err := fs.Sub(officialBundle, "bundles/official")
	if err != nil {
		return BundleManifest{}, nil, err
	}
	return ReadBundle(files)
}

// ReadBundle validates every byte before returning any importable content.
// An invalid batch cannot partially replace an already usable local catalog.
func ReadBundle(files fs.FS) (BundleManifest, []BundledTemplate, error) {
	var manifest BundleManifest
	data, err := readBundleFile(files, "manifest.json", 1<<20)
	if err != nil {
		return manifest, nil, err
	}
	if len(data) > 1<<20 {
		return manifest, nil, fmt.Errorf("bundle manifest exceeds size limit")
	}
	if err = json.Unmarshal(data, &manifest); err != nil {
		return manifest, nil, err
	}
	if manifest.Repository != "https://github.com/projectdiscovery/nuclei-templates" || len(manifest.Version) != 40 || manifest.License != "MIT" || manifest.EngineVersion != EngineVersion || len(manifest.Entries) == 0 || len(manifest.Entries) > 1000 {
		return manifest, nil, fmt.Errorf("unsupported content bundle identity")
	}
	if version, err := hex.DecodeString(manifest.Version); err != nil || len(version) != 20 {
		return manifest, nil, fmt.Errorf("invalid content source version")
	}
	if _, err := time.Parse(time.RFC3339, manifest.AcquiredAt); err != nil {
		return manifest, nil, fmt.Errorf("invalid content acquisition time")
	}
	if !fs.ValidPath(manifest.LicenseFile) {
		return manifest, nil, fmt.Errorf("invalid license path")
	}
	license, err := readBundleFile(files, manifest.LicenseFile, 1<<20)
	if err != nil {
		return manifest, nil, err
	}
	if !matchesHash(license, manifest.LicenseSHA256) {
		return manifest, nil, fmt.Errorf("license checksum mismatch")
	}
	result := []BundledTemplate{}
	seen := map[string]bool{}
	for _, entry := range manifest.Entries {
		if !fs.ValidPath(entry.File) || path.Base(entry.File) != entry.File || !strings.HasSuffix(entry.File, ".yaml") || !fs.ValidPath(entry.UpstreamPath) || !strings.HasPrefix(entry.UpstreamPath, "http/technologies/") {
			return manifest, nil, fmt.Errorf("invalid bundle template path")
		}
		data, err := readBundleFile(files, entry.File, 1<<20)
		if err != nil {
			return manifest, nil, err
		}
		if len(data) > 1<<20 || !matchesHash(data, entry.SHA256) {
			return manifest, nil, fmt.Errorf("template checksum mismatch: %s", entry.File)
		}
		metadata, err := Validate(data)
		if err != nil {
			return manifest, nil, fmt.Errorf("%s: %w", entry.File, err)
		}
		if seen[metadata.ID] {
			return manifest, nil, fmt.Errorf("duplicate template id: %s", metadata.ID)
		}
		seen[metadata.ID] = true
		result = append(result, BundledTemplate{Metadata: metadata, Content: string(data), SourceURL: manifest.Repository + "/blob/" + manifest.Version + "/" + entry.UpstreamPath, SourceVersion: manifest.Version, License: manifest.License})
	}
	return manifest, result, nil
}

func matchesHash(data []byte, expected string) bool {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) == expected
}

func readBundleFile(files fs.FS, name string, limit int64) ([]byte, error) {
	f, err := files.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("bundle file exceeds size limit: %s", name)
	}
	return data, nil
}
