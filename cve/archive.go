package cve

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxRecordBytes = 16 << 20

// WalkArchive consumes official flat delta ZIPs and nested baseline ZIPs without
// extracting source-controlled paths into the filesystem.
func WalkArchive(ctx context.Context, path, version string, visit func(Record) error) error {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer archive.Close()
	return walkZIP(ctx, &archive.Reader, version, visit, 0)
}

func walkZIP(ctx context.Context, archive *zip.Reader, version string, visit func(Record) error, depth int) error {
	for _, entry := range archive.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.FileInfo().IsDir() {
			continue
		}
		name := filepath.Base(strings.ReplaceAll(entry.Name, `\`, "/"))
		if strings.HasSuffix(strings.ToLower(name), ".zip") {
			if depth >= 1 {
				return fmt.Errorf("CVE archive nesting exceeds supported depth")
			}
			if err := walkNestedZIP(ctx, entry, version, visit, depth+1); err != nil {
				return err
			}
			continue
		}
		if !strings.HasPrefix(name, "CVE-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		if entry.UncompressedSize64 > maxRecordBytes {
			return fmt.Errorf("CVE record %s exceeds size limit", name)
		}
		reader, err := entry.Open()
		if err != nil {
			return err
		}
		raw, readErr := io.ReadAll(io.LimitReader(reader, maxRecordBytes+1))
		closeErr := reader.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if len(raw) > maxRecordBytes {
			return fmt.Errorf("CVE record %s exceeds size limit", name)
		}
		record, err := ParseRecord(raw, version)
		if err != nil {
			return fmt.Errorf("%s: %w", entry.Name, err)
		}
		if err := visit(record); err != nil {
			return err
		}
	}
	return nil
}

func walkNestedZIP(ctx context.Context, entry *zip.File, version string, visit func(Record) error, depth int) error {
	// Baseline archives contain a large cves.zip. Spool it to disk instead of
	// retaining the entire corpus in memory.
	if entry.UncompressedSize64 > 4<<30 {
		return fmt.Errorf("nested CVE archive exceeds size limit")
	}
	temp, err := os.CreateTemp("", "artex-cve-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	reader, err := entry.Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	if _, err := io.Copy(temp, io.LimitReader(reader, (4<<30)+1)); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := temp.Stat()
	if err != nil {
		return err
	}
	if info.Size() > 4<<30 {
		return fmt.Errorf("nested CVE archive exceeds size limit")
	}
	archive, err := zip.NewReader(temp, info.Size())
	if err != nil {
		return err
	}
	return walkZIP(ctx, archive, version, visit, depth)
}
