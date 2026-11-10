package cve

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestWalkArchiveReadsOfficialNestedBaselineAndHonorsCancellation(t *testing.T) {
	var inner bytes.Buffer
	writer := zip.NewWriter(&inner)
	entry, _ := writer.Create("cves/2099/76xxx/CVE-2099-76543.json")
	_, _ = entry.Write([]byte(`{"cveMetadata":{"cveId":"CVE-2099-76543","state":"PUBLISHED"}}`))
	metadata, _ := writer.Create("cves/deltaLog.json")
	_, _ = metadata.Write([]byte(`{"fetchTime":"2099-01-01"}`))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var outer bytes.Buffer
	writer = zip.NewWriter(&outer)
	entry, _ = writer.Create("cves.zip")
	_, _ = entry.Write(inner.Bytes())
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "baseline.zip")
	if err := os.WriteFile(path, outer.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	var records []Record
	if err := WalkArchive(context.Background(), path, "release-1", func(record Record) error {
		records = append(records, record)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].ID != "CVE-2099-76543" || records[0].SourceVersion != "release-1" {
		t.Fatalf("archive records: %+v", records)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WalkArchive(ctx, path, "release-1", func(Record) error { t.Fatal("callback after cancellation"); return nil }); err == nil {
		t.Fatal("cancelled archive read succeeded")
	}
}
