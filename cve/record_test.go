package cve

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseRecordRetainsSearchableMetadataAcrossContainers(t *testing.T) {
	input := json.RawMessage(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2099-76543","state":"PUBLISHED","datePublished":"2099-01-02T03:04:05Z","dateUpdated":"2099-01-03T03:04:05Z"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"Stored cross-site scripting in Acme Portal"}],"affected":[{"vendor":"Acme","product":"Portal","versions":[{"version":"1.0","status":"affected"}]}],"references":[{"url":"https://example.test/advisory"}]},"adp":[{"descriptions":[{"lang":"en","value":"Program advisory"}],"references":[{"url":"https://example.test/program"}]}]}}`)

	got, err := ParseRecord(input, "fixture-commit")
	if err != nil {
		t.Fatalf("ParseRecord: %v", err)
	}
	if got.ID != "CVE-2099-76543" || got.State != "PUBLISHED" || got.DataVersion != "5.1" {
		t.Fatalf("unexpected CVE metadata: %+v", got)
	}
	if got.Description != "Stored cross-site scripting in Acme Portal" {
		t.Fatalf("description = %q", got.Description)
	}
	if !reflect.DeepEqual(got.Products, []string{"Acme Portal"}) {
		t.Fatalf("products = %#v", got.Products)
	}
	if !reflect.DeepEqual(got.References, []string{"https://example.test/advisory", "https://example.test/program"}) {
		t.Fatalf("references = %#v", got.References)
	}
	if got.SourceVersion != "fixture-commit" || len(got.Raw) == 0 || got.ContentHash == "" {
		t.Fatalf("source provenance missing: %+v", got)
	}
}

func TestParseRecordFallsBackToNonEnglishDescriptionAndKeepsRejectedState(t *testing.T) {
	input := json.RawMessage(`{"dataType":"CVE_RECORD","dataVersion":"5.2","cveMetadata":{"cveId":"CVE-2099-76544","state":"REJECTED"},"containers":{"cna":{"descriptions":[{"lang":"fr","value":"Retiré par le CNA"}],"references":[]}}}`)

	got, err := ParseRecord(input, "fixture")
	if err != nil {
		t.Fatalf("ParseRecord: %v", err)
	}
	if got.State != "REJECTED" || got.Description != "Retiré par le CNA" {
		t.Fatalf("rejected record metadata lost: %+v", got)
	}
}

func TestParseRecordRejectsMissingIdentifierAndMalformedJSON(t *testing.T) {
	for name, input := range map[string]json.RawMessage{
		"missing id": json.RawMessage(`{"cveMetadata":{"state":"PUBLISHED"}}`),
		"malformed":  json.RawMessage(`{"cveMetadata":`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRecord(input, "fixture"); err == nil {
				t.Fatal("expected invalid record error")
			}
		})
	}
}
