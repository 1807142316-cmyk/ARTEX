package cve

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidRecord = errors.New("invalid CVE record")

type Record struct {
	ID            string          `json:"cve_id"`
	State         string          `json:"state"`
	DataVersion   string          `json:"data_version"`
	Description   string          `json:"description"`
	Products      []string        `json:"products"`
	References    []string        `json:"references"`
	Published     string          `json:"date_published,omitempty"`
	Updated       string          `json:"date_updated,omitempty"`
	SourceVersion string          `json:"source_version"`
	ContentHash   string          `json:"content_hash"`
	Raw           json.RawMessage `json:"raw"`
}

type cveDocument struct {
	DataVersion string `json:"dataVersion"`
	Metadata    struct {
		ID        string `json:"cveId"`
		State     string `json:"state"`
		Published string `json:"datePublished"`
		Updated   string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA cveContainer   `json:"cna"`
		ADP []cveContainer `json:"adp"`
	} `json:"containers"`
}

type cveContainer struct {
	Descriptions []struct {
		Language string `json:"lang"`
		Value    string `json:"value"`
	} `json:"descriptions"`
	Affected []struct {
		Vendor  string `json:"vendor"`
		Product string `json:"product"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

func ParseRecord(raw json.RawMessage, sourceVersion string) (Record, error) {
	var document cveDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrInvalidRecord, err)
	}
	document.Metadata.ID = strings.TrimSpace(document.Metadata.ID)
	if document.Metadata.ID == "" || !strings.HasPrefix(strings.ToUpper(document.Metadata.ID), "CVE-") {
		return Record{}, fmt.Errorf("%w: cveMetadata.cveId is required", ErrInvalidRecord)
	}

	containers := append([]cveContainer{document.Containers.CNA}, document.Containers.ADP...)
	record := Record{
		ID:            document.Metadata.ID,
		State:         strings.ToUpper(strings.TrimSpace(document.Metadata.State)),
		DataVersion:   strings.TrimSpace(document.DataVersion),
		Published:     strings.TrimSpace(document.Metadata.Published),
		Updated:       strings.TrimSpace(document.Metadata.Updated),
		SourceVersion: strings.TrimSpace(sourceVersion),
		Raw:           append(json.RawMessage(nil), raw...),
	}
	productSet := make(map[string]struct{})
	referenceSet := make(map[string]struct{})
	descriptionSet := make(map[string]struct{})
	for containerIndex, container := range containers {
		for _, description := range container.Descriptions {
			value := strings.TrimSpace(description.Value)
			if value == "" {
				continue
			}
			descriptionSet[value] = struct{}{}
			if record.Description == "" || (containerIndex == 0 && strings.EqualFold(description.Language, "en")) {
				record.Description = value
			}
		}
		for _, affected := range container.Affected {
			vendor, product := strings.TrimSpace(affected.Vendor), strings.TrimSpace(affected.Product)
			if product == "" {
				continue
			}
			label := product
			if vendor != "" && !strings.EqualFold(vendor, product) {
				label = vendor + " " + product
			}
			productSet[label] = struct{}{}
		}
		for _, reference := range container.References {
			if url := strings.TrimSpace(reference.URL); url != "" {
				referenceSet[url] = struct{}{}
			}
		}
	}
	if record.Description == "" && len(descriptionSet) > 0 {
		for description := range descriptionSet {
			record.Description = description
			break
		}
	}
	for product := range productSet {
		record.Products = append(record.Products, product)
	}
	for reference := range referenceSet {
		record.References = append(record.References, reference)
	}
	sortStrings(record.Products)
	sortStrings(record.References)
	hash := sha256.Sum256(raw)
	record.ContentHash = hex.EncodeToString(hash[:])
	return record, nil
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
