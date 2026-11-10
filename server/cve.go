package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/cve"
	"github.com/Autumn-27/artex/db"
)

const maxCVEImportBytes = 16 << 20
const maxCVEImportRecords = 1000

type cveImportRequest struct {
	SourceVersion string            `json:"source_version"`
	Records       []json.RawMessage `json:"records"`
}

func (s *Server) importCVERecords(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxCVEImportBytes)
	var request cveImportRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, "CVE import request exceeds size limit")
		} else {
			writeErr(w, http.StatusBadRequest, "invalid CVE import JSON")
		}
		return
	}
	if len(request.Records) == 0 || len(request.Records) > maxCVEImportRecords {
		writeErr(w, http.StatusBadRequest, "records must contain between 1 and 1000 entries")
		return
	}
	request.SourceVersion = strings.TrimSpace(request.SourceVersion)
	records := make([]db.CVERecord, 0, len(request.Records))
	for index, raw := range request.Records {
		parsed, err := cve.ParseRecord(raw, request.SourceVersion)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid CVE record at index "+strconv.Itoa(index))
			return
		}
		records = append(records, db.CVERecord{
			ID: parsed.ID, State: parsed.State, DataVersion: parsed.DataVersion, Description: parsed.Description,
			Products: parsed.Products, References: parsed.References, Published: parsed.Published,
			Updated: parsed.Updated, SourceVersion: parsed.SourceVersion, ContentHash: parsed.ContentHash, Raw: parsed.Raw,
		})
	}
	result, err := s.m.PG().UpsertCVERecords(r.Context(), records)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store CVE records: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) searchCVERecords(w http.ResponseWriter, r *http.Request) {
	page := findingPaginationParam(r.URL.Query().Get("page"), 1, 0)
	limit := findingPaginationParam(r.URL.Query().Get("limit"), 20, 100)
	result, err := s.m.PG().SearchCVERecords(r.Context(), r.URL.Query().Get("q"), page, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "search CVE records: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) cveRecordStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.m.PG().CVERecordStats(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "read CVE statistics: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}
