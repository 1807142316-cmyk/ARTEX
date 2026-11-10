package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/scantemplate"
)

const maxScanTemplateBytes = 1 << 20

func (s *Server) importScanTemplate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxScanTemplateBytes)
	var request struct {
		Content       string `json:"content"`
		SourceURL     string `json:"source_url"`
		SourceVersion string `json:"source_version"`
		License       string `json:"license"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			writeErr(w, http.StatusRequestEntityTooLarge, "scan template exceeds size limit")
		} else {
			writeErr(w, http.StatusBadRequest, "invalid scan template JSON")
		}
		return
	}
	request.Content = strings.TrimSpace(request.Content)
	request.SourceURL = strings.TrimSpace(request.SourceURL)
	request.SourceVersion = strings.TrimSpace(request.SourceVersion)
	request.License = strings.TrimSpace(request.License)
	if request.Content == "" || request.License == "" {
		writeErr(w, http.StatusBadRequest, "content and license are required")
		return
	}
	if request.SourceURL != "" {
		parsed, err := url.ParseRequestURI(request.SourceURL)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
			writeErr(w, http.StatusBadRequest, "source_url must be an absolute HTTP URL")
			return
		}
	}
	metadata, err := scantemplate.Validate([]byte(request.Content))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	template := db.ScanTemplate{ID: metadata.ID, Name: metadata.Name, Author: metadata.Author, Severity: metadata.Severity, Description: metadata.Description, Tags: metadata.Tags, References: metadata.References, Protocol: metadata.Protocol, SourceURL: request.SourceURL, SourceVersion: request.SourceVersion, License: request.License, ContentHash: metadata.ContentHash, Content: request.Content}
	if err := s.m.PG().SaveScanTemplate(r.Context(), template); err != nil {
		writeErr(w, http.StatusInternalServerError, "store scan template: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, template)
}

func (s *Server) listScanTemplates(w http.ResponseWriter, r *http.Request) {
	page := findingPaginationParam(r.URL.Query().Get("page"), 1, 0)
	limit := findingPaginationParam(r.URL.Query().Get("limit"), 20, 100)
	result, err := s.m.PG().SearchScanTemplates(r.Context(), r.URL.Query().Get("q"), r.URL.Query().Get("severity"), page, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list scan templates: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}
