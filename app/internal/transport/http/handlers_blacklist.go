package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"sessionproxy/internal/domain"
	appmw "sessionproxy/internal/transport/http/middleware"
)

type createBlacklistRequest struct {
	Pattern     string   `json:"pattern"`
	PatternType string   `json:"pattern_type,omitempty"` // "prefix" (default) or "regex"
	Description string   `json:"description,omitempty"`
	Methods     []string `json:"methods,omitempty"`
}

// handleCreateBlacklistEndpoint implements FR5: a reusable blocked-path
// rule an owner can then attach to a target_site (handleAttachBlacklistToSite)
// or to a specific shared_link (handleAttachEndpointToLink in
// handlers_links.go). Methods, if given, are stored via
// endpoint_blocked_methods in the same call.
func (s *Server) handleCreateBlacklistEndpoint(w http.ResponseWriter, r *http.Request) {
	var req createBlacklistRequest
	if !decodeJSON(r, &req) || req.Pattern == "" {
		writeError(w, http.StatusBadRequest, "pattern is required")
		return
	}
	if req.PatternType != "" && req.PatternType != domain.PatternTypePrefix && req.PatternType != domain.PatternTypeRegex {
		writeError(w, http.StatusBadRequest, "pattern_type must be 'prefix' or 'regex'")
		return
	}
	e := domain.BlacklistedEndpoint{UserID: appmw.UserID(r.Context()), Pattern: req.Pattern, PatternType: req.PatternType}
	if req.Description != "" {
		e.Description = &req.Description
	}
	created, err := s.Blacklist.Create(r.Context(), e)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if len(req.Methods) > 0 {
		if err := s.Blacklist.SetBlockedMethods(r.Context(), created.ID, req.Methods); err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		created.BlockedMethods = req.Methods
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleListBlacklist(w http.ResponseWriter, r *http.Request) {
	endpoints, err := s.Blacklist.ListByUser(r.Context(), appmw.UserID(r.Context()))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, endpoints)
}

func (s *Server) ownedBlacklistEndpoint(r *http.Request, w http.ResponseWriter) (domain.BlacklistedEndpoint, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "endpointID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid endpoint id")
		return domain.BlacklistedEndpoint{}, false
	}
	existing, err := s.Blacklist.GetByID(r.Context(), id)
	if err != nil || existing.UserID != appmw.UserID(r.Context()) {
		writeError(w, http.StatusNotFound, "blacklist endpoint not found")
		return domain.BlacklistedEndpoint{}, false
	}
	return existing, true
}

func (s *Server) handleDeleteBlacklistEndpoint(w http.ResponseWriter, r *http.Request) {
	existing, ok := s.ownedBlacklistEndpoint(r, w)
	if !ok {
		return
	}
	if err := s.Blacklist.Delete(r.Context(), existing.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type setBlockedMethodsRequest struct {
	Methods []string `json:"methods"`
}

func (s *Server) handleSetBlockedMethods(w http.ResponseWriter, r *http.Request) {
	existing, ok := s.ownedBlacklistEndpoint(r, w)
	if !ok {
		return
	}
	var req setBlockedMethodsRequest
	if !decodeJSON(r, &req) {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := s.Blacklist.SetBlockedMethods(r.Context(), existing.ID, req.Methods); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAttachBlacklistToSite(w http.ResponseWriter, r *http.Request) {
	existing, ok := s.ownedBlacklistEndpoint(r, w)
	if !ok {
		return
	}
	siteID, err := uuid.Parse(chi.URLParam(r, "siteID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid site id")
		return
	}
	if err := s.Blacklist.AttachToSite(r.Context(), siteID, existing.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
