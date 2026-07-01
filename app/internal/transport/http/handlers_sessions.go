package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"sessionproxy/internal/service"
	appmw "sessionproxy/internal/transport/http/middleware"
)

type importCookieRequest struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	HTTPOnly bool   `json:"http_only,omitempty"`
	SameSite string `json:"same_site,omitempty"`
}

type importTokenRequest struct {
	TokenType  string `json:"token_type,omitempty"`
	HeaderName string `json:"header_name,omitempty"`
	Value      string `json:"value"`
}

type importSessionRequest struct {
	BaseDomain string                `json:"base_domain"`
	SiteName   string                `json:"site_name"`
	BaseURL    string                `json:"base_url"`
	Cookies    []importCookieRequest `json:"cookies"`
	Tokens     []importTokenRequest  `json:"tokens,omitempty"`
}

// handleImportSession implements FR1. Plaintext cookie/token values live
// only in this request body and inside SessionImportService.Import, which
// encrypts each one before it reaches the database - see
// internal/crypto/aesgcm.go and internal/service/session_import.go.
func (s *Server) handleImportSession(w http.ResponseWriter, r *http.Request) {
	var req importSessionRequest
	if !decodeJSON(r, &req) || req.BaseDomain == "" || req.BaseURL == "" {
		writeError(w, http.StatusBadRequest, "base_domain and base_url are required")
		return
	}
	if req.SiteName == "" {
		req.SiteName = req.BaseDomain
	}

	cookies := make([]service.CookieInput, 0, len(req.Cookies))
	for _, c := range req.Cookies {
		cookies = append(cookies, service.CookieInput{
			Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
			Secure: c.Secure, HTTPOnly: c.HTTPOnly, SameSite: c.SameSite,
		})
	}
	tokens := make([]service.TokenInput, 0, len(req.Tokens))
	for _, t := range req.Tokens {
		tokens = append(tokens, service.TokenInput{TokenType: t.TokenType, HeaderName: t.HeaderName, Value: t.Value})
	}

	session, err := s.SessionImport.Import(r.Context(), appmw.UserID(r.Context()), req.BaseDomain, req.SiteName, req.BaseURL, cookies, tokens)
	if err != nil {
		s.Logger.Error("session import failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, session)
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.OriginalSessions.ListByUser(r.Context(), appmw.UserID(r.Context()))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "sessionID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	session, err := s.OriginalSessions.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	if session.UserID != appmw.UserID(r.Context()) {
		// 404, not 403: do not confirm another owner's session id exists.
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	writeJSON(w, http.StatusOK, session)
}
