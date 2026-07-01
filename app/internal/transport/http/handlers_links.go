package http

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"sessionproxy/internal/service"
	appmw "sessionproxy/internal/transport/http/middleware"
)

type createLinkRequest struct {
	OriginalSessionID uuid.UUID   `json:"original_session_id"`
	Label             string      `json:"label,omitempty"`
	TTLSeconds        int64       `json:"ttl_seconds,omitempty"`
	PolicyIDs         []uuid.UUID `json:"policy_ids,omitempty"`
	EndpointIDs       []uuid.UUID `json:"endpoint_ids,omitempty"`
}

// handleCreateLink implements FR2: turning an imported session into a
// guest-facing shared_link, optionally pre-attaching access_policies and
// link-level blacklist rules.
func (s *Server) handleCreateLink(w http.ResponseWriter, r *http.Request) {
	var req createLinkRequest
	if !decodeJSON(r, &req) || req.OriginalSessionID == uuid.Nil {
		writeError(w, http.StatusBadRequest, "original_session_id is required")
		return
	}
	in := service.CreateLinkInput{
		OriginalSessionID: req.OriginalSessionID,
		Label:             req.Label,
		PolicyIDs:         req.PolicyIDs,
		EndpointIDs:       req.EndpointIDs,
	}
	if req.TTLSeconds > 0 {
		in.TTL = time.Duration(req.TTLSeconds) * time.Second
	}

	link, err := s.Links.CreateLink(r.Context(), appmw.UserID(r.Context()), in)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrSessionNotOwned):
			writeError(w, http.StatusNotFound, "session not found")
		case errors.Is(err, service.ErrSessionNotActive):
			writeError(w, http.StatusConflict, err.Error())
		default:
			s.Logger.Error("create link failed", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusCreated, link)
}

func (s *Server) handleListLinks(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	links, err := s.SharedLinks.ListByUser(r.Context(), appmw.UserID(r.Context()), status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, links)
}

// handleGetLink and everything below run behind RequireLinkOwnership, so
// {linkID} is already verified to belong to the caller by the time these
// execute.
func (s *Server) handleGetLink(w http.ResponseWriter, r *http.Request) {
	id, _ := uuid.Parse(chi.URLParam(r, "linkID"))
	link, err := s.SharedLinks.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "link not found")
		return
	}
	writeJSON(w, http.StatusOK, link)
}

type terminateLinkRequest struct {
	Notes string `json:"notes,omitempty"`
}

func (s *Server) handleTerminateLink(w http.ResponseWriter, r *http.Request) {
	id, _ := uuid.Parse(chi.URLParam(r, "linkID"))
	var req terminateLinkRequest
	_ = decodeJSON(r, &req) // body is optional for this endpoint

	err := s.Links.TerminateLink(r.Context(), appmw.UserID(r.Context()), id, req.Notes)
	if err != nil {
		if errors.Is(err, service.ErrLinkAlreadyTerminated) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		s.Logger.Error("terminate link failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetLinkStats(w http.ResponseWriter, r *http.Request) {
	id, _ := uuid.Parse(chi.URLParam(r, "linkID"))
	stats, err := s.Stats.GetLinkStats(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if stats == nil {
		writeJSON(w, http.StatusOK, map[string]string{"message": "no data yet - mv_link_stats has not been refreshed since this link had traffic"})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleGetLinkLogs(w http.ResponseWriter, r *http.Request) {
	id, _ := uuid.Parse(chi.URLParam(r, "linkID"))
	logs, err := s.ProxyAccessLogs.ListByLink(r.Context(), id, 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, logs)
}

func (s *Server) handleGetLinkGuestSessions(w http.ResponseWriter, r *http.Request) {
	id, _ := uuid.Parse(chi.URLParam(r, "linkID"))
	sessions, err := s.GuestSessions.ListByLink(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (s *Server) handleGetLinkSecurityEvents(w http.ResponseWriter, r *http.Request) {
	id, _ := uuid.Parse(chi.URLParam(r, "linkID"))
	events, err := s.SecurityEvents.ListByLink(r.Context(), id, 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) handleGetLinkTermination(w http.ResponseWriter, r *http.Request) {
	id, _ := uuid.Parse(chi.URLParam(r, "linkID"))
	term, err := s.LinkTerminations.GetByLink(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if term == nil {
		writeError(w, http.StatusNotFound, "link has not been terminated")
		return
	}
	writeJSON(w, http.StatusOK, term)
}

func (s *Server) handleAttachEndpointToLink(w http.ResponseWriter, r *http.Request) {
	linkID, _ := uuid.Parse(chi.URLParam(r, "linkID"))
	endpointID, err := uuid.Parse(chi.URLParam(r, "endpointID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid endpoint id")
		return
	}
	if err := s.Blacklist.AttachToLink(r.Context(), linkID, endpointID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
