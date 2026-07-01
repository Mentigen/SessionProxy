package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"sessionproxy/internal/domain"
	appmw "sessionproxy/internal/transport/http/middleware"
)

type createPolicyRequest struct {
	Name                string `json:"name"`
	MaxRequests         *int64 `json:"max_requests,omitempty"`
	MaxBytesTransferred *int64 `json:"max_bytes_transferred,omitempty"`
	MaxTTLSeconds       *int64 `json:"max_ttl_seconds,omitempty"`
	MaxViolationCount   *int64 `json:"max_violation_count,omitempty"`
}

// handleCreatePolicy stores one access_policies row. It is not itself the
// enforcement point - policy_resolver.go (phase 4) resolves every policy
// attached to a link, via link_policies, down to one effective limit set
// using most-restrictive-wins.
func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var req createPolicyRequest
	if !decodeJSON(r, &req) || req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	p := domain.AccessPolicy{
		UserID:              appmw.UserID(r.Context()),
		Name:                req.Name,
		MaxRequests:         req.MaxRequests,
		MaxBytesTransferred: req.MaxBytesTransferred,
		MaxTTLSeconds:       req.MaxTTLSeconds,
		MaxViolationCount:   req.MaxViolationCount,
	}
	created, err := s.AccessPolicies.Create(r.Context(), p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.AccessPolicies.ListByUser(r.Context(), appmw.UserID(r.Context()))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, policies)
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "policyID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	existing, err := s.AccessPolicies.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	if existing.UserID != appmw.UserID(r.Context()) {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	if err := s.AccessPolicies.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
