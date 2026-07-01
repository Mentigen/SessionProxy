package http

import "net/http"

type createTargetSiteRequest struct {
	BaseDomain string `json:"base_domain"`
	Name       string `json:"name"`
	BaseURL    string `json:"base_url"`
}

// target_sites has no user_id column: it is a shared catalog of sites any
// owner can import a session for, not an owner-scoped resource. Listing is
// public (mounted outside the auth group in server.go); creating one is
// intentionally left open too, since GetOrCreateByDomain in
// SessionImportService already de-dupes by domain during import - this
// endpoint exists for owners who want to pre-register a site before
// importing, e.g. from a CLI/browser-extension flow.
func (s *Server) handleListTargetSites(w http.ResponseWriter, r *http.Request) {
	sites, err := s.TargetSites.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, sites)
}

func (s *Server) handleCreateTargetSite(w http.ResponseWriter, r *http.Request) {
	var req createTargetSiteRequest
	if !decodeJSON(r, &req) || req.BaseDomain == "" || req.Name == "" || req.BaseURL == "" {
		writeError(w, http.StatusBadRequest, "base_domain, name and base_url are required")
		return
	}
	site, err := s.TargetSites.GetOrCreateByDomain(r.Context(), req.BaseDomain, req.Name, req.BaseURL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, site)
}

func (s *Server) handleListRevocationReasons(w http.ResponseWriter, r *http.Request) {
	reasons, err := s.LinkTerminations.ListReasons(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, reasons)
}

func (s *Server) handleListGuests(w http.ResponseWriter, r *http.Request) {
	guests, err := s.Guests.List(r.Context(), 200, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, guests)
}
