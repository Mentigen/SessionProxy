// Package webui is the owner-facing HTML dashboard: templ-rendered pages
// plus htmx for the interactive bits (terminate-in-place) and a plain SSE
// endpoint for the live security feed. It talks to the same services as
// the REST control plane (internal/transport/http) and the same
// pubsub.Hub as the gRPC AdminService - three different front doors onto
// one set of application-layer rules, chosen deliberately over shipping a
// separate SPA/npm build for what is fundamentally an internal owner tool.
package webui

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"sessionproxy/internal/domain"
	"sessionproxy/internal/pubsub"
	"sessionproxy/internal/service"
	appmw "sessionproxy/internal/transport/http/middleware"
	"sessionproxy/internal/transport/webui/templates"
)

type Server struct {
	Logger *slog.Logger

	Auth          *service.AuthService
	SessionImport *service.SessionImportService
	Links         *service.LinkService

	SharedLinks domain.SharedLinkRepository
	Hub         *pubsub.Hub
}

// Routes mounts the dashboard under /dashboard. cmd/server/main.go mounts
// this alongside the REST control plane and the /r/ data plane on the same
// mux.
func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()

	r.Get("/login", s.handleLoginPage)
	r.Post("/login", s.handleLoginSubmit)
	r.Get("/logout", s.handleLogout)

	r.Group(func(r chi.Router) {
		r.Use(appmw.RequireSessionCookie(s.Auth))

		r.Get("/", s.handleLinksList)
		r.Get("/links", s.handleLinksList)
		r.Post("/links/{linkID}/terminate", s.handleTerminate)
		r.Get("/import", s.handleImportPage)
		r.Post("/import", s.handleImportSubmit)
		r.Get("/security-feed", s.handleSecurityFeedPage)
		r.Get("/events", s.handleSecurityFeedSSE)
	})

	return r
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	_ = templates.LoginPage("").Render(r.Context(), w)
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")
	token, _, err := s.Auth.Login(r.Context(), email, password)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = templates.LoginPage("invalid email or password").Render(r.Context(), w)
		return
	}
	// #nosec G124 -- HttpOnly and SameSite are set; Secure is computed from
	// r.TLS rather than a literal `true` because this stack is exercised
	// over plain HTTP in local/docker-compose demos (no TLS termination
	// configured for the app service). Behind TLS in a real deployment,
	// r.TLS != nil makes this Secure automatically.
	http.SetCookie(w, &http.Cookie{
		Name:     appmw.SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(time.Hour),
	})
	http.Redirect(w, r, "/dashboard/links", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// #nosec G124 -- see handleLoginSubmit above.
	http.SetCookie(w, &http.Cookie{
		Name:     appmw.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/dashboard/login", http.StatusSeeOther)
}

func (s *Server) handleLinksList(w http.ResponseWriter, r *http.Request) {
	links, err := s.SharedLinks.ListByUser(r.Context(), appmw.UserID(r.Context()), "")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = templates.LinksPage(links).Render(r.Context(), w)
}

func (s *Server) handleTerminate(w http.ResponseWriter, r *http.Request) {
	linkID, err := uuid.Parse(chi.URLParam(r, "linkID"))
	if err != nil {
		http.Error(w, "invalid link id", http.StatusBadRequest)
		return
	}
	if err := s.Links.TerminateLink(r.Context(), appmw.UserID(r.Context()), linkID, "terminated via dashboard"); err != nil {
		http.Error(w, "could not terminate link", http.StatusInternalServerError)
		return
	}
	link, err := s.SharedLinks.GetByID(r.Context(), linkID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = templates.LinkRow(link).Render(r.Context(), w)
}

func (s *Server) handleImportPage(w http.ResponseWriter, r *http.Request) {
	_ = templates.ImportPage("").Render(r.Context(), w)
}

func (s *Server) handleImportSubmit(w http.ResponseWriter, r *http.Request) {
	baseDomain := r.FormValue("base_domain")
	baseURL := r.FormValue("base_url")
	cookieName := r.FormValue("cookie_name")
	cookieValue := r.FormValue("cookie_value")

	session, err := s.SessionImport.Import(r.Context(), appmw.UserID(r.Context()), baseDomain, baseDomain, baseURL,
		[]service.CookieInput{{Name: cookieName, Value: cookieValue, Path: "/"}}, nil)
	if err != nil {
		s.Logger.Error("dashboard: import failed", "error", err)
		_ = templates.ImportPage("import failed - check server logs").Render(r.Context(), w)
		return
	}
	_ = templates.ImportPage(fmt.Sprintf("Imported. original_session_id = %s - create a shared link for it via POST /api/v1/links.", session.ID)).Render(r.Context(), w)
}

func (s *Server) handleSecurityFeedPage(w http.ResponseWriter, r *http.Request) {
	_ = templates.SecurityFeedPage().Render(r.Context(), w)
}

// handleSecurityFeedSSE streams pubsub.Hub events as they are published,
// filtered to links the authenticated owner actually owns - the same
// discretion as the REST/gRPC surfaces, just as a browser-native
// text/event-stream instead of JSON or protobuf.
func (s *Server) handleSecurityFeedSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	userID := appmw.UserID(r.Context())
	events, cancel := s.Hub.Subscribe()
	defer cancel()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-events:
			if !ok {
				return
			}
			owner, err := s.SharedLinks.OwnerUserID(ctx, evt.LinkID)
			if err != nil || owner != userID {
				continue
			}
			payload, err := json.Marshal(map[string]string{
				"type":        string(evt.Type),
				"link_id":     evt.LinkID.String(),
				"message":     evt.Message,
				"occurred_at": evt.OccurredAt.Format(time.RFC3339),
			})
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
