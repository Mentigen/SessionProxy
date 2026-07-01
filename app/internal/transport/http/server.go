// Package http implements the owner-facing control plane: authentication,
// session import, shared-link management, policies, blacklists, and
// read-only visibility into guests/logs/security events. It is documented
// by api/openapi.yaml and mounted under /api/v1 alongside the data plane's
// /r/ prefix (see cmd/server/main.go).
package http

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"sessionproxy/internal/domain"
	"sessionproxy/internal/service"
	appmw "sessionproxy/internal/transport/http/middleware"
)

// Server bundles every repository interface and service the control plane
// needs. Fields are typed as domain interfaces (not concrete pgx types) so
// the whole package stays testable against gomock fakes; main.go is the
// only place that supplies concrete *pgx.XxxRepo values, which satisfy
// these interfaces implicitly.
type Server struct {
	Logger *slog.Logger

	Auth          *service.AuthService
	SessionImport *service.SessionImportService
	Links         *service.LinkService

	Users            domain.UserRepository
	Devices          domain.DeviceRepository
	APIKeys          domain.APIKeyRepository
	TargetSites      domain.TargetSiteRepository
	OriginalSessions domain.OriginalSessionRepository
	SharedLinks      domain.SharedLinkRepository
	AccessPolicies   domain.AccessPolicyRepository
	Blacklist        domain.BlacklistRepository
	Guests           domain.GuestRepository
	GuestSessions    domain.GuestSessionRepository
	ProxyAccessLogs  domain.ProxyAccessLogRepository
	LinkTerminations domain.LinkTerminationRepository
	SecurityEvents   domain.SecurityEventRepository
	Stats            domain.StatsRepository
}

// Routes builds the chi router for the whole control plane. It is mounted
// at "/" alongside the data plane's "/r/" handler in cmd/server/main.go, so
// route prefixes here must not collide with RoutePrefix.
func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()
	// chimw.RealIP is deliberately not used: it trusts X-Forwarded-For/
	// X-Real-IP unconditionally, which is spoofable unless a proxy in
	// front of this service is configured to strip/overwrite those
	// headers (see GHSA-3fxj-6jh8-hvhx). Nothing in the control plane
	// makes a security decision based on client IP.
	r.Use(chimw.RequestID, chimw.Recoverer)
	r.Use(requestLogger(s.Logger))

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/auth/register", s.handleRegister)
		r.Post("/auth/login", s.handleLogin)

		r.Get("/target-sites", s.handleListTargetSites)
		r.Get("/revocation-reasons", s.handleListRevocationReasons)

		r.Group(func(r chi.Router) {
			r.Use(appmw.RequireAuth(s.Auth))

			r.Get("/me", s.handleMe)
			r.Post("/target-sites", s.handleCreateTargetSite)

			r.Route("/devices", func(r chi.Router) {
				r.Get("/", s.handleListDevices)
				r.Post("/", s.handleCreateDevice)
				r.Delete("/{deviceID}", s.handleDeleteDevice)
			})

			r.Route("/api-keys", func(r chi.Router) {
				r.Get("/", s.handleListAPIKeys)
				r.Post("/", s.handleCreateAPIKey)
				r.Post("/{keyID}/revoke", s.handleRevokeAPIKey)
			})

			r.Route("/sessions", func(r chi.Router) {
				r.Get("/", s.handleListSessions)
				r.Post("/import", s.handleImportSession)
				r.Get("/{sessionID}", s.handleGetSession)
			})

			r.Route("/policies", func(r chi.Router) {
				r.Get("/", s.handleListPolicies)
				r.Post("/", s.handleCreatePolicy)
				r.Delete("/{policyID}", s.handleDeletePolicy)
			})

			r.Route("/blacklist", func(r chi.Router) {
				r.Get("/", s.handleListBlacklist)
				r.Post("/", s.handleCreateBlacklistEndpoint)
				r.Delete("/{endpointID}", s.handleDeleteBlacklistEndpoint)
				r.Put("/{endpointID}/methods", s.handleSetBlockedMethods)
				r.Post("/{endpointID}/attach-site/{siteID}", s.handleAttachBlacklistToSite)
			})

			r.Route("/guests", func(r chi.Router) {
				r.Get("/", s.handleListGuests)
			})

			r.Route("/links", func(r chi.Router) {
				r.Get("/", s.handleListLinks)
				r.Post("/", s.handleCreateLink)

				r.Group(func(r chi.Router) {
					r.Use(appmw.RequireLinkOwnership(s.SharedLinks))
					r.Get("/{linkID}", s.handleGetLink)
					r.Post("/{linkID}/terminate", s.handleTerminateLink)
					r.Get("/{linkID}/stats", s.handleGetLinkStats)
					r.Get("/{linkID}/logs", s.handleGetLinkLogs)
					r.Get("/{linkID}/guest-sessions", s.handleGetLinkGuestSessions)
					r.Get("/{linkID}/security-events", s.handleGetLinkSecurityEvents)
					r.Get("/{linkID}/termination", s.handleGetLinkTermination)
					r.Post("/{linkID}/attach-endpoint/{endpointID}", s.handleAttachEndpointToLink)
				})
			})
		})
	})

	return r
}

func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Info("http request", "method", r.Method, "path", r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}
}
