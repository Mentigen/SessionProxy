// Package proxy is the data plane: it resolves a guest-facing capability URL
// (/r/{token}/...) to a shared_link, injects the owner's decrypted
// credentials into the outgoing request, proxies it to the target site,
// strips owner-identifying headers from the response, and records the
// request. This is the part of SessionProxy the rest of the application
// (control plane, gRPC, dashboard) exists to configure and observe.
package proxy

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"sessionproxy/internal/crypto"
	"sessionproxy/internal/domain"
)

// Enforcer is implemented by internal/service starting in phase 4 (Redis
// usage limits) and phase 5 (blacklist matching). A nil Enforcer - the
// state of the app at the end of phase 2 - means every request is allowed
// and no counters are updated; Handler works standalone for the data-plane
// gate before those phases exist.
type Enforcer interface {
	// BeforeProxy runs after the link is resolved but before the request
	// reaches the target site. forwardPath is the path on the target site
	// (i.e. r.URL.Path with the "/r/{token}" prefix already stripped) -
	// blacklist patterns like "/settings" are matched against this, not
	// against the guest-facing r.URL.Path. ok=false rejects the request
	// with the given status/message without ever calling the target.
	BeforeProxy(ctx context.Context, link domain.LinkWithSession, guestSessionID uuid.UUID, forwardPath string, r *http.Request) (ok bool, status int, message string, err error)
	// AfterProxy runs once the response has been fully written to the
	// guest, with the real byte count and status code.
	AfterProxy(ctx context.Context, link domain.LinkWithSession, guestSessionID uuid.UUID, statusCode int, bytesTransferred int64)
}

// AccessLogger records one proxy_access_logs row. The phase-2 implementation
// (SyncAccessLogger) writes synchronously; phase 6 replaces it with a
// buffered/batched implementation behind the same interface, so Handler
// does not change when logging becomes async.
type AccessLogger interface {
	Log(ctx context.Context, entry domain.ProxyAccessLog)
}

// SyncAccessLogger writes proxy_access_logs directly on the request path.
// Simple and correct, at the cost of one extra INSERT's latency per request -
// acceptable for the phase-2 gate; phase 6 swaps this for an async writer
// once the rest of the data plane is proven correct.
type SyncAccessLogger struct {
	Repo   domain.ProxyAccessLogRepository
	Logger *slog.Logger
}

func (s SyncAccessLogger) Log(ctx context.Context, entry domain.ProxyAccessLog) {
	if err := s.Repo.Insert(ctx, entry); err != nil {
		s.Logger.Error("proxy: failed to write proxy_access_logs", "error", err)
	}
}

// Handler is the http.Handler mounted at /r/ for every guest request.
type Handler struct {
	Links          domain.SharedLinkRepository
	SessionCookies domain.SessionCookieRepository
	SessionTokens  domain.SessionTokenRepository
	Guests         domain.GuestRepository
	GuestSessions  domain.GuestSessionRepository

	Cipher    *crypto.Cipher
	Enforcer  Enforcer // may be nil until phase 4/5 wire one in
	Logger    *slog.Logger
	AccessLog AccessLogger

	reverseProxy *httputil.ReverseProxy
}

// New wires a Handler with its own httputil.ReverseProxy instance.
func New(links domain.SharedLinkRepository, cookies domain.SessionCookieRepository, tokens domain.SessionTokenRepository, guests domain.GuestRepository, guestSessions domain.GuestSessionRepository, cipher *crypto.Cipher, accessLog AccessLogger, logger *slog.Logger) *Handler {
	return &Handler{
		Links:          links,
		SessionCookies: cookies,
		SessionTokens:  tokens,
		Guests:         guests,
		GuestSessions:  guestSessions,
		Cipher:         cipher,
		AccessLog:      accessLog,
		Logger:         logger,
		reverseProxy:   newReverseProxy(logger),
	}
}

// RoutePrefix is the fixed mount point for guest traffic: /r/{token}/...
const RoutePrefix = "/r/"

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	token, forwardPath, ok := parseTokenAndPath(r.URL.Path)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	link, err := h.Links.GetByToken(ctx, token)
	if err != nil {
		http.Error(w, "link not found", http.StatusNotFound)
		return
	}

	if reason := inactiveReason(link); reason != "" {
		http.Error(w, reason, http.StatusGone)
		return
	}

	guest, err := h.Guests.GetOrCreate(ctx, clientIP(r), r.UserAgent(), "")
	if err != nil {
		h.Logger.Error("proxy: guest lookup failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	guestSessionID, err := h.resolveGuestSession(ctx, link.Link.ID, guest.ID)
	if err != nil {
		h.Logger.Error("proxy: guest_session resolve failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if h.Enforcer != nil {
		allowed, status, message, err := h.Enforcer.BeforeProxy(ctx, link, guestSessionID, forwardPath, r)
		if err != nil {
			h.Logger.Error("proxy: enforcement check failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !allowed {
			http.Error(w, message, status)
			h.logAccess(ctx, link, guestSessionID, forwardPath, r.Method, status, 0, time.Since(start))
			return
		}
	}

	plan, err := BuildInjectionPlan(ctx, h.Cipher, h.SessionCookies, h.SessionTokens, link.OriginalSession.ID)
	if err != nil {
		h.Logger.Error("proxy: failed to build injection plan", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	targetURL, err := url.Parse(link.TargetSite.BaseURL)
	if err != nil {
		h.Logger.Error("proxy: invalid target_sites.base_url", "error", err, "target_site", link.TargetSite.ID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	ctx = withForwardTarget(ctx, forwardTarget{BaseURL: targetURL, ForwardPath: forwardPath, Plan: plan})

	cw := newCountingResponseWriter(w)
	h.reverseProxy.ServeHTTP(cw, r.WithContext(ctx))

	elapsed := time.Since(start)
	if h.Enforcer != nil {
		h.Enforcer.AfterProxy(ctx, link, guestSessionID, cw.status, cw.bytes)
	}
	_ = h.GuestSessions.TouchLastRequest(ctx, guestSessionID)
	h.logAccess(ctx, link, guestSessionID, forwardPath, r.Method, cw.status, cw.bytes, elapsed)
}

func (h *Handler) resolveGuestSession(ctx context.Context, linkID, guestID uuid.UUID) (uuid.UUID, error) {
	existing, err := h.GuestSessions.GetActiveByLinkAndGuest(ctx, linkID, &guestID)
	if err != nil {
		return uuid.Nil, err
	}
	if existing != nil {
		return existing.ID, nil
	}
	created, err := h.GuestSessions.Create(ctx, domain.GuestSession{SharedLinkID: linkID, GuestID: &guestID})
	if err != nil {
		return uuid.Nil, err
	}
	return created.ID, nil
}

func (h *Handler) logAccess(ctx context.Context, link domain.LinkWithSession, guestSessionID uuid.UUID, path, method string, status int, bytesTransferred int64, elapsed time.Duration) {
	if h.AccessLog == nil {
		return
	}
	statusCopy := status
	bytesCopy := int(bytesTransferred)
	ms := int(elapsed.Milliseconds())
	gsID := guestSessionID
	h.AccessLog.Log(ctx, domain.ProxyAccessLog{
		GuestSessionID:   &gsID,
		SharedLinkID:     link.Link.ID,
		TargetURL:        link.TargetSite.BaseURL + path,
		HTTPMethod:       method,
		ResponseStatus:   &statusCopy,
		BytesTransferred: &bytesCopy,
		ResponseTimeMs:   &ms,
	})
}

// inactiveReason returns a non-empty guest-facing message if the link
// cannot be used right now: wrong status, past its own expires_at, or the
// owner session it belongs to is no longer active.
func inactiveReason(link domain.LinkWithSession) string {
	switch {
	case link.Link.Status != domain.LinkStatusActive:
		return "this link is no longer active"
	case link.Link.ExpiresAt != nil && time.Now().After(*link.Link.ExpiresAt):
		return "this link has expired"
	case link.OriginalSession.Status != domain.SessionStatusActive:
		return "the underlying session is no longer active"
	default:
		return ""
	}
}

// parseTokenAndPath splits "/r/{token}/{rest...}" into token and "/{rest...}".
// A request for exactly "/r/{token}" (no trailing path) forwards "/" to the
// target site's base_url.
func parseTokenAndPath(p string) (token, forwardPath string, ok bool) {
	if !strings.HasPrefix(p, RoutePrefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(p, RoutePrefix)
	if rest == "" {
		return "", "", false
	}
	slash := strings.IndexByte(rest, '/')
	if slash == -1 {
		return rest, "/", true
	}
	return rest[:slash], rest[slash:], true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
