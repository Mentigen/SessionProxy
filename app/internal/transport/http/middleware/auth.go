// Package middleware holds cross-cutting HTTP concerns for the owner-facing
// control plane: authentication and ownership checks. Neither applies to
// the guest-facing data plane (internal/proxy), which is deliberately
// unauthenticated - the link token itself is the capability.
package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

type ctxKey int

const userIDKey ctxKey = 1

// Authenticator verifies a bearer token - either an owner JWT (from
// AuthService.VerifyJWT) or a long-lived api_keys value (VerifyAPIKey) -
// and returns the owning user_id. Both accept the same "Authorization:
// Bearer <token>" header; which one applies is told apart by prefix
// (api keys are minted as "spk_...", see AuthService.CreateAPIKey).
type Authenticator interface {
	VerifyJWT(token string) (uuid.UUID, error)
	VerifyAPIKey(ctx context.Context, rawKey string) (uuid.UUID, error)
}

// RequireAuth rejects any request without a valid bearer credential and
// stores the resolved user_id in the request context for downstream
// handlers and the Ownership middleware.
func RequireAuth(auth Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := bearerToken(r)
			if !ok {
				http.Error(w, "missing or malformed Authorization header", http.StatusUnauthorized)
				return
			}

			var (
				userID uuid.UUID
				err    error
			)
			if strings.HasPrefix(token, "spk_") {
				userID, err = auth.VerifyAPIKey(r.Context(), token)
			} else {
				userID, err = auth.VerifyJWT(token)
			}
			if err != nil {
				http.Error(w, "invalid credentials", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), userIDKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SessionCookieName is the httpOnly cookie the web dashboard stores its JWT
// in - a browser session, as opposed to the Authorization header used by
// REST/CLI/gRPC clients. Same JWT, same AuthService.VerifyJWT, different
// transport.
const SessionCookieName = "sp_session"

// RequireSessionCookie is RequireAuth's counterpart for the HTML dashboard:
// it reads the JWT from SessionCookieName instead of an Authorization
// header, and redirects to /dashboard/login instead of returning a bare
// 401, since the caller here is a browser navigating pages, not an API
// client.
func RequireSessionCookie(auth Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(SessionCookieName)
			if err != nil || cookie.Value == "" {
				http.Redirect(w, r, "/dashboard/login", http.StatusSeeOther)
				return
			}
			userID, err := auth.VerifyJWT(cookie.Value)
			if err != nil {
				http.Redirect(w, r, "/dashboard/login", http.StatusSeeOther)
				return
			}
			ctx := context.WithValue(r.Context(), userIDKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	return strings.TrimPrefix(h, prefix), true
}

// UserID reads the authenticated owner's user_id set by RequireAuth. It
// panics if called on a request that did not go through RequireAuth - a
// programmer error (unprotected route), not a runtime condition to recover
// from silently.
func UserID(ctx context.Context) uuid.UUID {
	id, ok := ctx.Value(userIDKey).(uuid.UUID)
	if !ok {
		panic("middleware: UserID called without RequireAuth in the chain")
	}
	return id
}
