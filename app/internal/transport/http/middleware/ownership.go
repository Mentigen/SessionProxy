package middleware

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// LinkOwnerResolver is the one join every link-scoped endpoint must go
// through: shared_links carries no user_id column by design (see
// README.md section 4), so ownership always resolves via
// original_sessions.user_id.
type LinkOwnerResolver interface {
	OwnerUserID(ctx context.Context, linkID uuid.UUID) (uuid.UUID, error)
}

// RequireLinkOwnership is mounted on every route under
// /api/v1/links/{linkID}/... (stats, logs, guest-sessions, security-events,
// terminate). It resolves {linkID} from the chi route, checks it against
// the authenticated user from RequireAuth, and responds 404 on mismatch -
// not 403 - so an owner probing another owner's link ID cannot even learn
// that it exists.
func RequireLinkOwnership(resolver LinkOwnerResolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			linkID, err := uuid.Parse(chi.URLParam(r, "linkID"))
			if err != nil {
				http.Error(w, "invalid link id", http.StatusBadRequest)
				return
			}
			owner, err := resolver.OwnerUserID(r.Context(), linkID)
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			if owner != UserID(r.Context()) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
