// Package integration contains the end-to-end acceptance test for the data
// plane, run against a real Postgres (via testcontainers-go, migrated with
// the project's actual goose migrations - not a duplicated schema) and a
// real HTTP target (httptest.Server standing in for the guest's target
// site). This is the gate described in the implementation plan: if this
// test fails, the core premise of the project - safe credential injection
// with no leakage to the guest - does not hold.
package integration

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"sessionproxy/internal/crypto"
	"sessionproxy/internal/domain"
	"sessionproxy/internal/proxy"
	pgxrepo "sessionproxy/internal/repository/pgx"
)

// migrationsDir resolves the project's real migrations directory, one
// level above app/.
func migrationsDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd() // app/test/integration
	require.NoError(t, err)
	dir := filepath.Join(wd, "..", "..", "..", "migrations")
	_, err = os.Stat(dir)
	require.NoError(t, err, "migrations directory must exist at %s", dir)
	return dir
}

// testEnv bundles everything a test needs: a migrated Postgres, a pgx pool
// wired into the same repositories the app uses, and an AES cipher.
type testEnv struct {
	pool   *pgxpool.Pool
	repos  *pgxrepo.Repos
	cipher *crypto.Cipher
}

func setupEnv(t *testing.T) testEnv {
	t.Helper()
	ctx := context.Background()

	pgContainer, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("sessionproxy_test"),
		tcpostgres.WithUsername("sessionproxy"),
		tcpostgres.WithPassword("sessionproxy"),
		tcpostgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pgContainer.Terminate(context.Background()) })

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	// goose runs migrations through database/sql; the app itself talks to
	// Postgres through pgxpool, so this is the one place stdlib pgx shows up.
	db, err := sql.Open("pgx", connStr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, migrationsDir(t)))

	pool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	cipher, err := crypto.New([]byte("01234567890123456789012345678901")) // 32 bytes, test-only key
	require.NoError(t, err)

	return testEnv{pool: pool, repos: pgxrepo.NewRepos(pool), cipher: cipher}
}

// seedOwnerWithCookie creates the full ownership chain a guest request needs
// to resolve: user -> target_site -> original_session -> session_cookies
// (encrypted) -> shared_link. It returns the link's guest-facing token.
func (env testEnv) seedOwnerWithCookie(t *testing.T, ctx context.Context, targetBaseURL, cookieName, cookieValue string, linkExpired bool) string {
	t.Helper()

	user, err := env.repos.Users.Create(ctx, domain.User{Email: uuid.NewString() + "@example.com", PasswordHash: "irrelevant-for-this-test"})
	require.NoError(t, err)

	site, err := env.repos.TargetSites.Create(ctx, domain.TargetSite{BaseDomain: "stub.local", Name: "Stub", BaseURL: targetBaseURL})
	require.NoError(t, err)

	session, err := env.repos.OriginalSessions.Create(ctx, domain.OriginalSession{UserID: user.ID, TargetSiteID: site.ID})
	require.NoError(t, err)

	encrypted, err := env.cipher.Encrypt(cookieValue)
	require.NoError(t, err)
	require.NoError(t, env.repos.SessionCookies.CreateBatch(ctx, []domain.SessionCookie{
		{OriginalSessionID: session.ID, Name: cookieName, ValueEncrypted: encrypted, Path: "/"},
	}))

	link := domain.SharedLink{OriginalSessionID: session.ID, Token: uuid.NewString()}
	if linkExpired {
		past := time.Now().Add(-time.Hour)
		link.ExpiresAt = &past
	}
	created, err := env.repos.SharedLinks.Create(ctx, link)
	require.NoError(t, err)

	return created.Token
}

func newProxyHandler(env testEnv) *proxy.Handler {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	accessLogger := proxy.SyncAccessLogger{Repo: env.repos.ProxyAccessLogs, Logger: logger}
	return proxy.New(env.repos.SharedLinks, env.repos.SessionCookies, env.repos.SessionTokens, env.repos.Guests, env.repos.GuestSessions, env.cipher, accessLogger, logger)
}

// TestProxy_InjectsOwnerCookieAndStripsResponseSetCookie is the core FR3/FR4
// assertion: the target must receive the owner's decrypted cookie, and the
// guest must never receive whatever Set-Cookie the target sends back.
func TestProxy_InjectsOwnerCookieAndStripsResponseSetCookie(t *testing.T) {
	ctx := context.Background()
	env := setupEnv(t)

	var receivedCookie string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session_id")
		if err == nil {
			receivedCookie = c.Value
		}
		// #nosec G124 -- deliberately a "careless" cookie from the stub
		// target, to prove the proxy strips it before it reaches the guest.
		http.SetCookie(w, &http.Cookie{Name: "target_tracking_cookie", Value: "should-never-reach-guest"})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello from target"))
	}))
	defer target.Close()

	token := env.seedOwnerWithCookie(t, ctx, target.URL, "session_id", "owner-secret-abc123", false)
	handler := newProxyHandler(env)

	req := httptest.NewRequest(http.MethodGet, proxy.RoutePrefix+token+"/dashboard", nil)
	req.RemoteAddr = "203.0.113.5:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "owner-secret-abc123", receivedCookie, "target must receive the owner's decrypted cookie")
	require.Empty(t, rec.Result().Header.Values("Set-Cookie"), "guest must never receive any Set-Cookie from the target")
	require.Equal(t, "hello from target", rec.Body.String())
}

// TestProxy_ExpiredLinkReturns410 checks that a link past its own
// expires_at is rejected before any request reaches the target - the
// target must never be contacted for a dead link.
func TestProxy_ExpiredLinkReturns410(t *testing.T) {
	ctx := context.Background()
	env := setupEnv(t)

	targetHit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	token := env.seedOwnerWithCookie(t, ctx, target.URL, "session_id", "owner-secret", true)
	handler := newProxyHandler(env)

	req := httptest.NewRequest(http.MethodGet, proxy.RoutePrefix+token+"/anything", nil)
	req.RemoteAddr = "203.0.113.6:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusGone, rec.Code)
	require.False(t, targetHit, "an expired link must never reach the target site")
}

// TestProxy_UnknownTokenReturns404 checks the not-found path for a token
// that resolves to no shared_link at all.
func TestProxy_UnknownTokenReturns404(t *testing.T) {
	env := setupEnv(t)
	handler := newProxyHandler(env)

	req := httptest.NewRequest(http.MethodGet, proxy.RoutePrefix+"does-not-exist"+"/x", nil)
	req.RemoteAddr = "203.0.113.7:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
}

// TestProxy_WritesProxyAccessLog checks the row that eventually feeds the
// existing CDC pipeline (Debezium -> Kafka -> ClickHouse -> Metabase) is
// actually written for a successful proxied request.
func TestProxy_WritesProxyAccessLog(t *testing.T) {
	ctx := context.Background()
	env := setupEnv(t)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer target.Close()

	token := env.seedOwnerWithCookie(t, ctx, target.URL, "session_id", "owner-secret", false)
	handler := newProxyHandler(env)

	req := httptest.NewRequest(http.MethodGet, proxy.RoutePrefix+token+"/logged-path", nil)
	req.RemoteAddr = "203.0.113.8:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusTeapot, rec.Code)

	link, err := env.repos.SharedLinks.GetByToken(ctx, token)
	require.NoError(t, err)

	logs, err := env.repos.ProxyAccessLogs.ListByLink(ctx, link.Link.ID, 10)
	require.NoError(t, err)
	require.Len(t, logs, 1)
	require.Equal(t, http.StatusTeapot, *logs[0].ResponseStatus)
	require.Equal(t, http.MethodGet, logs[0].HTTPMethod)
}

// TestProxy_SameGuestReusesGuestSession is a regression test for a NULL-
// comparison bug: GuestRepo.GetOrCreate matched on
// "browser_fingerprint = NULL", which SQL never evaluates true, so every
// request from the same guest silently created a brand new guests row and
// guest_sessions row instead of reusing the existing active one.
func TestProxy_SameGuestReusesGuestSession(t *testing.T) {
	ctx := context.Background()
	env := setupEnv(t)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	token := env.seedOwnerWithCookie(t, ctx, target.URL, "session_id", "owner-secret", false)
	handler := newProxyHandler(env)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, proxy.RoutePrefix+token+"/again", nil)
		req.RemoteAddr = "198.51.100.9:55555"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	}

	link, err := env.repos.SharedLinks.GetByToken(ctx, token)
	require.NoError(t, err)

	sessions, err := env.repos.GuestSessions.ListByLink(ctx, link.Link.ID)
	require.NoError(t, err)
	require.Len(t, sessions, 1, "two requests from the same IP must reuse one guest_session, not create two")

	guests, err := env.repos.Guests.List(ctx, 100, 0)
	require.NoError(t, err)
	require.Len(t, guests, 1, "two requests from the same IP must reuse one guests row, not create two")
}
