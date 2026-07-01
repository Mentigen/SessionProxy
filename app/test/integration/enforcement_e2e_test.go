package integration

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"

	"sessionproxy/internal/domain"
	"sessionproxy/internal/limiter"
	"sessionproxy/internal/proxy"
	"sessionproxy/internal/service"
)

func startRedis(t *testing.T) *goredis.Client {
	t.Helper()
	ctx := context.Background()
	container, err := tcredis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	connStr, err := container.ConnectionString(ctx)
	require.NoError(t, err)
	opts, err := goredis.ParseURL(connStr)
	require.NoError(t, err)
	client := goredis.NewClient(opts)
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.Ping(ctx).Err())
	return client
}

func newEnforcedProxyHandler(env testEnv, rdb *goredis.Client) *proxy.Handler {
	logger := slog.New(slog.NewTextHandler(discardWriter{}, nil))
	accessLogger := proxy.SyncAccessLogger{Repo: env.repos.ProxyAccessLogs, Logger: logger}
	handler := proxy.New(env.repos.SharedLinks, env.repos.SessionCookies, env.repos.SessionTokens, env.repos.Guests, env.repos.GuestSessions, env.cipher, accessLogger, logger)

	counters := limiter.NewCounterStore(rdb)
	policies := service.NewPolicyResolver(env.repos.AccessPolicies)
	blacklist := service.NewBlacklistService(env.repos.Blacklist, logger)
	links := service.NewLinkService(env.repos.OriginalSessions, env.repos.SharedLinks, env.repos.AccessPolicies, env.repos.Blacklist, env.repos.LinkTerminations)
	handler.Enforcer = service.NewEnforcementService(counters, policies, blacklist, links, env.repos.UsageCounters, env.repos.SecurityEvents, nil, logger)
	return handler
}

// TestEnforcement_RequestLimitTerminatesLink is the FR6 acceptance
// scenario: a link with a 2-request policy allows exactly two guest
// requests and rejects the third, auto-terminating the link with reason
// "request_limit".
func TestEnforcement_RequestLimitTerminatesLink(t *testing.T) {
	ctx := context.Background()
	env := setupEnv(t)
	rdb := startRedis(t)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	token := env.seedOwnerWithCookie(t, ctx, target.URL, "session_id", "owner-secret", false)
	link, err := env.repos.SharedLinks.GetByToken(ctx, token)
	require.NoError(t, err)

	maxRequests := int64(2)
	policy, err := env.repos.AccessPolicies.Create(ctx, domain.AccessPolicy{
		UserID: link.OwnerUserID, Name: "two-requests-only", MaxRequests: &maxRequests,
	})
	require.NoError(t, err)
	require.NoError(t, env.repos.AccessPolicies.AttachToLink(ctx, link.Link.ID, policy.ID))

	handler := newEnforcedProxyHandler(env, rdb)

	doRequest := func() int {
		req := httptest.NewRequest(http.MethodGet, proxy.RoutePrefix+token+"/x", nil)
		req.RemoteAddr = "192.0.2.50:9999"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	require.Equal(t, http.StatusOK, doRequest(), "1st request must be allowed")
	require.Equal(t, http.StatusOK, doRequest(), "2nd request must be allowed - it is the one that reaches the limit")
	// AfterProxy on the 2nd request already saw requests==max_requests and
	// auto-terminated the link, so the 3rd request never gets as far as
	// EnforcementService.BeforeProxy - handler.go's own inactiveReason
	// check rejects it first with 410, the same status an owner-terminated
	// or expired link returns. Enforcer.BeforeProxy's own >= check exists
	// as a second line of defense for the concurrent-request race where two
	// requests could pass the status check before either's AfterProxy runs.
	require.Equal(t, http.StatusGone, doRequest(), "3rd request must be rejected - the link was already auto-terminated")

	updated, err := env.repos.SharedLinks.GetByID(ctx, link.Link.ID)
	require.NoError(t, err)
	require.Equal(t, domain.LinkStatusTerminated, updated.Status)

	term, err := env.repos.LinkTerminations.GetByLink(ctx, link.Link.ID)
	require.NoError(t, err)
	require.NotNil(t, term)
	require.Equal(t, domain.ReasonRequestLimit, term.ReasonCode)
}

// TestEnforcement_WarmLoadSurvivesRedisRestart is the regression test for
// the exact failure mode flagged during planning: if Redis restarts (here
// simulated with FlushAll) without warm-loading from usage_counters first,
// a link that had already reached its limit would silently regain a fresh
// quota. This proves it does not.
func TestEnforcement_WarmLoadSurvivesRedisRestart(t *testing.T) {
	ctx := context.Background()
	env := setupEnv(t)
	rdb := startRedis(t)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	token := env.seedOwnerWithCookie(t, ctx, target.URL, "session_id", "owner-secret", false)
	link, err := env.repos.SharedLinks.GetByToken(ctx, token)
	require.NoError(t, err)

	maxRequests := int64(5)
	policy, err := env.repos.AccessPolicies.Create(ctx, domain.AccessPolicy{
		UserID: link.OwnerUserID, Name: "five-requests", MaxRequests: &maxRequests,
	})
	require.NoError(t, err)
	require.NoError(t, env.repos.AccessPolicies.AttachToLink(ctx, link.Link.ID, policy.ID))

	// Simulate that, before a crash, the link had already consumed its
	// entire quota and that fact was durably flushed to Postgres.
	require.NoError(t, env.repos.UsageCounters.Upsert(ctx, domain.UsageCounters{
		SharedLinkID: link.Link.ID, RequestCount: maxRequests, BytesTransferred: 0, ViolationCount: 0,
	}))

	// Simulate the Redis restart: no counters survive.
	require.NoError(t, rdb.FlushAll(ctx).Err())

	handler := newEnforcedProxyHandler(env, rdb)
	req := httptest.NewRequest(http.MethodGet, proxy.RoutePrefix+token+"/x", nil)
	req.RemoteAddr = "192.0.2.51:9999"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code, "warm-loaded counters must still reflect the exhausted quota, not reset to zero")

	updated, err := env.repos.SharedLinks.GetByID(ctx, link.Link.ID)
	require.NoError(t, err)
	require.Equal(t, domain.LinkStatusTerminated, updated.Status)
}

// TestEnforcement_SyncWorkerFlushesRedisToPostgres checks the durability
// side: after a few allowed requests, the periodic worker must land the
// same counts in usage_counters, not just Redis.
func TestEnforcement_SyncWorkerFlushesRedisToPostgres(t *testing.T) {
	ctx := context.Background()
	env := setupEnv(t)
	rdb := startRedis(t)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	token := env.seedOwnerWithCookie(t, ctx, target.URL, "session_id", "owner-secret", false)
	link, err := env.repos.SharedLinks.GetByToken(ctx, token)
	require.NoError(t, err)

	handler := newEnforcedProxyHandler(env, rdb)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, proxy.RoutePrefix+token+"/x", nil)
		req.RemoteAddr = "192.0.2.52:9999"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	}

	counterStore := limiter.NewCounterStore(rdb)
	worker := limiter.NewSyncWorker(counterStore, env.repos.UsageCounters, time.Second, slog.New(slog.NewTextHandler(discardWriter{}, nil)))
	workerCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	go worker.Run(workerCtx)
	<-workerCtx.Done()

	usage, err := env.repos.UsageCounters.GetByLink(ctx, link.Link.ID)
	require.NoError(t, err)
	require.Equal(t, int64(3), usage.RequestCount, "sync_worker must flush the Redis request count into usage_counters")
}
