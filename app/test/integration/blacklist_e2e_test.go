package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"sessionproxy/internal/domain"
	"sessionproxy/internal/proxy"
)

// TestBlacklist_BlockedPathReturns403AndLogsSecurityEvent is the FR5/FR7
// acceptance scenario: a link-level blacklist rule blocks a path on the
// target site before the target is ever contacted, and the attempt is
// recorded in security_events.
func TestBlacklist_BlockedPathReturns403AndLogsSecurityEvent(t *testing.T) {
	ctx := context.Background()
	env := setupEnv(t)
	rdb := startRedis(t)

	targetHit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	token := env.seedOwnerWithCookie(t, ctx, target.URL, "session_id", "owner-secret", false)
	link, err := env.repos.SharedLinks.GetByToken(ctx, token)
	require.NoError(t, err)

	endpoint, err := env.repos.Blacklist.Create(ctx, domain.BlacklistedEndpoint{
		UserID: link.OwnerUserID, Pattern: "/settings", PatternType: domain.PatternTypePrefix,
	})
	require.NoError(t, err)
	require.NoError(t, env.repos.Blacklist.AttachToLink(ctx, link.Link.ID, endpoint.ID))

	handler := newEnforcedProxyHandler(env, rdb)
	req := httptest.NewRequest(http.MethodGet, proxy.RoutePrefix+token+"/settings/profile", nil)
	req.RemoteAddr = "203.0.113.10:1111"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.False(t, targetHit, "a blacklisted path must never reach the target site")

	events, err := env.repos.SecurityEvents.ListByLink(ctx, link.Link.ID, 10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, domain.EventBlacklistViolation, events[0].EventType)
	require.Equal(t, "/settings/profile", *events[0].TargetURL)
}

// TestBlacklist_SiteLevelRuleAppliesAcrossLinks checks the other half of
// FR5: a rule attached to a target_site (not to one specific link) blocks
// every link created against sessions for that site.
func TestBlacklist_SiteLevelRuleAppliesAcrossLinks(t *testing.T) {
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

	endpoint, err := env.repos.Blacklist.Create(ctx, domain.BlacklistedEndpoint{
		UserID: link.OwnerUserID, Pattern: "/billing", PatternType: domain.PatternTypePrefix,
	})
	require.NoError(t, err)
	// Attached to the target_site, not to this specific link.
	require.NoError(t, env.repos.Blacklist.AttachToSite(ctx, link.TargetSite.ID, endpoint.ID))

	handler := newEnforcedProxyHandler(env, rdb)
	req := httptest.NewRequest(http.MethodGet, proxy.RoutePrefix+token+"/billing", nil)
	req.RemoteAddr = "203.0.113.11:2222"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
}

// TestBlacklist_ReachingMaxViolationCountTerminatesLink is the FR6
// acceptance scenario for the violation-count path specifically: repeated
// blacklist hits, not usage limits, must also auto-terminate once
// max_violation_count is reached.
func TestBlacklist_ReachingMaxViolationCountTerminatesLink(t *testing.T) {
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

	maxViolations := int64(2)
	policy, err := env.repos.AccessPolicies.Create(ctx, domain.AccessPolicy{
		UserID: link.OwnerUserID, Name: "strict", MaxViolationCount: &maxViolations,
	})
	require.NoError(t, err)
	require.NoError(t, env.repos.AccessPolicies.AttachToLink(ctx, link.Link.ID, policy.ID))

	endpoint, err := env.repos.Blacklist.Create(ctx, domain.BlacklistedEndpoint{
		UserID: link.OwnerUserID, Pattern: "/settings", PatternType: domain.PatternTypePrefix,
	})
	require.NoError(t, err)
	require.NoError(t, env.repos.Blacklist.AttachToLink(ctx, link.Link.ID, endpoint.ID))

	handler := newEnforcedProxyHandler(env, rdb)
	hitSettings := func() int {
		req := httptest.NewRequest(http.MethodGet, proxy.RoutePrefix+token+"/settings", nil)
		req.RemoteAddr = "203.0.113.12:3333"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	require.Equal(t, http.StatusForbidden, hitSettings(), "1st violation: blocked, link stays active")
	updatedAfterFirst, err := env.repos.SharedLinks.GetByID(ctx, link.Link.ID)
	require.NoError(t, err)
	require.Equal(t, domain.LinkStatusActive, updatedAfterFirst.Status)

	require.Equal(t, http.StatusForbidden, hitSettings(), "2nd violation: reaches max_violation_count, link is terminated")

	updated, err := env.repos.SharedLinks.GetByID(ctx, link.Link.ID)
	require.NoError(t, err)
	require.Equal(t, domain.LinkStatusTerminated, updated.Status)

	term, err := env.repos.LinkTerminations.GetByLink(ctx, link.Link.ID)
	require.NoError(t, err)
	require.NotNil(t, term)
	require.Equal(t, domain.ReasonViolationLimit, term.ReasonCode)

	events, err := env.repos.SecurityEvents.ListByLink(ctx, link.Link.ID, 10)
	require.NoError(t, err)
	require.Len(t, events, 2, "both violations must be logged, not just the one that crossed the threshold")
}
