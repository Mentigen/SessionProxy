package service

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"sessionproxy/internal/domain"
)

func newTestBlacklistService() *BlacklistService {
	return NewBlacklistService(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestMatchRules_PrefixMatch(t *testing.T) {
	s := newTestBlacklistService()
	rules := []domain.BlacklistedEndpoint{{Pattern: "/settings", PatternType: domain.PatternTypePrefix}}

	require.NotNil(t, s.MatchRules(rules, "GET", "/settings"))
	require.NotNil(t, s.MatchRules(rules, "GET", "/settings/profile"))
	require.Nil(t, s.MatchRules(rules, "GET", "/dashboard"))
}

// TestMatchRules_MatchesForwardPathNotGuestURL is a regression test for the
// exact bug flagged during planning: the blacklist must be checked against
// the forward path on the target site (e.g. "/settings"), never against
// the guest-facing "/r/{token}/settings" URL, or a prefix rule would never
// match anything.
func TestMatchRules_MatchesForwardPathNotGuestURL(t *testing.T) {
	s := newTestBlacklistService()
	rules := []domain.BlacklistedEndpoint{{Pattern: "/settings", PatternType: domain.PatternTypePrefix}}

	require.Nil(t, s.MatchRules(rules, "GET", "/r/some-token/settings"), "matching the raw guest URL must not accidentally succeed either")
	require.NotNil(t, s.MatchRules(rules, "GET", "/settings"), "matching the stripped forward path must succeed")
}

func TestMatchRules_RegexMatch(t *testing.T) {
	s := newTestBlacklistService()
	rules := []domain.BlacklistedEndpoint{{Pattern: `^/account/\d+/delete$`, PatternType: domain.PatternTypeRegex}}

	require.NotNil(t, s.MatchRules(rules, "POST", "/account/42/delete"))
	require.Nil(t, s.MatchRules(rules, "POST", "/account/42/edit"))
}

func TestMatchRules_InvalidRegexFailsClosed(t *testing.T) {
	s := newTestBlacklistService()
	rules := []domain.BlacklistedEndpoint{{Pattern: `(unclosed`, PatternType: domain.PatternTypeRegex}}

	require.NotNil(t, s.MatchRules(rules, "GET", "/anything"), "a broken regex rule must block rather than silently pass everything through")
}

// TestMatchRules_EmptyBlockedMethodsBlocksEverything is a regression test
// for the semantics documented on domain.BlacklistedEndpoint.BlockedMethods:
// an empty slice means "block regardless of method", not "block nothing".
func TestMatchRules_EmptyBlockedMethodsBlocksEverything(t *testing.T) {
	s := newTestBlacklistService()
	rules := []domain.BlacklistedEndpoint{{Pattern: "/billing", PatternType: domain.PatternTypePrefix}}

	require.NotNil(t, s.MatchRules(rules, "GET", "/billing"))
	require.NotNil(t, s.MatchRules(rules, "DELETE", "/billing"))
}

func TestMatchRules_NonEmptyBlockedMethodsOnlyBlocksThoseMethods(t *testing.T) {
	s := newTestBlacklistService()
	rules := []domain.BlacklistedEndpoint{{
		Pattern: "/account/delete", PatternType: domain.PatternTypePrefix,
		BlockedMethods: []string{"POST", "DELETE"},
	}}

	require.NotNil(t, s.MatchRules(rules, "POST", "/account/delete"))
	require.NotNil(t, s.MatchRules(rules, "DELETE", "/account/delete"))
	require.Nil(t, s.MatchRules(rules, "GET", "/account/delete"), "GET is not in the blocked method list")
}
