package service

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"sessionproxy/internal/domain"
)

// BlacklistService implements FR5/FR6's path-blocking half: matching a
// guest request's forward path (the path on the target site, with the
// "/r/{token}" prefix already stripped - not the guest-facing URL) against
// every blacklisted_endpoints rule that applies to a link, either directly
// (link_endpoint_rules) or through its target_site (site_endpoint_rules).
type BlacklistService struct {
	blacklist domain.BlacklistRepository
	logger    *slog.Logger
}

func NewBlacklistService(blacklist domain.BlacklistRepository, logger *slog.Logger) *BlacklistService {
	return &BlacklistService{blacklist: blacklist, logger: logger}
}

// Check returns the first rule that blocks this method+path combination for
// this link, or nil if none apply. It never returns an error for a request
// that simply isn't blocked - only for an infrastructure failure loading
// the rules, which the caller should treat as fail-closed (see MatchRules).
func (s *BlacklistService) Check(ctx context.Context, linkID, targetSiteID uuid.UUID, method, path string) (*domain.BlacklistedEndpoint, error) {
	rules, err := s.blacklist.RulesForLink(ctx, linkID, targetSiteID)
	if err != nil {
		return nil, fmt.Errorf("service: load blacklist rules: %w", err)
	}
	return s.MatchRules(rules, method, path), nil
}

// MatchRules is the pure matching logic, split out from Check so it can be
// unit tested without a database: it takes an already-loaded rule set and
// returns the first one that blocks method+path, or nil.
//
// Matching rules, both load-bearing and easy to get backwards:
//   - pattern_type "prefix": strings.HasPrefix(path, pattern).
//   - pattern_type "regex": regexp.MatchString(pattern, path). Go's regexp
//     is RE2 (linear time, no catastrophic backtracking / ReDoS), but a
//     malformed pattern still fails to compile - that failure is treated as
//     a match (fail-closed), not a skip, because this is a security control
//     and a broken rule must not silently stop blocking anything.
//   - BlockedMethods: an EMPTY slice means every HTTP method is blocked for
//     this pattern. A NON-EMPTY slice blocks only the methods it lists.
//     This is the opposite of the intuitive "empty = nothing blocked" and
//     is explicitly what domain.BlacklistedEndpoint.BlockedMethods documents.
func (s *BlacklistService) MatchRules(rules []domain.BlacklistedEndpoint, method, path string) *domain.BlacklistedEndpoint {
	for i := range rules {
		rule := rules[i]
		if !s.pathMatches(rule, path) {
			continue
		}
		if len(rule.BlockedMethods) > 0 && !containsMethod(rule.BlockedMethods, method) {
			continue
		}
		return &rule
	}
	return nil
}

func (s *BlacklistService) pathMatches(rule domain.BlacklistedEndpoint, path string) bool {
	switch rule.PatternType {
	case domain.PatternTypeRegex:
		matched, err := regexp.MatchString(rule.Pattern, path)
		if err != nil {
			s.logger.Error("blacklist: invalid regex pattern, failing closed", "endpoint_id", rule.ID, "pattern", rule.Pattern, "error", err)
			return true // fail-closed: a broken security rule blocks, it does not silently pass everything through
		}
		return matched
	default: // domain.PatternTypePrefix, and any unrecognized value defaults to prefix
		return strings.HasPrefix(path, rule.Pattern)
	}
}

func containsMethod(methods []string, method string) bool {
	for _, m := range methods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}
