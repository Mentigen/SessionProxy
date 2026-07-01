package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"sessionproxy/internal/domain"
)

// PolicyResolver turns the set of access_policies attached to a shared_link
// via link_policies (M:N) into one effective limit set, using
// most-restrictive-wins: the minimum of each field across every attached
// policy. A NULL field on any one policy does not participate in the min
// (it behaves as +Inf, i.e. "this policy does not restrict this
// dimension"), so a link with policies {max_requests: 100} and
// {max_requests: NULL, max_bytes_transferred: 5000} ends up with
// max_requests=100 and max_bytes_transferred=5000, not unlimited.
//
// A link with zero attached policies is unlimited on every numeric
// dimension except max_violation_count, which always defaults to
// domain.DefaultMaxViolationCount (3) - matching the schema-level DEFAULT.
type PolicyResolver struct {
	policies domain.AccessPolicyRepository
}

func NewPolicyResolver(policies domain.AccessPolicyRepository) *PolicyResolver {
	return &PolicyResolver{policies: policies}
}

func (r *PolicyResolver) Resolve(ctx context.Context, linkID uuid.UUID) (domain.EffectivePolicy, error) {
	policies, err := r.policies.ListForLink(ctx, linkID)
	if err != nil {
		return domain.EffectivePolicy{}, fmt.Errorf("service: list policies for link: %w", err)
	}

	effective := domain.EffectivePolicy{MaxViolationCount: domain.DefaultMaxViolationCount}
	for _, p := range policies {
		effective.MaxRequests = minPtr(effective.MaxRequests, p.MaxRequests)
		effective.MaxBytesTransferred = minPtr(effective.MaxBytesTransferred, p.MaxBytesTransferred)
		effective.MaxTTLSeconds = minPtr(effective.MaxTTLSeconds, p.MaxTTLSeconds)
		if p.MaxViolationCount != nil {
			effective.MaxViolationCount = minInt64(effective.MaxViolationCount, *p.MaxViolationCount)
		}
	}
	return effective, nil
}

// minPtr returns the smaller of two optional limits, treating nil as +Inf:
// nil vs nil -> nil, nil vs X -> X, X vs Y -> min(X, Y).
func minPtr(a, b *int64) *int64 {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case *a < *b:
		return a
	default:
		return b
	}
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
