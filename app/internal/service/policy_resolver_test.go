package service

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"sessionproxy/internal/domain"
	"sessionproxy/internal/domain/mocks"
)

func ptr(v int64) *int64 { return &v }

// TestPolicyResolver_NoPoliciesIsUnlimitedExceptViolationCount checks the
// zero-policy case: a link with nothing attached via link_policies is
// unlimited on every numeric dimension, but max_violation_count still
// falls back to the schema default of 3, not to "unlimited" - a link
// without an explicit policy is still subject to a violation cap.
func TestPolicyResolver_NoPoliciesIsUnlimitedExceptViolationCount(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mocks.NewMockAccessPolicyRepository(ctrl)
	linkID := uuid.New()
	repo.EXPECT().ListForLink(gomock.Any(), linkID).Return(nil, nil)

	resolver := NewPolicyResolver(repo)
	effective, err := resolver.Resolve(context.Background(), linkID)
	require.NoError(t, err)

	require.Nil(t, effective.MaxRequests)
	require.Nil(t, effective.MaxBytesTransferred)
	require.Nil(t, effective.MaxTTLSeconds)
	require.Equal(t, domain.DefaultMaxViolationCount, effective.MaxViolationCount)
}

// TestPolicyResolver_MostRestrictiveWinsAcrossMultiplePolicies is the core
// M:N link_policies scenario: two policies attached to the same link, each
// constraining a different (or overlapping) dimension, must resolve to the
// minimum of each field - not the first, not the last, not an average.
func TestPolicyResolver_MostRestrictiveWinsAcrossMultiplePolicies(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mocks.NewMockAccessPolicyRepository(ctrl)
	linkID := uuid.New()

	policies := []domain.AccessPolicy{
		{Name: "generous", MaxRequests: ptr(1000), MaxBytesTransferred: ptr(1_000_000)},
		{Name: "strict-requests-only", MaxRequests: ptr(50)}, // MaxBytesTransferred nil: does not restrict that dimension
	}
	repo.EXPECT().ListForLink(gomock.Any(), linkID).Return(policies, nil)

	resolver := NewPolicyResolver(repo)
	effective, err := resolver.Resolve(context.Background(), linkID)
	require.NoError(t, err)

	require.NotNil(t, effective.MaxRequests)
	require.Equal(t, int64(50), *effective.MaxRequests, "the stricter of 1000 and 50 must win")
	require.NotNil(t, effective.MaxBytesTransferred)
	require.Equal(t, int64(1_000_000), *effective.MaxBytesTransferred, "a NULL on one policy must not turn a real limit on another into unlimited")
}

// TestPolicyResolver_NullViolationCountFallsBackToDefault checks that an
// access_policy with an explicit NULL max_violation_count (the column is
// nullable in the schema) does not accidentally make the link's violation
// cap unlimited - it must fall back to the same default of 3 as having no
// policy at all.
func TestPolicyResolver_NullViolationCountFallsBackToDefault(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mocks.NewMockAccessPolicyRepository(ctrl)
	linkID := uuid.New()

	repo.EXPECT().ListForLink(gomock.Any(), linkID).Return([]domain.AccessPolicy{
		{Name: "no-violation-cap-set", MaxViolationCount: nil},
	}, nil)

	resolver := NewPolicyResolver(repo)
	effective, err := resolver.Resolve(context.Background(), linkID)
	require.NoError(t, err)
	require.Equal(t, domain.DefaultMaxViolationCount, effective.MaxViolationCount)
}

// TestPolicyResolver_ExplicitViolationCountOverridesDefault checks the
// normal case: an explicit, stricter max_violation_count on one policy
// replaces the default of 3.
func TestPolicyResolver_ExplicitViolationCountOverridesDefault(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mocks.NewMockAccessPolicyRepository(ctrl)
	linkID := uuid.New()

	repo.EXPECT().ListForLink(gomock.Any(), linkID).Return([]domain.AccessPolicy{
		{Name: "strict", MaxViolationCount: ptr(1)},
	}, nil)

	resolver := NewPolicyResolver(repo)
	effective, err := resolver.Resolve(context.Background(), linkID)
	require.NoError(t, err)
	require.Equal(t, int64(1), effective.MaxViolationCount)
}
