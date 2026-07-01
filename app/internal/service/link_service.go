package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"sessionproxy/internal/domain"
)

var (
	ErrSessionNotOwned       = errors.New("service: original_session does not belong to this user")
	ErrSessionNotActive      = errors.New("service: original_session is not active")
	ErrLinkNotOwned          = errors.New("service: shared_link does not belong to this user")
	ErrLinkAlreadyTerminated = errors.New("service: shared_link is already terminated")
)

// LinkService implements FR2 (create a shared_link with TTL/limits) and the
// owner-facing half of FR6 (manual termination). Automatic termination
// triggered by usage limits lives in enforcement_service.go (phase 4),
// which reuses TerminateLink's write path.
type LinkService struct {
	sessions     domain.OriginalSessionRepository
	links        domain.SharedLinkRepository
	policies     domain.AccessPolicyRepository
	blacklist    domain.BlacklistRepository
	terminations domain.LinkTerminationRepository
}

func NewLinkService(sessions domain.OriginalSessionRepository, links domain.SharedLinkRepository, policies domain.AccessPolicyRepository, blacklist domain.BlacklistRepository, terminations domain.LinkTerminationRepository) *LinkService {
	return &LinkService{sessions: sessions, links: links, policies: policies, blacklist: blacklist, terminations: terminations}
}

// CreateLinkInput is everything an owner supplies when turning an imported
// session into a guest-facing capability URL.
type CreateLinkInput struct {
	OriginalSessionID uuid.UUID
	Label             string
	TTL               time.Duration // zero means no expires_at
	PolicyIDs         []uuid.UUID   // access_policies to attach via link_policies
	EndpointIDs       []uuid.UUID   // blacklisted_endpoints to attach via link_endpoint_rules
}

// CreateLink validates that the session belongs to the caller and is
// active, generates a capability token, and attaches whichever policies
// and link-level blacklist rules the owner selected. It is not wrapped in a
// database transaction: a failure attaching one policy leaves the link
// created but partially configured rather than rolled back entirely. This
// is an accepted simplification (documented in README) - the owner-facing
// API surfaces partial failures and lets the owner retry the attach calls,
// rather than the app carrying a generic cross-table transaction helper
// used by exactly one write path.
func (s *LinkService) CreateLink(ctx context.Context, userID uuid.UUID, in CreateLinkInput) (domain.SharedLink, error) {
	session, err := s.sessions.GetByID(ctx, in.OriginalSessionID)
	if err != nil {
		return domain.SharedLink{}, fmt.Errorf("service: load original_session: %w", err)
	}
	if session.UserID != userID {
		return domain.SharedLink{}, ErrSessionNotOwned
	}
	if session.Status != domain.SessionStatusActive {
		return domain.SharedLink{}, ErrSessionNotActive
	}

	token, err := generateLinkToken()
	if err != nil {
		return domain.SharedLink{}, err
	}

	link := domain.SharedLink{OriginalSessionID: in.OriginalSessionID, Token: token}
	if in.Label != "" {
		link.Label = &in.Label
	}
	if in.TTL > 0 {
		expiry := time.Now().Add(in.TTL)
		link.ExpiresAt = &expiry
	}

	created, err := s.links.Create(ctx, link)
	if err != nil {
		return domain.SharedLink{}, fmt.Errorf("service: create shared_link: %w", err)
	}

	for _, policyID := range in.PolicyIDs {
		if err := s.policies.AttachToLink(ctx, created.ID, policyID); err != nil {
			return created, fmt.Errorf("service: attach policy %s: %w", policyID, err)
		}
	}
	for _, endpointID := range in.EndpointIDs {
		if err := s.blacklist.AttachToLink(ctx, created.ID, endpointID); err != nil {
			return created, fmt.Errorf("service: attach blacklist rule %s: %w", endpointID, err)
		}
	}

	return created, nil
}

func generateLinkToken() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("service: generate link token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// TerminateLink implements the owner-initiated half of FR6/FR8: it verifies
// ownership through shared_links.original_session_id -> original_sessions.user_id
// (the join the schema requires, since shared_links carries no user_id),
// then flips the link to terminated and records why in link_terminations.
func (s *LinkService) TerminateLink(ctx context.Context, userID, linkID uuid.UUID, notes string) error {
	owner, err := s.links.OwnerUserID(ctx, linkID)
	if err != nil {
		return fmt.Errorf("service: resolve link owner: %w", err)
	}
	if owner != userID {
		return ErrLinkNotOwned
	}

	link, err := s.links.GetByID(ctx, linkID)
	if err != nil {
		return fmt.Errorf("service: load shared_link: %w", err)
	}
	if link.Status == domain.LinkStatusTerminated {
		return ErrLinkAlreadyTerminated
	}

	if err := s.links.UpdateStatus(ctx, linkID, domain.LinkStatusTerminated); err != nil {
		return fmt.Errorf("service: update shared_link status: %w", err)
	}

	term := domain.LinkTermination{SharedLinkID: linkID, ReasonCode: domain.ReasonManual, TerminatedBy: &userID}
	if notes != "" {
		term.Notes = &notes
	}
	if err := s.terminations.Create(ctx, term); err != nil {
		return fmt.Errorf("service: record link_termination: %w", err)
	}
	return nil
}

// AutoTerminate is the system-triggered counterpart to TerminateLink: no
// owner is involved, so there is no ownership check and terminated_by
// stays NULL (see README.md: "NULL, если ссылка была отключена
// автоматически"). It is called by EnforcementService when Redis counters
// cross an effective policy limit, and by the data plane's own TTL check.
// It is idempotent - terminating an already-terminated link is a no-op,
// not an error, since limiter increments can race across concurrent
// requests for the same link.
func (s *LinkService) AutoTerminate(ctx context.Context, linkID uuid.UUID, reasonCode string) error {
	link, err := s.links.GetByID(ctx, linkID)
	if err != nil {
		return fmt.Errorf("service: load shared_link: %w", err)
	}
	if link.Status == domain.LinkStatusTerminated {
		return nil
	}
	if err := s.links.UpdateStatus(ctx, linkID, domain.LinkStatusTerminated); err != nil {
		return fmt.Errorf("service: update shared_link status: %w", err)
	}
	if err := s.terminations.Create(ctx, domain.LinkTermination{SharedLinkID: linkID, ReasonCode: reasonCode}); err != nil {
		return fmt.Errorf("service: record link_termination: %w", err)
	}
	return nil
}
