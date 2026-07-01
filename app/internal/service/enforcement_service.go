package service

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"sessionproxy/internal/domain"
	"sessionproxy/internal/limiter"
	"sessionproxy/internal/pubsub"
)

// EnforcementService implements proxy.Enforcer (structurally - the proxy
// package never imports this one, keeping the data plane decoupled from
// how limits happen to be enforced). It is the application-layer logic the
// schema deliberately does not: README.md, "Примечание по бизнес-правилам
// 5 и 6" - comparing usage_counters against access_policies and flipping
// shared_links.status to 'terminated' cannot be done declaratively because
// the values live in different tables.
type EnforcementService struct {
	counters       *limiter.CounterStore
	policies       *PolicyResolver
	blacklist      *BlacklistService
	links          *LinkService
	usage          domain.UsageCounterRepository
	securityEvents domain.SecurityEventRepository
	hub            *pubsub.Hub // may be nil: without it, enforcement works exactly as before, just with no live feed
	logger         *slog.Logger
}

func NewEnforcementService(counters *limiter.CounterStore, policies *PolicyResolver, blacklist *BlacklistService, links *LinkService, usage domain.UsageCounterRepository, securityEvents domain.SecurityEventRepository, hub *pubsub.Hub, logger *slog.Logger) *EnforcementService {
	return &EnforcementService{counters: counters, policies: policies, blacklist: blacklist, links: links, usage: usage, securityEvents: securityEvents, hub: hub, logger: logger}
}

func (e *EnforcementService) publish(evtType pubsub.EventType, linkID uuid.UUID, message string) {
	if e.hub == nil {
		return
	}
	e.hub.Publish(pubsub.Event{Type: evtType, LinkID: linkID, Message: message, OccurredAt: time.Now()})
}

// BeforeProxy warm-loads Redis from the durable usage_counters row on first
// touch, resolves the link's effective policy (most-restrictive-wins across
// every attached access_policy), checks the blacklist (FR5), and rejects
// the request outright if any dimension is already at or past its limit.
// It runs before the target site is ever contacted.
func (e *EnforcementService) BeforeProxy(ctx context.Context, link domain.LinkWithSession, guestSessionID uuid.UUID, forwardPath string, r *http.Request) (bool, int, string, error) {
	if err := e.warmLoad(ctx, link.Link.ID); err != nil {
		return false, http.StatusInternalServerError, "internal error", err
	}

	effective, err := e.policies.Resolve(ctx, link.Link.ID)
	if err != nil {
		return false, http.StatusInternalServerError, "internal error", err
	}

	// Blacklist check runs first, before any numeric limit: a blocked path
	// is a security violation regardless of how much quota is left.
	blocked, err := e.blacklist.Check(ctx, link.Link.ID, link.TargetSite.ID, r.Method, forwardPath)
	if err != nil {
		return false, http.StatusInternalServerError, "internal error", err
	}
	if blocked != nil {
		return e.recordViolation(ctx, link, guestSessionID, effective, r.Method, forwardPath)
	}

	if effective.MaxTTLSeconds != nil {
		deadline := link.Link.CreatedAt.Add(time.Duration(*effective.MaxTTLSeconds) * time.Second)
		if time.Now().After(deadline) {
			e.autoTerminate(ctx, link.Link.ID, domain.ReasonTTLExpired)
			return false, http.StatusGone, "link TTL (from access policy) has expired", nil
		}
	}

	snapshot, err := e.counters.Get(ctx, link.Link.ID)
	if err != nil {
		return false, http.StatusInternalServerError, "internal error", err
	}

	if effective.MaxRequests != nil && snapshot.Requests >= *effective.MaxRequests {
		e.autoTerminate(ctx, link.Link.ID, domain.ReasonRequestLimit)
		return false, http.StatusForbidden, "request limit reached", nil
	}
	if effective.MaxBytesTransferred != nil && snapshot.Bytes >= *effective.MaxBytesTransferred {
		e.autoTerminate(ctx, link.Link.ID, domain.ReasonTrafficLimit)
		return false, http.StatusForbidden, "traffic limit reached", nil
	}
	if snapshot.Violations >= effective.MaxViolationCount {
		e.autoTerminate(ctx, link.Link.ID, domain.ReasonViolationLimit)
		return false, http.StatusForbidden, "violation limit reached", nil
	}

	return true, http.StatusOK, "", nil
}

// recordViolation writes the security_event for a blacklist match - every
// match, not only the one that eventually crosses the threshold - then
// increments the violation counter and auto-terminates once
// max_violation_count is reached. A blocked request never reaches
// AfterProxy (BeforeProxy returned ok=false), so the violation increment
// has to happen here; it is the only place a blocked request touches any
// counter.
func (e *EnforcementService) recordViolation(ctx context.Context, link domain.LinkWithSession, guestSessionID uuid.UUID, effective domain.EffectivePolicy, method, path string) (bool, int, string, error) {
	gsID := guestSessionID
	event := domain.SecurityEvent{
		GuestSessionID: &gsID,
		SharedLinkID:   link.Link.ID,
		EventType:      domain.EventBlacklistViolation,
		TargetURL:      &path,
		HTTPMethod:     &method,
	}
	if err := e.securityEvents.Create(ctx, event); err != nil {
		e.logger.Error("enforcement: failed to record security_event", "error", err)
	}
	e.publish(pubsub.EventBlacklistViolation, link.Link.ID, method+" "+path+" was blocked by blacklist")

	violations, err := e.counters.IncrViolations(ctx, link.Link.ID)
	if err != nil {
		e.logger.Error("enforcement: incr violations failed", "error", err)
	}

	if violations >= effective.MaxViolationCount {
		e.autoTerminate(ctx, link.Link.ID, domain.ReasonViolationLimit)
		return false, http.StatusForbidden, "link terminated: too many blacklist violations", nil
	}
	return false, http.StatusForbidden, "this path is not accessible through this shared link", nil
}

// AfterProxy increments Redis counters with the real numbers from the
// completed request/response, then re-checks the same thresholds: a
// request that was allowed to start can still be the one that pushes the
// link over its limit, in which case the link is terminated for the
// request that follows, not this one - this one already got its response.
func (e *EnforcementService) AfterProxy(ctx context.Context, link domain.LinkWithSession, guestSessionID uuid.UUID, statusCode int, bytesTransferred int64) {
	if _, err := e.counters.IncrRequests(ctx, link.Link.ID); err != nil {
		e.logger.Error("enforcement: incr requests failed", "error", err)
	}
	if _, err := e.counters.IncrBytes(ctx, link.Link.ID, bytesTransferred); err != nil {
		e.logger.Error("enforcement: incr bytes failed", "error", err)
	}

	effective, err := e.policies.Resolve(ctx, link.Link.ID)
	if err != nil {
		e.logger.Error("enforcement: resolve policy failed", "error", err)
		return
	}
	snapshot, err := e.counters.Get(ctx, link.Link.ID)
	if err != nil {
		e.logger.Error("enforcement: get counters failed", "error", err)
		return
	}

	switch {
	case effective.MaxRequests != nil && snapshot.Requests >= *effective.MaxRequests:
		e.autoTerminate(ctx, link.Link.ID, domain.ReasonRequestLimit)
	case effective.MaxBytesTransferred != nil && snapshot.Bytes >= *effective.MaxBytesTransferred:
		e.autoTerminate(ctx, link.Link.ID, domain.ReasonTrafficLimit)
	}
}

func (e *EnforcementService) warmLoad(ctx context.Context, linkID uuid.UUID) error {
	usage, err := e.usage.GetByLink(ctx, linkID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			usage = domain.UsageCounters{SharedLinkID: linkID}
		} else {
			return err
		}
	}
	return e.counters.WarmLoad(ctx, linkID, usage.RequestCount, usage.BytesTransferred, usage.ViolationCount)
}

func (e *EnforcementService) autoTerminate(ctx context.Context, linkID uuid.UUID, reason string) {
	if err := e.links.AutoTerminate(ctx, linkID, reason); err != nil {
		e.logger.Error("enforcement: auto-terminate failed", "link_id", linkID, "reason", reason, "error", err)
		return
	}
	e.publish(pubsub.EventLinkTerminated, linkID, "link auto-terminated: "+reason)
}
