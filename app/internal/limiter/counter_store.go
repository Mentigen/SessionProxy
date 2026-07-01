// Package limiter implements the fast enforcement path for shared_link
// usage limits: per-request counters live in Redis (namespace "sp:"), with
// Postgres usage_counters as the durable, eventually-consistent copy that
// sync_worker.go flushes to periodically. Redis is the source of truth for
// the "is this request allowed right now" decision; Postgres is the
// source of truth for reporting/audit and for warm-loading Redis back after
// a restart (see WarmLoad).
package limiter

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const dirtySetKey = "sp:dirty_links"

// CounterStore wraps a single Redis client for the request/bytes/violation
// counters of every shared_link.
type CounterStore struct {
	rdb *redis.Client
}

func NewCounterStore(rdb *redis.Client) *CounterStore {
	return &CounterStore{rdb: rdb}
}

func requestsKey(linkID uuid.UUID) string   { return fmt.Sprintf("sp:link:%s:requests", linkID) }
func bytesKey(linkID uuid.UUID) string      { return fmt.Sprintf("sp:link:%s:bytes", linkID) }
func violationsKey(linkID uuid.UUID) string { return fmt.Sprintf("sp:link:%s:violations", linkID) }

// WarmLoad seeds Redis from the durable Postgres counters, but only for
// counters that don't exist in Redis yet (SETNX semantics). This is what
// makes a process restart safe: without it, every counter would silently
// reset to zero and every link would appear to have a fresh quota,
// violating FR6 (limits must actually be enforced) the moment the app
// restarts. Called lazily on first touch of a link, not eagerly for every
// link at startup - there is no bound on how many shared_links might exist.
func (c *CounterStore) WarmLoad(ctx context.Context, linkID uuid.UUID, requestCount, bytesTransferred, violationCount int64) error {
	pipe := c.rdb.Pipeline()
	pipe.SetNX(ctx, requestsKey(linkID), requestCount, 0)
	pipe.SetNX(ctx, bytesKey(linkID), bytesTransferred, 0)
	pipe.SetNX(ctx, violationsKey(linkID), violationCount, 0)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("limiter: warm load: %w", err)
	}
	return nil
}

// Counters is a snapshot of the three Redis-backed counters for one link.
type Counters struct {
	Requests   int64
	Bytes      int64
	Violations int64
}

// Get reads the current snapshot. A missing key (never warm-loaded or
// incremented) reads as 0, not an error - callers should WarmLoad before
// relying on this for enforcement decisions.
func (c *CounterStore) Get(ctx context.Context, linkID uuid.UUID) (Counters, error) {
	pipe := c.rdb.Pipeline()
	reqCmd := pipe.Get(ctx, requestsKey(linkID))
	bytesCmd := pipe.Get(ctx, bytesKey(linkID))
	violCmd := pipe.Get(ctx, violationsKey(linkID))
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return Counters{}, fmt.Errorf("limiter: get counters: %w", err)
	}
	reqs, err := intOrZero(reqCmd)
	if err != nil {
		return Counters{}, err
	}
	bytesV, err := intOrZero(bytesCmd)
	if err != nil {
		return Counters{}, err
	}
	viol, err := intOrZero(violCmd)
	if err != nil {
		return Counters{}, err
	}
	return Counters{Requests: reqs, Bytes: bytesV, Violations: viol}, nil
}

func intOrZero(cmd *redis.StringCmd) (int64, error) {
	v, err := cmd.Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, fmt.Errorf("limiter: parse counter: %w", err)
	}
	return v, nil
}

// IncrRequests increments the request counter (called before proxying, so
// even a request that later fails upstream still consumes quota) and marks
// the link dirty for the next sync_worker flush.
func (c *CounterStore) IncrRequests(ctx context.Context, linkID uuid.UUID) (int64, error) {
	return c.incrAndMarkDirty(ctx, linkID, requestsKey(linkID), 1)
}

// IncrBytes increments the byte counter by the exact number of bytes
// written to the guest (measured by proxy.countingResponseWriter, after the
// response is fully sent - not resp.ContentLength, which is -1 for chunked
// responses).
func (c *CounterStore) IncrBytes(ctx context.Context, linkID uuid.UUID, n int64) (int64, error) {
	return c.incrAndMarkDirty(ctx, linkID, bytesKey(linkID), n)
}

// IncrViolations increments the blacklist-violation counter (phase 5).
func (c *CounterStore) IncrViolations(ctx context.Context, linkID uuid.UUID) (int64, error) {
	return c.incrAndMarkDirty(ctx, linkID, violationsKey(linkID), 1)
}

func (c *CounterStore) incrAndMarkDirty(ctx context.Context, linkID uuid.UUID, key string, delta int64) (int64, error) {
	pipe := c.rdb.Pipeline()
	incrCmd := pipe.IncrBy(ctx, key, delta)
	pipe.SAdd(ctx, dirtySetKey, linkID.String())
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("limiter: increment %s: %w", key, err)
	}
	return incrCmd.Val(), nil
}

// SetTerminated updates nothing in Redis directly - termination status
// lives in Postgres shared_links.status, read fresh by the data plane on
// every request via SharedLinkRepository.GetByToken. Redis only tracks
// counters, never link status, which keeps this package from needing to
// invalidate a cache when an owner manually terminates a link through the
// control plane.

// DirtyLinkIDs returns every link with counters that have changed since the
// last sync_worker flush.
func (c *CounterStore) DirtyLinkIDs(ctx context.Context) ([]uuid.UUID, error) {
	raw, err := c.rdb.SMembers(ctx, dirtySetKey).Result()
	if err != nil {
		return nil, fmt.Errorf("limiter: list dirty links: %w", err)
	}
	out := make([]uuid.UUID, 0, len(raw))
	for _, s := range raw {
		id, err := uuid.Parse(s)
		if err != nil {
			continue
		}
		out = append(out, id)
	}
	return out, nil
}

// ClearDirty removes a link from the dirty set after sync_worker has
// successfully flushed its counters to usage_counters.
func (c *CounterStore) ClearDirty(ctx context.Context, linkID uuid.UUID) error {
	return c.rdb.SRem(ctx, dirtySetKey, linkID.String()).Err()
}
