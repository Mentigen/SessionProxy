package limiter

import (
	"context"
	"log/slog"
	"time"

	"sessionproxy/internal/domain"
)

// SyncWorker periodically flushes the Redis-backed counters of every dirty
// link into usage_counters, so Postgres stays a reasonably fresh durable
// copy for reporting/audit and for WarmLoad after a restart. It is a pull
// loop over a Redis set (SMEMBERS sp:dirty_links), not a pub/sub - simpler
// to reason about and test deterministically than an event-driven design,
// at the cost of up to one interval of staleness in usage_counters (Redis
// itself is always current; this only affects the durable copy).
type SyncWorker struct {
	store    *CounterStore
	usage    domain.UsageCounterRepository
	interval time.Duration
	logger   *slog.Logger
}

func NewSyncWorker(store *CounterStore, usage domain.UsageCounterRepository, interval time.Duration, logger *slog.Logger) *SyncWorker {
	return &SyncWorker{store: store, usage: usage, interval: interval, logger: logger}
}

// Run blocks until ctx is cancelled, flushing on every tick. Intended to be
// started in its own goroutine from main().
func (w *SyncWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.flushOnce(ctx)
		}
	}
}

func (w *SyncWorker) flushOnce(ctx context.Context) {
	linkIDs, err := w.store.DirtyLinkIDs(ctx)
	if err != nil {
		w.logger.Error("sync_worker: list dirty links failed", "error", err)
		return
	}
	for _, linkID := range linkIDs {
		counters, err := w.store.Get(ctx, linkID)
		if err != nil {
			w.logger.Error("sync_worker: read counters failed", "link_id", linkID, "error", err)
			continue
		}
		err = w.usage.Upsert(ctx, domain.UsageCounters{
			SharedLinkID:     linkID,
			RequestCount:     counters.Requests,
			BytesTransferred: counters.Bytes,
			ViolationCount:   counters.Violations,
		})
		if err != nil {
			w.logger.Error("sync_worker: upsert usage_counters failed", "link_id", linkID, "error", err)
			continue
		}
		if err := w.store.ClearDirty(ctx, linkID); err != nil {
			w.logger.Error("sync_worker: clear dirty flag failed", "link_id", linkID, "error", err)
		}
	}
}
