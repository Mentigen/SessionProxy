package proxy

import (
	"context"
	"log/slog"
	"time"

	"sessionproxy/internal/domain"
)

// AsyncAccessLogger implements AccessLogger by buffering proxy_access_logs
// rows in memory and flushing them to Postgres in batches, either when the
// batch reaches BatchSize entries or every FlushInterval, whichever comes
// first. This replaces SyncAccessLogger (used through phase 2-5 to keep
// the data plane simple while it was still being proven correct) once the
// rest of the pipeline is settled: Log() no longer does any I/O on the
// guest's request path, which is what makes async logging worth the extra
// moving part - see internal/proxy/bodycounter.go and handler.go for where
// the numbers being logged come from.
//
// Log() never blocks the caller on a full buffer: it drops the entry and
// logs a warning instead. A dropped proxy_access_logs row is a monitoring
// gap, not a security or billing correctness issue (Redis counters in
// internal/limiter are the enforcement source of truth and are updated
// synchronously in handler.go, independently of this logger).
type AsyncAccessLogger struct {
	repo    domain.ProxyAccessLogRepository
	logger  *slog.Logger
	entries chan domain.ProxyAccessLog

	batchSize     int
	flushInterval time.Duration
}

// NewAsyncAccessLogger builds a logger; call Run in its own goroutine to
// start flushing.
func NewAsyncAccessLogger(repo domain.ProxyAccessLogRepository, logger *slog.Logger, batchSize int, flushInterval time.Duration) *AsyncAccessLogger {
	if batchSize < 1 {
		batchSize = 1
	}
	return &AsyncAccessLogger{
		repo:          repo,
		logger:        logger,
		entries:       make(chan domain.ProxyAccessLog, batchSize*20),
		batchSize:     batchSize,
		flushInterval: flushInterval,
	}
}

// Log enqueues one row. Called synchronously from Handler.ServeHTTP, but
// the channel send is the only work done on that path - no database access.
func (a *AsyncAccessLogger) Log(_ context.Context, entry domain.ProxyAccessLog) {
	select {
	case a.entries <- entry:
	default:
		a.logger.Warn("proxy: access log buffer full, dropping entry", "shared_link_id", entry.SharedLinkID)
	}
}

// Run flushes batches until ctx is cancelled, then flushes whatever is left
// once more before returning. Intended to be started with `go logger.Run(ctx)`
// from main().
func (a *AsyncAccessLogger) Run(ctx context.Context) {
	ticker := time.NewTicker(a.flushInterval)
	defer ticker.Stop()

	batch := make([]domain.ProxyAccessLog, 0, a.batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		// Deliberately not r.Context() or the request's context: by the
		// time a batch flushes, the request(s) that produced these entries
		// have long since returned and their contexts may already be
		// cancelled. The write must outlive any single request.
		if err := a.repo.InsertBatch(context.Background(), batch); err != nil {
			a.logger.Error("proxy: batch insert proxy_access_logs failed", "error", err, "count", len(batch))
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case e := <-a.entries:
			batch = append(batch, e)
			if len(batch) >= a.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}
