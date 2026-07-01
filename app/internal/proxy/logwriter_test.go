package proxy

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"sessionproxy/internal/domain"
)

// fakeLogRepo is a minimal in-memory stand-in for
// domain.ProxyAccessLogRepository, just enough to observe what
// AsyncAccessLogger actually flushed and how many batches it took.
type fakeLogRepo struct {
	mu      sync.Mutex
	rows    []domain.ProxyAccessLog
	batches int
}

func (f *fakeLogRepo) Insert(_ context.Context, l domain.ProxyAccessLog) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows = append(f.rows, l)
	f.batches++
	return nil
}

func (f *fakeLogRepo) InsertBatch(_ context.Context, logs []domain.ProxyAccessLog) error {
	if len(logs) == 0 {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows = append(f.rows, logs...)
	f.batches++
	return nil
}

func (f *fakeLogRepo) ListByLink(context.Context, uuid.UUID, int) ([]domain.ProxyAccessLog, error) {
	return nil, nil
}

func (f *fakeLogRepo) snapshot() ([]domain.ProxyAccessLog, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]domain.ProxyAccessLog(nil), f.rows...), f.batches
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestAsyncAccessLogger_FlushesOnBatchSize checks that a full batch flushes
// immediately rather than waiting for the timer, and that it lands in a
// single InsertBatch call.
func TestAsyncAccessLogger_FlushesOnBatchSize(t *testing.T) {
	repo := &fakeLogRepo{}
	logger := NewAsyncAccessLogger(repo, testLogger(), 3, time.Hour) // interval long enough to never fire in this test
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go logger.Run(ctx)

	linkID := uuid.New()
	for i := 0; i < 3; i++ {
		logger.Log(context.Background(), domain.ProxyAccessLog{SharedLinkID: linkID, HTTPMethod: "GET"})
	}

	require.Eventually(t, func() bool {
		rows, batches := repo.snapshot()
		return len(rows) == 3 && batches == 1
	}, 2*time.Second, 10*time.Millisecond, "3 entries with batch size 3 must flush as exactly one batch")
}

// TestAsyncAccessLogger_FlushesOnTimerWithPartialBatch checks that entries
// below the batch size still get written once the flush interval elapses -
// otherwise a quiet link's last few requests would never be logged.
func TestAsyncAccessLogger_FlushesOnTimerWithPartialBatch(t *testing.T) {
	repo := &fakeLogRepo{}
	logger := NewAsyncAccessLogger(repo, testLogger(), 100, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go logger.Run(ctx)

	logger.Log(context.Background(), domain.ProxyAccessLog{SharedLinkID: uuid.New(), HTTPMethod: "GET"})

	require.Eventually(t, func() bool {
		rows, _ := repo.snapshot()
		return len(rows) == 1
	}, 2*time.Second, 10*time.Millisecond, "a single entry below batch size must still flush once the timer fires")
}

// TestAsyncAccessLogger_FlushesRemainderOnShutdown checks that entries
// buffered but not yet flushed are written once when the context is
// cancelled, so a graceful shutdown does not silently drop the last batch.
func TestAsyncAccessLogger_FlushesRemainderOnShutdown(t *testing.T) {
	repo := &fakeLogRepo{}
	logger := NewAsyncAccessLogger(repo, testLogger(), 100, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		logger.Run(ctx)
		close(done)
	}()

	logger.Log(context.Background(), domain.ProxyAccessLog{SharedLinkID: uuid.New(), HTTPMethod: "GET"})
	time.Sleep(20 * time.Millisecond) // let Log's channel send land before shutdown
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}

	rows, _ := repo.snapshot()
	require.Len(t, rows, 1, "the buffered entry must be flushed on shutdown, not dropped")
}
