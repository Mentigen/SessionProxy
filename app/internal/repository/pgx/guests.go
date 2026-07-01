package pgx

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"sessionproxy/internal/domain"
)

// GuestRepo implements domain.GuestRepository.
type GuestRepo struct{ q querier }

func NewGuestRepo(q querier) *GuestRepo { return &GuestRepo{q: q} }

// GetOrCreate identifies a guest by IP+UA+fingerprint. This is the proxy's
// own anonymous guest bookkeeping - unrelated to any cookie the owner's
// session carries, and it never touches session_cookies/session_tokens.
func (r *GuestRepo) GetOrCreate(ctx context.Context, ipAddress, userAgent, fingerprint string) (domain.Guest, error) {
	row := r.q.QueryRow(ctx, `
		SELECT id, ip_address, user_agent, browser_fingerprint, first_seen_at, last_seen_at
		FROM guests
		WHERE ip_address IS NOT DISTINCT FROM $1 AND browser_fingerprint IS NOT DISTINCT FROM $2
		ORDER BY first_seen_at DESC LIMIT 1`, nullIfEmpty(ipAddress), nullIfEmpty(fingerprint))
	g, err := scanGuest(row)
	if err == nil {
		_, _ = r.q.Exec(ctx, `UPDATE guests SET last_seen_at=now() WHERE id=$1`, g.ID)
		return g, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return domain.Guest{}, err
	}
	row = r.q.QueryRow(ctx, `
		INSERT INTO guests (id, ip_address, user_agent, browser_fingerprint)
		VALUES (gen_random_uuid(), $1, $2, $3)
		RETURNING id, ip_address, user_agent, browser_fingerprint, first_seen_at, last_seen_at`,
		nullIfEmpty(ipAddress), nullIfEmpty(userAgent), nullIfEmpty(fingerprint))
	return scanGuest(row)
}

func (r *GuestRepo) List(ctx context.Context, limit, offset int) ([]domain.Guest, error) {
	rows, err := r.q.Query(ctx, `SELECT id, ip_address, user_agent, browser_fingerprint, first_seen_at, last_seen_at FROM guests ORDER BY first_seen_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("pgx: list guests: %w", err)
	}
	defer rows.Close()
	var out []domain.Guest
	for rows.Next() {
		g, err := scanGuest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func scanGuest(row scanner) (domain.Guest, error) {
	var g domain.Guest
	err := row.Scan(&g.ID, &g.IPAddress, &g.UserAgent, &g.BrowserFingerprint, &g.FirstSeenAt, &g.LastSeenAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Guest{}, err
		}
		return domain.Guest{}, fmt.Errorf("pgx: scan guest: %w", err)
	}
	return g, nil
}

// GuestSessionRepo implements domain.GuestSessionRepository.
type GuestSessionRepo struct{ q querier }

func NewGuestSessionRepo(q querier) *GuestSessionRepo { return &GuestSessionRepo{q: q} }

func (r *GuestSessionRepo) Create(ctx context.Context, gs domain.GuestSession) (domain.GuestSession, error) {
	row := r.q.QueryRow(ctx, `
		INSERT INTO guest_sessions (id, shared_link_id, guest_id, status)
		VALUES (gen_random_uuid(), $1, $2, COALESCE($3, 'active'))
		RETURNING id, shared_link_id, guest_id, status, started_at, last_request_at, terminated_at`,
		gs.SharedLinkID, gs.GuestID, nullIfEmpty(gs.Status))
	return scanGuestSession(row)
}

// GetActiveByLinkAndGuest is used on every proxied request to decide
// whether this is a returning guest (reuse the guest_session, satisfying
// the FK on proxy_access_logs) or a brand new one.
func (r *GuestSessionRepo) GetActiveByLinkAndGuest(ctx context.Context, linkID uuid.UUID, guestID *uuid.UUID) (*domain.GuestSession, error) {
	row := r.q.QueryRow(ctx, `
		SELECT id, shared_link_id, guest_id, status, started_at, last_request_at, terminated_at
		FROM guest_sessions
		WHERE shared_link_id=$1
		  AND (guest_id = $2 OR ($2::uuid IS NULL AND guest_id IS NULL))
		  AND status='active'
		ORDER BY started_at DESC LIMIT 1`, linkID, guestID)
	gs, err := scanGuestSession(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &gs, nil
}

func (r *GuestSessionRepo) ListByLink(ctx context.Context, linkID uuid.UUID) ([]domain.GuestSession, error) {
	rows, err := r.q.Query(ctx, `SELECT id, shared_link_id, guest_id, status, started_at, last_request_at, terminated_at FROM guest_sessions WHERE shared_link_id=$1 ORDER BY started_at DESC`, linkID)
	if err != nil {
		return nil, fmt.Errorf("pgx: list guest_sessions: %w", err)
	}
	defer rows.Close()
	var out []domain.GuestSession
	for rows.Next() {
		gs, err := scanGuestSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, gs)
	}
	return out, rows.Err()
}

func (r *GuestSessionRepo) Terminate(ctx context.Context, id uuid.UUID) error {
	_, err := r.q.Exec(ctx, `UPDATE guest_sessions SET status='terminated', terminated_at=now() WHERE id=$1`, id)
	return err
}

func (r *GuestSessionRepo) TouchLastRequest(ctx context.Context, id uuid.UUID) error {
	_, err := r.q.Exec(ctx, `UPDATE guest_sessions SET last_request_at=now() WHERE id=$1`, id)
	return err
}

func scanGuestSession(row scanner) (domain.GuestSession, error) {
	var gs domain.GuestSession
	err := row.Scan(&gs.ID, &gs.SharedLinkID, &gs.GuestID, &gs.Status, &gs.StartedAt, &gs.LastRequestAt, &gs.TerminatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.GuestSession{}, err
		}
		return domain.GuestSession{}, fmt.Errorf("pgx: scan guest_session: %w", err)
	}
	return gs, nil
}

// UsageCounterRepo implements domain.UsageCounterRepository. It is the
// durability/reporting side of the limiter: Redis is the fast enforcement
// path, this table is what sync_worker flushes into and what the app warm-
// loads Redis from on startup (see internal/limiter).
type UsageCounterRepo struct{ q querier }

func NewUsageCounterRepo(q querier) *UsageCounterRepo { return &UsageCounterRepo{q: q} }

func (r *UsageCounterRepo) GetByLink(ctx context.Context, linkID uuid.UUID) (domain.UsageCounters, error) {
	row := r.q.QueryRow(ctx, `SELECT id, shared_link_id, request_count, bytes_transferred, violation_count, updated_at FROM usage_counters WHERE shared_link_id=$1`, linkID)
	var c domain.UsageCounters
	err := row.Scan(&c.ID, &c.SharedLinkID, &c.RequestCount, &c.BytesTransferred, &c.ViolationCount, &c.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.UsageCounters{}, err
		}
		return domain.UsageCounters{}, fmt.Errorf("pgx: scan usage_counters: %w", err)
	}
	return c, nil
}

// Upsert relies on usage_counters.shared_link_id being UNIQUE (migration
// 00004), so ON CONFLICT targets that column directly.
func (r *UsageCounterRepo) Upsert(ctx context.Context, c domain.UsageCounters) error {
	_, err := r.q.Exec(ctx, `
		INSERT INTO usage_counters (id, shared_link_id, request_count, bytes_transferred, violation_count, updated_at)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, now())
		ON CONFLICT (shared_link_id) DO UPDATE SET
			request_count = EXCLUDED.request_count,
			bytes_transferred = EXCLUDED.bytes_transferred,
			violation_count = EXCLUDED.violation_count,
			updated_at = now()`,
		c.SharedLinkID, c.RequestCount, c.BytesTransferred, c.ViolationCount)
	return err
}
