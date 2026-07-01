package pgx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"sessionproxy/internal/domain"
)

// ProxyAccessLogRepo implements domain.ProxyAccessLogRepository. This table
// is the one Debezium replicates (REPLICA IDENTITY FULL, publication
// pub_proxy_logs, migration 00008) - every row inserted here eventually
// shows up in ClickHouse/Metabase through the existing CDC pipeline.
type ProxyAccessLogRepo struct{ q querier }

func NewProxyAccessLogRepo(q querier) *ProxyAccessLogRepo { return &ProxyAccessLogRepo{q: q} }

func (r *ProxyAccessLogRepo) Insert(ctx context.Context, l domain.ProxyAccessLog) error {
	_, err := r.q.Exec(ctx, `
		INSERT INTO proxy_access_logs (guest_session_id, shared_link_id, target_url, http_method, response_status, bytes_transferred, response_time_ms, requested_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, now()))`,
		l.GuestSessionID, l.SharedLinkID, l.TargetURL, l.HTTPMethod, l.ResponseStatus, l.BytesTransferred, l.ResponseTimeMs, zeroTimeToNil(l))
	if err != nil {
		return fmt.Errorf("pgx: insert proxy_access_log: %w", err)
	}
	return nil
}

func zeroTimeToNil(l domain.ProxyAccessLog) any {
	if l.RequestedAt.IsZero() {
		return nil
	}
	return l.RequestedAt
}

// InsertBatch is used by the async log writer (internal/proxy/logwriter.go)
// to flush several accumulated requests in a single round trip via pgx.Batch.
func (r *ProxyAccessLogRepo) InsertBatch(ctx context.Context, logs []domain.ProxyAccessLog) error {
	if len(logs) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, l := range logs {
		batch.Queue(`
			INSERT INTO proxy_access_logs (guest_session_id, shared_link_id, target_url, http_method, response_status, bytes_transferred, response_time_ms, requested_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, now()))`,
			l.GuestSessionID, l.SharedLinkID, l.TargetURL, l.HTTPMethod, l.ResponseStatus, l.BytesTransferred, l.ResponseTimeMs, zeroTimeToNil(l))
	}
	br, ok := r.q.(batchQuerier)
	if !ok {
		// Fallback for a plain transaction that doesn't expose SendBatch:
		// insert one by one inside the same querier.
		for _, l := range logs {
			if err := r.Insert(ctx, l); err != nil {
				return err
			}
		}
		return nil
	}
	results := br.SendBatch(ctx, batch)
	defer func() { _ = results.Close() }()
	for range logs {
		if _, err := results.Exec(); err != nil {
			return fmt.Errorf("pgx: batch insert proxy_access_logs: %w", err)
		}
	}
	return nil
}

// batchQuerier is implemented by *pgxpool.Pool and pgx.Tx (SendBatch), used
// opportunistically by InsertBatch for a real multi-statement round trip.
type batchQuerier interface {
	SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults
}

func (r *ProxyAccessLogRepo) ListByLink(ctx context.Context, linkID uuid.UUID, limit int) ([]domain.ProxyAccessLog, error) {
	rows, err := r.q.Query(ctx, `
		SELECT id, guest_session_id, shared_link_id, target_url, http_method, response_status, bytes_transferred, response_time_ms, requested_at
		FROM proxy_access_logs WHERE shared_link_id=$1 ORDER BY requested_at DESC LIMIT $2`, linkID, limit)
	if err != nil {
		return nil, fmt.Errorf("pgx: list proxy_access_logs: %w", err)
	}
	defer rows.Close()
	var out []domain.ProxyAccessLog
	for rows.Next() {
		var l domain.ProxyAccessLog
		if err := rows.Scan(&l.ID, &l.GuestSessionID, &l.SharedLinkID, &l.TargetURL, &l.HTTPMethod, &l.ResponseStatus, &l.BytesTransferred, &l.ResponseTimeMs, &l.RequestedAt); err != nil {
			return nil, fmt.Errorf("pgx: scan proxy_access_log: %w", err)
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// LinkTerminationRepo implements domain.LinkTerminationRepository.
// revocation_reasons is a tiny fixed reference table seeded once by
// migration 00005 (5 rows); we resolve ReasonCode -> reason_id by joining
// rather than caching, since this is not a hot path.
type LinkTerminationRepo struct{ q querier }

func NewLinkTerminationRepo(q querier) *LinkTerminationRepo { return &LinkTerminationRepo{q: q} }

func (r *LinkTerminationRepo) Create(ctx context.Context, t domain.LinkTermination) error {
	_, err := r.q.Exec(ctx, `
		INSERT INTO link_terminations (id, shared_link_id, reason_id, terminated_by, notes)
		SELECT gen_random_uuid(), $1, rr.id, $3, $4
		FROM revocation_reasons rr WHERE rr.code = $2`,
		t.SharedLinkID, t.ReasonCode, t.TerminatedBy, t.Notes)
	if err != nil {
		return fmt.Errorf("pgx: insert link_termination: %w", err)
	}
	return nil
}

func (r *LinkTerminationRepo) ListReasons(ctx context.Context) ([]domain.RevocationReason, error) {
	rows, err := r.q.Query(ctx, `SELECT code, description FROM revocation_reasons ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("pgx: list revocation_reasons: %w", err)
	}
	defer rows.Close()
	var out []domain.RevocationReason
	for rows.Next() {
		var rr domain.RevocationReason
		if err := rows.Scan(&rr.Code, &rr.Description); err != nil {
			return nil, fmt.Errorf("pgx: scan revocation_reason: %w", err)
		}
		out = append(out, rr)
	}
	return out, rows.Err()
}

func (r *LinkTerminationRepo) GetByLink(ctx context.Context, linkID uuid.UUID) (*domain.LinkTermination, error) {
	row := r.q.QueryRow(ctx, `
		SELECT lt.id, lt.shared_link_id, rr.code, lt.terminated_by, lt.notes, lt.terminated_at
		FROM link_terminations lt
		JOIN revocation_reasons rr ON rr.id = lt.reason_id
		WHERE lt.shared_link_id = $1
		ORDER BY lt.terminated_at DESC LIMIT 1`, linkID)
	var t domain.LinkTermination
	err := row.Scan(&t.ID, &t.SharedLinkID, &t.ReasonCode, &t.TerminatedBy, &t.Notes, &t.TerminatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("pgx: scan link_termination: %w", err)
	}
	return &t, nil
}

// SecurityEventRepo implements domain.SecurityEventRepository.
type SecurityEventRepo struct{ q querier }

func NewSecurityEventRepo(q querier) *SecurityEventRepo { return &SecurityEventRepo{q: q} }

func (r *SecurityEventRepo) Create(ctx context.Context, e domain.SecurityEvent) error {
	var detailsJSON []byte
	if e.Details != nil {
		b, err := json.Marshal(e.Details)
		if err != nil {
			return fmt.Errorf("pgx: marshal security_event details: %w", err)
		}
		detailsJSON = b
	}
	_, err := r.q.Exec(ctx, `
		INSERT INTO security_events (guest_session_id, shared_link_id, event_type, target_url, http_method, details)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		e.GuestSessionID, e.SharedLinkID, e.EventType, e.TargetURL, e.HTTPMethod, detailsJSON)
	if err != nil {
		return fmt.Errorf("pgx: insert security_event: %w", err)
	}
	return nil
}

func (r *SecurityEventRepo) ListByLink(ctx context.Context, linkID uuid.UUID, limit int) ([]domain.SecurityEvent, error) {
	rows, err := r.q.Query(ctx, `
		SELECT id, guest_session_id, shared_link_id, event_type, target_url, http_method, details, occurred_at
		FROM security_events WHERE shared_link_id=$1 ORDER BY occurred_at DESC LIMIT $2`, linkID, limit)
	if err != nil {
		return nil, fmt.Errorf("pgx: list security_events: %w", err)
	}
	return scanSecurityEvents(rows)
}

func (r *SecurityEventRepo) ListRecent(ctx context.Context, limit int) ([]domain.SecurityEvent, error) {
	rows, err := r.q.Query(ctx, `
		SELECT id, guest_session_id, shared_link_id, event_type, target_url, http_method, details, occurred_at
		FROM security_events ORDER BY occurred_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("pgx: list recent security_events: %w", err)
	}
	return scanSecurityEvents(rows)
}

func scanSecurityEvents(rows pgx.Rows) ([]domain.SecurityEvent, error) {
	defer rows.Close()
	var out []domain.SecurityEvent
	for rows.Next() {
		var e domain.SecurityEvent
		var detailsJSON []byte
		if err := rows.Scan(&e.ID, &e.GuestSessionID, &e.SharedLinkID, &e.EventType, &e.TargetURL, &e.HTTPMethod, &detailsJSON, &e.OccurredAt); err != nil {
			return nil, fmt.Errorf("pgx: scan security_event: %w", err)
		}
		if len(detailsJSON) > 0 {
			if err := json.Unmarshal(detailsJSON, &e.Details); err != nil {
				return nil, fmt.Errorf("pgx: unmarshal security_event details: %w", err)
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// StatsRepo implements domain.StatsRepository, backed by mv_link_stats
// (migration 00007).
type StatsRepo struct{ q querier }

func NewStatsRepo(q querier) *StatsRepo { return &StatsRepo{q: q} }

func (r *StatsRepo) GetLinkStats(ctx context.Context, linkID uuid.UUID) (*domain.LinkStats, error) {
	row := r.q.QueryRow(ctx, `
		SELECT target_site_id, site_name, base_domain, shared_link_id, total_requests, total_bytes, avg_response_ms, first_request_at, last_request_at
		FROM mv_link_stats WHERE shared_link_id = $1`, linkID)
	var s domain.LinkStats
	err := row.Scan(&s.TargetSiteID, &s.SiteName, &s.BaseDomain, &s.SharedLinkID, &s.TotalRequests, &s.TotalBytes, &s.AvgResponseMs, &s.FirstRequestAt, &s.LastRequestAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("pgx: scan mv_link_stats: %w", err)
	}
	return &s, nil
}

// RefreshMaterializedView is called periodically (or after a termination)
// since mv_link_stats does not auto-refresh. CONCURRENTLY requires the
// unique index uix_mv_link_stats created in migration 00007, which already
// exists, so this never blocks reads of the view while it runs.
func (r *StatsRepo) RefreshMaterializedView(ctx context.Context) error {
	_, err := r.q.Exec(ctx, `REFRESH MATERIALIZED VIEW CONCURRENTLY mv_link_stats`)
	if err != nil {
		return fmt.Errorf("pgx: refresh mv_link_stats: %w", err)
	}
	return nil
}
