package pgx

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"sessionproxy/internal/domain"
)

// SharedLinkRepo implements domain.SharedLinkRepository.
type SharedLinkRepo struct{ q querier }

func NewSharedLinkRepo(q querier) *SharedLinkRepo { return &SharedLinkRepo{q: q} }

func (r *SharedLinkRepo) Create(ctx context.Context, l domain.SharedLink) (domain.SharedLink, error) {
	row := r.q.QueryRow(ctx, `
		INSERT INTO shared_links (id, original_session_id, token, status, label, expires_at)
		VALUES (gen_random_uuid(), $1, $2, COALESCE($3, 'active'), $4, $5)
		RETURNING id, original_session_id, token, status, label, created_at, expires_at`,
		l.OriginalSessionID, l.Token, nullIfEmpty(l.Status), l.Label, l.ExpiresAt)
	return scanSharedLink(row)
}

func (r *SharedLinkRepo) GetByID(ctx context.Context, id uuid.UUID) (domain.SharedLink, error) {
	row := r.q.QueryRow(ctx, `SELECT id, original_session_id, token, status, label, created_at, expires_at FROM shared_links WHERE id=$1`, id)
	return scanSharedLink(row)
}

// GetByToken resolves the guest-facing capability URL. It is the first
// thing the data plane does for every proxied request, joining through to
// the owning session and target site in one round trip.
func (r *SharedLinkRepo) GetByToken(ctx context.Context, token string) (domain.LinkWithSession, error) {
	row := r.q.QueryRow(ctx, `
		SELECT
			sl.id, sl.original_session_id, sl.token, sl.status, sl.label, sl.created_at, sl.expires_at,
			os.id, os.user_id, os.target_site_id, os.device_id, os.status, os.label, os.imported_at, os.expires_at,
			ts.id, ts.base_domain, ts.name, ts.base_url, ts.created_at
		FROM shared_links sl
		JOIN original_sessions os ON os.id = sl.original_session_id
		JOIN target_sites ts ON ts.id = os.target_site_id
		WHERE sl.token = $1`, token)

	var out domain.LinkWithSession
	err := row.Scan(
		&out.Link.ID, &out.Link.OriginalSessionID, &out.Link.Token, &out.Link.Status, &out.Link.Label, &out.Link.CreatedAt, &out.Link.ExpiresAt,
		&out.OriginalSession.ID, &out.OriginalSession.UserID, &out.OriginalSession.TargetSiteID, &out.OriginalSession.DeviceID, &out.OriginalSession.Status, &out.OriginalSession.Label, &out.OriginalSession.ImportedAt, &out.OriginalSession.ExpiresAt,
		&out.TargetSite.ID, &out.TargetSite.BaseDomain, &out.TargetSite.Name, &out.TargetSite.BaseURL, &out.TargetSite.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.LinkWithSession{}, err
		}
		return domain.LinkWithSession{}, fmt.Errorf("pgx: get link by token: %w", err)
	}
	out.OwnerUserID = out.OriginalSession.UserID
	return out, nil
}

func (r *SharedLinkRepo) ListByUser(ctx context.Context, userID uuid.UUID, status string) ([]domain.SharedLink, error) {
	rows, err := r.q.Query(ctx, `
		SELECT sl.id, sl.original_session_id, sl.token, sl.status, sl.label, sl.created_at, sl.expires_at
		FROM shared_links sl
		JOIN original_sessions os ON os.id = sl.original_session_id
		WHERE os.user_id = $1 AND ($2 = '' OR sl.status = $2)
		ORDER BY sl.created_at DESC`, userID, status)
	if err != nil {
		return nil, fmt.Errorf("pgx: list shared_links: %w", err)
	}
	defer rows.Close()
	var out []domain.SharedLink
	for rows.Next() {
		l, err := scanSharedLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (r *SharedLinkRepo) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	_, err := r.q.Exec(ctx, `UPDATE shared_links SET status=$2 WHERE id=$1`, id, status)
	return err
}

// OwnerUserID performs the join the schema deliberately requires:
// shared_links has no user_id column, so ownership always goes through
// original_sessions.
func (r *SharedLinkRepo) OwnerUserID(ctx context.Context, linkID uuid.UUID) (uuid.UUID, error) {
	row := r.q.QueryRow(ctx, `
		SELECT os.user_id FROM shared_links sl
		JOIN original_sessions os ON os.id = sl.original_session_id
		WHERE sl.id = $1`, linkID)
	var userID uuid.UUID
	if err := row.Scan(&userID); err != nil {
		return uuid.Nil, fmt.Errorf("pgx: owner_user_id: %w", err)
	}
	return userID, nil
}

func scanSharedLink(row scanner) (domain.SharedLink, error) {
	var l domain.SharedLink
	err := row.Scan(&l.ID, &l.OriginalSessionID, &l.Token, &l.Status, &l.Label, &l.CreatedAt, &l.ExpiresAt)
	if err != nil {
		return domain.SharedLink{}, fmt.Errorf("pgx: scan shared_link: %w", err)
	}
	return l, nil
}

// AccessPolicyRepo implements domain.AccessPolicyRepository.
type AccessPolicyRepo struct{ q querier }

func NewAccessPolicyRepo(q querier) *AccessPolicyRepo { return &AccessPolicyRepo{q: q} }

func (r *AccessPolicyRepo) Create(ctx context.Context, p domain.AccessPolicy) (domain.AccessPolicy, error) {
	row := r.q.QueryRow(ctx, `
		INSERT INTO access_policies (id, user_id, name, max_requests, max_bytes_transferred, max_ttl_seconds, max_violation_count)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6)
		RETURNING id, user_id, name, max_requests, max_bytes_transferred, max_ttl_seconds, max_violation_count, created_at`,
		p.UserID, p.Name, p.MaxRequests, p.MaxBytesTransferred, p.MaxTTLSeconds, p.MaxViolationCount)
	return scanAccessPolicy(row)
}

func (r *AccessPolicyRepo) GetByID(ctx context.Context, id uuid.UUID) (domain.AccessPolicy, error) {
	row := r.q.QueryRow(ctx, `SELECT id, user_id, name, max_requests, max_bytes_transferred, max_ttl_seconds, max_violation_count, created_at FROM access_policies WHERE id=$1`, id)
	return scanAccessPolicy(row)
}

func (r *AccessPolicyRepo) ListByUser(ctx context.Context, userID uuid.UUID) ([]domain.AccessPolicy, error) {
	rows, err := r.q.Query(ctx, `SELECT id, user_id, name, max_requests, max_bytes_transferred, max_ttl_seconds, max_violation_count, created_at FROM access_policies WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("pgx: list access_policies: %w", err)
	}
	defer rows.Close()
	var out []domain.AccessPolicy
	for rows.Next() {
		p, err := scanAccessPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r *AccessPolicyRepo) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.q.Exec(ctx, `DELETE FROM access_policies WHERE id=$1`, id)
	return err
}

func (r *AccessPolicyRepo) AttachToLink(ctx context.Context, linkID, policyID uuid.UUID) error {
	_, err := r.q.Exec(ctx, `INSERT INTO link_policies (link_id, policy_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, linkID, policyID)
	return err
}

// ListForLink returns every access_policy attached to a shared_link via the
// link_policies M:N table - the input set for most-restrictive-wins
// resolution in service/policy_resolver.go.
func (r *AccessPolicyRepo) ListForLink(ctx context.Context, linkID uuid.UUID) ([]domain.AccessPolicy, error) {
	rows, err := r.q.Query(ctx, `
		SELECT ap.id, ap.user_id, ap.name, ap.max_requests, ap.max_bytes_transferred, ap.max_ttl_seconds, ap.max_violation_count, ap.created_at
		FROM access_policies ap
		JOIN link_policies lp ON lp.policy_id = ap.id
		WHERE lp.link_id = $1`, linkID)
	if err != nil {
		return nil, fmt.Errorf("pgx: list policies for link: %w", err)
	}
	defer rows.Close()
	var out []domain.AccessPolicy
	for rows.Next() {
		p, err := scanAccessPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func scanAccessPolicy(row scanner) (domain.AccessPolicy, error) {
	var p domain.AccessPolicy
	err := row.Scan(&p.ID, &p.UserID, &p.Name, &p.MaxRequests, &p.MaxBytesTransferred, &p.MaxTTLSeconds, &p.MaxViolationCount, &p.CreatedAt)
	if err != nil {
		return domain.AccessPolicy{}, fmt.Errorf("pgx: scan access_policy: %w", err)
	}
	return p, nil
}

// BlacklistRepo implements domain.BlacklistRepository.
type BlacklistRepo struct{ q querier }

func NewBlacklistRepo(q querier) *BlacklistRepo { return &BlacklistRepo{q: q} }

func (r *BlacklistRepo) Create(ctx context.Context, e domain.BlacklistedEndpoint) (domain.BlacklistedEndpoint, error) {
	row := r.q.QueryRow(ctx, `
		INSERT INTO blacklisted_endpoints (id, user_id, pattern, pattern_type, description)
		VALUES (gen_random_uuid(), $1, $2, COALESCE($3, 'prefix'), $4)
		RETURNING id, user_id, pattern, pattern_type, description, created_at`,
		e.UserID, e.Pattern, nullIfEmpty(e.PatternType), e.Description)
	return scanBlacklistedEndpoint(row)
}

func (r *BlacklistRepo) GetByID(ctx context.Context, id uuid.UUID) (domain.BlacklistedEndpoint, error) {
	row := r.q.QueryRow(ctx, `SELECT id, user_id, pattern, pattern_type, description, created_at FROM blacklisted_endpoints WHERE id=$1`, id)
	e, err := scanBlacklistedEndpoint(row)
	if err != nil {
		return domain.BlacklistedEndpoint{}, err
	}
	methods, err := r.blockedMethods(ctx, e.ID)
	if err != nil {
		return domain.BlacklistedEndpoint{}, err
	}
	e.BlockedMethods = methods
	return e, nil
}

func (r *BlacklistRepo) ListByUser(ctx context.Context, userID uuid.UUID) ([]domain.BlacklistedEndpoint, error) {
	rows, err := r.q.Query(ctx, `SELECT id, user_id, pattern, pattern_type, description, created_at FROM blacklisted_endpoints WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("pgx: list blacklisted_endpoints: %w", err)
	}
	defer rows.Close()
	var out []domain.BlacklistedEndpoint
	for rows.Next() {
		e, err := scanBlacklistedEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		methods, err := r.blockedMethods(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].BlockedMethods = methods
	}
	return out, nil
}

func (r *BlacklistRepo) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.q.Exec(ctx, `DELETE FROM blacklisted_endpoints WHERE id=$1`, id)
	return err
}

func (r *BlacklistRepo) AttachToSite(ctx context.Context, siteID, endpointID uuid.UUID) error {
	_, err := r.q.Exec(ctx, `INSERT INTO site_endpoint_rules (target_site_id, endpoint_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, siteID, endpointID)
	return err
}

func (r *BlacklistRepo) AttachToLink(ctx context.Context, linkID, endpointID uuid.UUID) error {
	_, err := r.q.Exec(ctx, `INSERT INTO link_endpoint_rules (link_id, endpoint_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, linkID, endpointID)
	return err
}

func (r *BlacklistRepo) SetBlockedMethods(ctx context.Context, endpointID uuid.UUID, methods []string) error {
	if _, err := r.q.Exec(ctx, `DELETE FROM endpoint_blocked_methods WHERE endpoint_id=$1`, endpointID); err != nil {
		return fmt.Errorf("pgx: clear endpoint_blocked_methods: %w", err)
	}
	for _, m := range methods {
		if _, err := r.q.Exec(ctx, `INSERT INTO endpoint_blocked_methods (endpoint_id, http_method) VALUES ($1, $2)`, endpointID, m); err != nil {
			return fmt.Errorf("pgx: insert endpoint_blocked_methods: %w", err)
		}
	}
	return nil
}

// RulesForLink returns the union of site-level rules (via the link's
// target_site) and link-level rules, each with its blocked HTTP methods
// populated - exactly the input the data plane's blacklist check needs.
func (r *BlacklistRepo) RulesForLink(ctx context.Context, linkID, targetSiteID uuid.UUID) ([]domain.BlacklistedEndpoint, error) {
	rows, err := r.q.Query(ctx, `
		SELECT be.id, be.user_id, be.pattern, be.pattern_type, be.description, be.created_at
		FROM blacklisted_endpoints be
		JOIN site_endpoint_rules ser ON ser.endpoint_id = be.id
		WHERE ser.target_site_id = $1
		UNION
		SELECT be.id, be.user_id, be.pattern, be.pattern_type, be.description, be.created_at
		FROM blacklisted_endpoints be
		JOIN link_endpoint_rules ler ON ler.endpoint_id = be.id
		WHERE ler.link_id = $2`, targetSiteID, linkID)
	if err != nil {
		return nil, fmt.Errorf("pgx: rules for link: %w", err)
	}
	defer rows.Close()
	var out []domain.BlacklistedEndpoint
	for rows.Next() {
		e, err := scanBlacklistedEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		methods, err := r.blockedMethods(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].BlockedMethods = methods
	}
	return out, nil
}

func (r *BlacklistRepo) blockedMethods(ctx context.Context, endpointID uuid.UUID) ([]string, error) {
	rows, err := r.q.Query(ctx, `SELECT http_method FROM endpoint_blocked_methods WHERE endpoint_id=$1`, endpointID)
	if err != nil {
		return nil, fmt.Errorf("pgx: blocked_methods: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func scanBlacklistedEndpoint(row scanner) (domain.BlacklistedEndpoint, error) {
	var e domain.BlacklistedEndpoint
	err := row.Scan(&e.ID, &e.UserID, &e.Pattern, &e.PatternType, &e.Description, &e.CreatedAt)
	if err != nil {
		return domain.BlacklistedEndpoint{}, fmt.Errorf("pgx: scan blacklisted_endpoint: %w", err)
	}
	return e, nil
}
