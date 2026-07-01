package pgx

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"sessionproxy/internal/domain"
)

// TargetSiteRepo implements domain.TargetSiteRepository.
type TargetSiteRepo struct{ q querier }

func NewTargetSiteRepo(q querier) *TargetSiteRepo { return &TargetSiteRepo{q: q} }

func (r *TargetSiteRepo) Create(ctx context.Context, s domain.TargetSite) (domain.TargetSite, error) {
	row := r.q.QueryRow(ctx, `
		INSERT INTO target_sites (id, base_domain, name, base_url)
		VALUES (gen_random_uuid(), $1, $2, $3)
		RETURNING id, base_domain, name, base_url, created_at`,
		s.BaseDomain, s.Name, s.BaseURL)
	return scanTargetSite(row)
}

func (r *TargetSiteRepo) GetByID(ctx context.Context, id uuid.UUID) (domain.TargetSite, error) {
	row := r.q.QueryRow(ctx, `SELECT id, base_domain, name, base_url, created_at FROM target_sites WHERE id=$1`, id)
	return scanTargetSite(row)
}

// GetOrCreateByDomain looks up a target_sites row by base_domain and creates
// one if none exists yet. There is no unique constraint on base_domain in
// the schema (migrations are not modified by the app), so this is a
// select-then-insert rather than ON CONFLICT; a rare benign race just
// produces two rows for the same domain, which is a cosmetic duplicate, not
// a correctness issue (each shared_link still points at one specific row).
func (r *TargetSiteRepo) GetOrCreateByDomain(ctx context.Context, domainName, name, baseURL string) (domain.TargetSite, error) {
	row := r.q.QueryRow(ctx, `SELECT id, base_domain, name, base_url, created_at FROM target_sites WHERE base_domain=$1 LIMIT 1`, domainName)
	site, err := scanTargetSite(row)
	if err == nil {
		return site, nil
	}
	return r.Create(ctx, domain.TargetSite{BaseDomain: domainName, Name: name, BaseURL: baseURL})
}

func (r *TargetSiteRepo) List(ctx context.Context) ([]domain.TargetSite, error) {
	rows, err := r.q.Query(ctx, `SELECT id, base_domain, name, base_url, created_at FROM target_sites ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("pgx: list target_sites: %w", err)
	}
	defer rows.Close()
	var out []domain.TargetSite
	for rows.Next() {
		s, err := scanTargetSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func scanTargetSite(row scanner) (domain.TargetSite, error) {
	var s domain.TargetSite
	err := row.Scan(&s.ID, &s.BaseDomain, &s.Name, &s.BaseURL, &s.CreatedAt)
	if err != nil {
		return domain.TargetSite{}, fmt.Errorf("pgx: scan target_site: %w", err)
	}
	return s, nil
}

// OriginalSessionRepo implements domain.OriginalSessionRepository.
type OriginalSessionRepo struct{ q querier }

func NewOriginalSessionRepo(q querier) *OriginalSessionRepo { return &OriginalSessionRepo{q: q} }

func (r *OriginalSessionRepo) Create(ctx context.Context, s domain.OriginalSession) (domain.OriginalSession, error) {
	row := r.q.QueryRow(ctx, `
		INSERT INTO original_sessions (id, user_id, target_site_id, device_id, status, label, expires_at)
		VALUES (gen_random_uuid(), $1, $2, $3, COALESCE($4, 'active'), $5, $6)
		RETURNING id, user_id, target_site_id, device_id, status, label, imported_at, expires_at`,
		s.UserID, s.TargetSiteID, s.DeviceID, nullIfEmpty(s.Status), s.Label, s.ExpiresAt)
	return scanOriginalSession(row)
}

func (r *OriginalSessionRepo) GetByID(ctx context.Context, id uuid.UUID) (domain.OriginalSession, error) {
	row := r.q.QueryRow(ctx, `SELECT id, user_id, target_site_id, device_id, status, label, imported_at, expires_at FROM original_sessions WHERE id=$1`, id)
	return scanOriginalSession(row)
}

func (r *OriginalSessionRepo) ListByUser(ctx context.Context, userID uuid.UUID) ([]domain.OriginalSession, error) {
	rows, err := r.q.Query(ctx, `SELECT id, user_id, target_site_id, device_id, status, label, imported_at, expires_at FROM original_sessions WHERE user_id=$1 ORDER BY imported_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("pgx: list original_sessions: %w", err)
	}
	defer rows.Close()
	var out []domain.OriginalSession
	for rows.Next() {
		s, err := scanOriginalSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *OriginalSessionRepo) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	_, err := r.q.Exec(ctx, `UPDATE original_sessions SET status=$2 WHERE id=$1`, id, status)
	return err
}

func scanOriginalSession(row scanner) (domain.OriginalSession, error) {
	var s domain.OriginalSession
	err := row.Scan(&s.ID, &s.UserID, &s.TargetSiteID, &s.DeviceID, &s.Status, &s.Label, &s.ImportedAt, &s.ExpiresAt)
	if err != nil {
		return domain.OriginalSession{}, fmt.Errorf("pgx: scan original_session: %w", err)
	}
	return s, nil
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// SessionCookieRepo implements domain.SessionCookieRepository. It never
// decrypts anything - value_encrypted is written and read as opaque text,
// exactly as the crypto package produced it.
type SessionCookieRepo struct{ q querier }

func NewSessionCookieRepo(q querier) *SessionCookieRepo { return &SessionCookieRepo{q: q} }

func (r *SessionCookieRepo) CreateBatch(ctx context.Context, cookies []domain.SessionCookie) error {
	for _, c := range cookies {
		_, err := r.q.Exec(ctx, `
			INSERT INTO session_cookies (id, original_session_id, name, value_encrypted, domain, path, secure, http_only, same_site, expires_at)
			VALUES (gen_random_uuid(), $1, $2, $3, $4, COALESCE($5, '/'), $6, $7, $8, $9)`,
			c.OriginalSessionID, c.Name, c.ValueEncrypted, c.Domain, nullIfEmptyPath(c.Path), c.Secure, c.HTTPOnly, c.SameSite, c.ExpiresAt)
		if err != nil {
			return fmt.Errorf("pgx: insert session_cookie %q: %w", c.Name, err)
		}
	}
	return nil
}

func nullIfEmptyPath(p string) *string {
	if p == "" {
		return nil
	}
	return &p
}

func (r *SessionCookieRepo) ListBySession(ctx context.Context, originalSessionID uuid.UUID) ([]domain.SessionCookie, error) {
	rows, err := r.q.Query(ctx, `
		SELECT id, original_session_id, name, value_encrypted, domain, path, secure, http_only, same_site, expires_at, created_at
		FROM session_cookies WHERE original_session_id=$1`, originalSessionID)
	if err != nil {
		return nil, fmt.Errorf("pgx: list session_cookies: %w", err)
	}
	defer rows.Close()
	var out []domain.SessionCookie
	for rows.Next() {
		var c domain.SessionCookie
		if err := rows.Scan(&c.ID, &c.OriginalSessionID, &c.Name, &c.ValueEncrypted, &c.Domain, &c.Path, &c.Secure, &c.HTTPOnly, &c.SameSite, &c.ExpiresAt, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("pgx: scan session_cookie: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SessionTokenRepo implements domain.SessionTokenRepository.
type SessionTokenRepo struct{ q querier }

func NewSessionTokenRepo(q querier) *SessionTokenRepo { return &SessionTokenRepo{q: q} }

func (r *SessionTokenRepo) CreateBatch(ctx context.Context, tokens []domain.SessionToken) error {
	for _, t := range tokens {
		_, err := r.q.Exec(ctx, `
			INSERT INTO session_tokens (id, original_session_id, token_type, header_name, value_encrypted, expires_at)
			VALUES (gen_random_uuid(), $1, $2, $3, $4, $5)`,
			t.OriginalSessionID, t.TokenType, t.HeaderName, t.ValueEncrypted, t.ExpiresAt)
		if err != nil {
			return fmt.Errorf("pgx: insert session_token: %w", err)
		}
	}
	return nil
}

func (r *SessionTokenRepo) ListBySession(ctx context.Context, originalSessionID uuid.UUID) ([]domain.SessionToken, error) {
	rows, err := r.q.Query(ctx, `
		SELECT id, original_session_id, token_type, header_name, value_encrypted, expires_at, created_at
		FROM session_tokens WHERE original_session_id=$1`, originalSessionID)
	if err != nil {
		return nil, fmt.Errorf("pgx: list session_tokens: %w", err)
	}
	defer rows.Close()
	var out []domain.SessionToken
	for rows.Next() {
		var t domain.SessionToken
		if err := rows.Scan(&t.ID, &t.OriginalSessionID, &t.TokenType, &t.HeaderName, &t.ValueEncrypted, &t.ExpiresAt, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("pgx: scan session_token: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
