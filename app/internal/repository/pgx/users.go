package pgx

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"sessionproxy/internal/domain"
)

// UserRepo implements domain.UserRepository.
type UserRepo struct{ q querier }

func NewUserRepo(q querier) *UserRepo { return &UserRepo{q: q} }

func (r *UserRepo) Create(ctx context.Context, u domain.User) (domain.User, error) {
	row := r.q.QueryRow(ctx, `
		INSERT INTO users (id, email, password_hash, display_name)
		VALUES (gen_random_uuid(), $1, $2, $3)
		RETURNING id, email, password_hash, display_name, created_at, updated_at`,
		u.Email, u.PasswordHash, u.DisplayName)
	return scanUser(row)
}

func (r *UserRepo) GetByID(ctx context.Context, id uuid.UUID) (domain.User, error) {
	row := r.q.QueryRow(ctx, `SELECT id, email, password_hash, display_name, created_at, updated_at FROM users WHERE id=$1`, id)
	return scanUser(row)
}

func (r *UserRepo) GetByEmail(ctx context.Context, email string) (domain.User, error) {
	row := r.q.QueryRow(ctx, `SELECT id, email, password_hash, display_name, created_at, updated_at FROM users WHERE email=$1`, email)
	return scanUser(row)
}

func (r *UserRepo) List(ctx context.Context, limit, offset int) ([]domain.User, error) {
	rows, err := r.q.Query(ctx, `SELECT id, email, password_hash, display_name, created_at, updated_at FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("pgx: list users: %w", err)
	}
	defer rows.Close()
	var out []domain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (r *UserRepo) Update(ctx context.Context, u domain.User) (domain.User, error) {
	row := r.q.QueryRow(ctx, `
		UPDATE users SET email=$2, display_name=$3, updated_at=now()
		WHERE id=$1
		RETURNING id, email, password_hash, display_name, created_at, updated_at`,
		u.ID, u.Email, u.DisplayName)
	return scanUser(row)
}

func (r *UserRepo) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.q.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
	return err
}

func scanUser(row scanner) (domain.User, error) {
	var u domain.User
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return domain.User{}, fmt.Errorf("pgx: scan user: %w", err)
	}
	return u, nil
}

// DeviceRepo implements domain.DeviceRepository.
type DeviceRepo struct{ q querier }

func NewDeviceRepo(q querier) *DeviceRepo { return &DeviceRepo{q: q} }

func (r *DeviceRepo) Create(ctx context.Context, d domain.Device) (domain.Device, error) {
	row := r.q.QueryRow(ctx, `
		INSERT INTO devices (id, user_id, name, fingerprint)
		VALUES (gen_random_uuid(), $1, $2, $3)
		RETURNING id, user_id, name, fingerprint, last_seen_at, created_at`,
		d.UserID, d.Name, d.Fingerprint)
	return scanDevice(row)
}

func (r *DeviceRepo) GetByID(ctx context.Context, id uuid.UUID) (domain.Device, error) {
	row := r.q.QueryRow(ctx, `SELECT id, user_id, name, fingerprint, last_seen_at, created_at FROM devices WHERE id=$1`, id)
	return scanDevice(row)
}

func (r *DeviceRepo) ListByUser(ctx context.Context, userID uuid.UUID) ([]domain.Device, error) {
	rows, err := r.q.Query(ctx, `SELECT id, user_id, name, fingerprint, last_seen_at, created_at FROM devices WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("pgx: list devices: %w", err)
	}
	defer rows.Close()
	var out []domain.Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (r *DeviceRepo) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.q.Exec(ctx, `DELETE FROM devices WHERE id=$1`, id)
	return err
}

func scanDevice(row scanner) (domain.Device, error) {
	var d domain.Device
	err := row.Scan(&d.ID, &d.UserID, &d.Name, &d.Fingerprint, &d.LastSeenAt, &d.CreatedAt)
	if err != nil {
		return domain.Device{}, fmt.Errorf("pgx: scan device: %w", err)
	}
	return d, nil
}

// APIKeyRepo implements domain.APIKeyRepository. Callers pass an already
// hashed key (sha256/bcrypt happens in the service layer, same separation of
// concerns as credential encryption).
type APIKeyRepo struct{ q querier }

func NewAPIKeyRepo(q querier) *APIKeyRepo { return &APIKeyRepo{q: q} }

func (r *APIKeyRepo) Create(ctx context.Context, k domain.APIKey) (domain.APIKey, error) {
	row := r.q.QueryRow(ctx, `
		INSERT INTO api_keys (id, user_id, device_id, key_hash, label, expires_at)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5)
		RETURNING id, user_id, device_id, key_hash, label, revoked_at, expires_at, created_at`,
		k.UserID, k.DeviceID, k.KeyHash, k.Label, k.ExpiresAt)
	return scanAPIKey(row)
}

func (r *APIKeyRepo) GetByHash(ctx context.Context, keyHash string) (domain.APIKey, error) {
	row := r.q.QueryRow(ctx, `SELECT id, user_id, device_id, key_hash, label, revoked_at, expires_at, created_at FROM api_keys WHERE key_hash=$1`, keyHash)
	return scanAPIKey(row)
}

func (r *APIKeyRepo) ListByUser(ctx context.Context, userID uuid.UUID) ([]domain.APIKey, error) {
	rows, err := r.q.Query(ctx, `SELECT id, user_id, device_id, key_hash, label, revoked_at, expires_at, created_at FROM api_keys WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("pgx: list api_keys: %w", err)
	}
	defer rows.Close()
	var out []domain.APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (r *APIKeyRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	_, err := r.q.Exec(ctx, `UPDATE api_keys SET revoked_at=now() WHERE id=$1`, id)
	return err
}

func scanAPIKey(row scanner) (domain.APIKey, error) {
	var k domain.APIKey
	err := row.Scan(&k.ID, &k.UserID, &k.DeviceID, &k.KeyHash, &k.Label, &k.RevokedAt, &k.ExpiresAt, &k.CreatedAt)
	if err != nil {
		return domain.APIKey{}, fmt.Errorf("pgx: scan api_key: %w", err)
	}
	return k, nil
}
