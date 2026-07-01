// Package pgx implements the domain repository interfaces on top of
// jackc/pgx/v5. This is the only package in the app that runs SQL.
//
// The application connects to whichever entry point migrate-ha already uses
// in HA mode (haproxy:5432) or migrate uses directly (postgres:5432) - see
// docker-compose.yml. It never runs migrations itself; migrate/migrate-ha
// remain the sole owners of schema changes.
package pgx

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPool opens a pgx connection pool against DATABASE_URL.
func NewPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("pgx: creating pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pgx: ping: %w", err)
	}
	return pool, nil
}
