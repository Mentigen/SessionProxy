package pgx

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// querier is satisfied by both *pgxpool.Pool and pgx.Tx. Repositories accept
// it instead of a concrete pool so link_service can run multi-table writes
// (shared_links + link_policies + link_endpoint_rules) inside one
// transaction by handing the repositories a pgx.Tx instead of the pool.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// scanner is satisfied by both pgx.Row and pgx.Rows: both expose
// Scan(dest ...any) error with an identical signature, so a single scan
// helper per domain type can take either one.
type scanner interface {
	Scan(dest ...any) error
}

// WithTx runs fn inside a transaction, committing on success and rolling
// back on any error or panic.
func WithTx(ctx context.Context, pool *pgxpool.Pool, fn func(tx pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(ctx)
			panic(p)
		}
	}()
	if err := fn(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}
