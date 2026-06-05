package storage

import (
	"context"
	"database/sql"
)

// SQLDBAdapter wraps *sql.DB to satisfy the DBExecutor interface.
// Use NewSQLAdapter to create one from an open *sql.DB.
type SQLDBAdapter struct {
	db *sql.DB
}

// NewSQLAdapter wraps a *sql.DB as a DBExecutor.
func NewSQLAdapter(db *sql.DB) *SQLDBAdapter {
	return &SQLDBAdapter{db: db}
}

// QueryRowContext delegates to the underlying *sql.DB.
// The returned *sql.Row satisfies RowScanner.
func (a *SQLDBAdapter) QueryRowContext(ctx context.Context, query string, args ...interface{}) RowScanner {
	return a.db.QueryRowContext(ctx, query, args...)
}

// ExecContext delegates to the underlying *sql.DB.
// The returned sql.Result satisfies Result.
func (a *SQLDBAdapter) ExecContext(ctx context.Context, query string, args ...interface{}) (Result, error) {
	return a.db.ExecContext(ctx, query, args...)
}

// QueryContext delegates to the underlying *sql.DB.
// The returned *sql.Rows satisfies Rows.
func (a *SQLDBAdapter) QueryContext(ctx context.Context, query string, args ...interface{}) (Rows, error) {
	return a.db.QueryContext(ctx, query, args...)
}

// DB returns the underlying *sql.DB for operations that need it directly (e.g. migrations).
func (a *SQLDBAdapter) DB() *sql.DB {
	return a.db
}
