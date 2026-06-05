// Package storage provides the persistence layer for AgentAuth.
// PostgreSQL is used for durable storage of identities, policies, and audit logs.
// Redis is used as a fast revocation cache and token store.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// IdentityRecord is the persisted representation of an agent identity (no private key).
type IdentityRecord struct {
	ID             string            `db:"id"`
	SPIFFEID       string            `db:"spiffe_id"`
	TenantID       string            `db:"tenant_id"`
	DelegatorID    string            `db:"delegator_id"`
	DeclaredIntent string            `db:"declared_intent"`
	CertificatePEM string            `db:"certificate_pem"`
	IssuedAt       time.Time         `db:"issued_at"`
	ExpiresAt      time.Time         `db:"expires_at"`
	Labels         map[string]string `db:"labels"`
	Revoked        bool              `db:"revoked"`
	RevokedAt      *time.Time        `db:"revoked_at,omitempty"`
}

// TokenRecord is the persisted record of an issued access token.
type TokenRecord struct {
	JTI            string    `db:"jti"`
	AgentID        string    `db:"agent_id"`
	TenantID       string    `db:"tenant_id"`
	Resource       string    `db:"resource"`
	Scopes         []string  `db:"scopes"`
	DPoPThumbprint string    `db:"dpop_thumbprint"`
	IssuedAt       time.Time `db:"issued_at"`
	ExpiresAt      time.Time `db:"expires_at"`
	Revoked        bool      `db:"revoked"`
	RevokedAt      *time.Time `db:"revoked_at,omitempty"`
}

// IdentityStore is the interface for storing and retrieving agent identities.
type IdentityStore interface {
	StoreIdentity(ctx context.Context, record *IdentityRecord) error
	GetIdentity(ctx context.Context, agentID string) (*IdentityRecord, error)
	GetIdentityBySPIFFEID(ctx context.Context, spiffeID string) (*IdentityRecord, error)
	RevokeIdentity(ctx context.Context, agentID string) error
	ListIdentities(ctx context.Context, tenantID string, limit, offset int) ([]*IdentityRecord, error)
}

// TokenStore is the interface for storing and retrieving access tokens.
type TokenStore interface {
	StoreToken(ctx context.Context, record *TokenRecord) error
	GetToken(ctx context.Context, jti string) (*TokenRecord, error)
	RevokeToken(ctx context.Context, jti string) error
	RevokeAllForAgent(ctx context.Context, agentID string) error
}

// PostgresIdentityStore implements IdentityStore using PostgreSQL.
type PostgresIdentityStore struct {
	db DBExecutor
}

// DBExecutor abstracts database operations for testability.
type DBExecutor interface {
	QueryRowContext(ctx context.Context, query string, args ...interface{}) RowScanner
	ExecContext(ctx context.Context, query string, args ...interface{}) (Result, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (Rows, error)
}

// RowScanner abstracts sql.Row for testability.
type RowScanner interface {
	Scan(dest ...interface{}) error
}

// Result abstracts sql.Result for testability.
type Result interface {
	RowsAffected() (int64, error)
}

// Rows abstracts sql.Rows for testability.
type Rows interface {
	Next() bool
	Scan(dest ...interface{}) error
	Close() error
	Err() error
}

// NewPostgresIdentityStore creates a new PostgreSQL identity store.
func NewPostgresIdentityStore(db DBExecutor) *PostgresIdentityStore {
	return &PostgresIdentityStore{db: db}
}

// StoreIdentity persists a new agent identity record.
func (s *PostgresIdentityStore) StoreIdentity(ctx context.Context, record *IdentityRecord) error {
	query := `
		INSERT INTO agent_identities (
			id, spiffe_id, tenant_id, delegator_id, declared_intent,
			certificate_pem, issued_at, expires_at, labels, revoked
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (id) DO UPDATE SET
			certificate_pem = EXCLUDED.certificate_pem,
			expires_at = EXCLUDED.expires_at
	`
	_, err := s.db.ExecContext(ctx, query,
		record.ID,
		record.SPIFFEID,
		record.TenantID,
		record.DelegatorID,
		record.DeclaredIntent,
		record.CertificatePEM,
		record.IssuedAt,
		record.ExpiresAt,
		labelsToJSON(record.Labels),
		record.Revoked,
	)
	if err != nil {
		return fmt.Errorf("inserting identity record: %w", err)
	}
	return nil
}

// GetIdentity retrieves an identity record by agent ID.
func (s *PostgresIdentityStore) GetIdentity(ctx context.Context, agentID string) (*IdentityRecord, error) {
	query := `
		SELECT id, spiffe_id, tenant_id, delegator_id, declared_intent,
		       certificate_pem, issued_at, expires_at, labels, revoked, revoked_at
		FROM agent_identities
		WHERE id = $1
	`
	row := s.db.QueryRowContext(ctx, query, agentID)
	return scanIdentityRecord(row)
}

// GetIdentityBySPIFFEID retrieves an identity record by SPIFFE ID.
func (s *PostgresIdentityStore) GetIdentityBySPIFFEID(ctx context.Context, spiffeID string) (*IdentityRecord, error) {
	query := `
		SELECT id, spiffe_id, tenant_id, delegator_id, declared_intent,
		       certificate_pem, issued_at, expires_at, labels, revoked, revoked_at
		FROM agent_identities
		WHERE spiffe_id = $1
	`
	row := s.db.QueryRowContext(ctx, query, spiffeID)
	return scanIdentityRecord(row)
}

// RevokeIdentity marks an identity as revoked.
func (s *PostgresIdentityStore) RevokeIdentity(ctx context.Context, agentID string) error {
	query := `
		UPDATE agent_identities
		SET revoked = true, revoked_at = NOW()
		WHERE id = $1 AND revoked = false
	`
	result, err := s.db.ExecContext(ctx, query, agentID)
	if err != nil {
		return fmt.Errorf("revoking identity: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("identity %s not found or already revoked", agentID)
	}
	return nil
}

// ListIdentities returns a paginated list of identities for a tenant.
func (s *PostgresIdentityStore) ListIdentities(ctx context.Context, tenantID string, limit, offset int) ([]*IdentityRecord, error) {
	query := `
		SELECT id, spiffe_id, tenant_id, delegator_id, declared_intent,
		       certificate_pem, issued_at, expires_at, labels, revoked, revoked_at
		FROM agent_identities
		WHERE tenant_id = $1
		ORDER BY issued_at DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := s.db.QueryContext(ctx, query, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("listing identities: %w", err)
	}
	defer rows.Close()

	var records []*IdentityRecord
	for rows.Next() {
		record, err := scanIdentityRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning identity record: %w", err)
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

// scanIdentityRecord scans a row into an IdentityRecord.
func scanIdentityRecord(row RowScanner) (*IdentityRecord, error) {
	record := &IdentityRecord{}
	var labelsJSON string
	var revokedAt *time.Time

	err := row.Scan(
		&record.ID,
		&record.SPIFFEID,
		&record.TenantID,
		&record.DelegatorID,
		&record.DeclaredIntent,
		&record.CertificatePEM,
		&record.IssuedAt,
		&record.ExpiresAt,
		&labelsJSON,
		&record.Revoked,
		&revokedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scanning identity record: %w", err)
	}

	record.RevokedAt = revokedAt
	record.Labels = jsonToLabels(labelsJSON)
	return record, nil
}

// PostgresTokenStore implements TokenStore using PostgreSQL.
type PostgresTokenStore struct {
	db DBExecutor
}

// NewPostgresTokenStore creates a new PostgreSQL token store.
func NewPostgresTokenStore(db DBExecutor) *PostgresTokenStore {
	return &PostgresTokenStore{db: db}
}

// StoreToken persists a new token record.
func (s *PostgresTokenStore) StoreToken(ctx context.Context, record *TokenRecord) error {
	query := `
		INSERT INTO access_tokens (
			jti, agent_id, tenant_id, resource, scopes,
			dpop_thumbprint, issued_at, expires_at, revoked
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := s.db.ExecContext(ctx, query,
		record.JTI,
		record.AgentID,
		record.TenantID,
		record.Resource,
		scopesToJSON(record.Scopes),
		record.DPoPThumbprint,
		record.IssuedAt,
		record.ExpiresAt,
		record.Revoked,
	)
	if err != nil {
		return fmt.Errorf("inserting token record: %w", err)
	}
	return nil
}

// GetToken retrieves a token record by JTI.
func (s *PostgresTokenStore) GetToken(ctx context.Context, jti string) (*TokenRecord, error) {
	query := `
		SELECT jti, agent_id, tenant_id, resource, scopes,
		       dpop_thumbprint, issued_at, expires_at, revoked, revoked_at
		FROM access_tokens
		WHERE jti = $1
	`
	row := s.db.QueryRowContext(ctx, query, jti)
	record := &TokenRecord{}
	var scopesJSON string
	var revokedAt *time.Time

	err := row.Scan(
		&record.JTI,
		&record.AgentID,
		&record.TenantID,
		&record.Resource,
		&scopesJSON,
		&record.DPoPThumbprint,
		&record.IssuedAt,
		&record.ExpiresAt,
		&record.Revoked,
		&revokedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scanning token record: %w", err)
	}
	record.RevokedAt = revokedAt
	record.Scopes = jsonToScopes(scopesJSON)
	return record, nil
}

// RevokeToken marks a token as revoked by JTI.
func (s *PostgresTokenStore) RevokeToken(ctx context.Context, jti string) error {
	query := `UPDATE access_tokens SET revoked = true, revoked_at = NOW() WHERE jti = $1`
	_, err := s.db.ExecContext(ctx, query, jti)
	if err != nil {
		return fmt.Errorf("revoking token: %w", err)
	}
	return nil
}

// RevokeAllForAgent revokes all tokens associated with an agent.
func (s *PostgresTokenStore) RevokeAllForAgent(ctx context.Context, agentID string) error {
	query := `UPDATE access_tokens SET revoked = true, revoked_at = NOW() WHERE agent_id = $1 AND revoked = false`
	_, err := s.db.ExecContext(ctx, query, agentID)
	if err != nil {
		return fmt.Errorf("revoking agent tokens: %w", err)
	}
	return nil
}

// Helper functions for JSON serialization of labels and scopes.

func labelsToJSON(labels map[string]string) string {
	if len(labels) == 0 {
		return "{}"
	}
	data, err := json.Marshal(labels)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func jsonToLabels(s string) map[string]string {
	m := make(map[string]string)
	if s == "" || s == "{}" {
		return m
	}
	_ = json.Unmarshal([]byte(s), &m)
	return m
}

func scopesToJSON(scopes []string) string {
	if len(scopes) == 0 {
		return "[]"
	}
	data, err := json.Marshal(scopes)
	if err != nil {
		return "[]"
	}
	return string(data)
}

func jsonToScopes(s string) []string {
	if s == "" || s == "[]" {
		return nil
	}
	var scopes []string
	_ = json.Unmarshal([]byte(s), &scopes)
	return scopes
}

// Schema returns the PostgreSQL schema DDL for AgentAuth tables.
const Schema = `
-- AgentAuth PostgreSQL Schema

CREATE TABLE IF NOT EXISTS agent_identities (
    id              TEXT PRIMARY KEY,
    spiffe_id       TEXT NOT NULL UNIQUE,
    tenant_id       TEXT NOT NULL,
    delegator_id    TEXT,
    declared_intent TEXT NOT NULL,
    certificate_pem TEXT NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    labels          JSONB NOT NULL DEFAULT '{}',
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_identities_tenant ON agent_identities(tenant_id);
CREATE INDEX IF NOT EXISTS idx_identities_spiffe ON agent_identities(spiffe_id);
CREATE INDEX IF NOT EXISTS idx_identities_expires ON agent_identities(expires_at);

CREATE TABLE IF NOT EXISTS access_tokens (
    jti             TEXT PRIMARY KEY,
    agent_id        TEXT NOT NULL REFERENCES agent_identities(id),
    tenant_id       TEXT NOT NULL,
    resource        TEXT NOT NULL,
    scopes          JSONB NOT NULL DEFAULT '[]',
    dpop_thumbprint TEXT,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tokens_agent ON access_tokens(agent_id);
CREATE INDEX IF NOT EXISTS idx_tokens_expires ON access_tokens(expires_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id              TEXT PRIMARY KEY,
    seq             BIGSERIAL NOT NULL,
    prev_hash       TEXT NOT NULL,
    entry_hash      TEXT NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    agent_id        TEXT NOT NULL,
    action          TEXT NOT NULL,
    resource        TEXT NOT NULL,
    decision        TEXT NOT NULL,
    envelope_ref    TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

CREATE TABLE IF NOT EXISTS tenants (
    id                   TEXT PRIMARY KEY,
    name                 TEXT NOT NULL,
    max_delegation_depth INTEGER NOT NULL DEFAULT 4,
    allowed_tools        JSONB NOT NULL DEFAULT '[]',
    blocked_tools        JSONB NOT NULL DEFAULT '[]',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`
