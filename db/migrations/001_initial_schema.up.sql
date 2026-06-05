-- AgentAuth initial schema
-- Run with: migrate -path db/migrations -database $DATABASE_URL up
-- Or apply manually: psql $DATABASE_URL -f db/migrations/001_initial_schema.up.sql

BEGIN;

-- -----------------------------------------------------------------------
-- Tenants
-- -----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
    id                   TEXT PRIMARY KEY,
    name                 TEXT NOT NULL,
    max_delegation_depth INTEGER NOT NULL DEFAULT 4,
    allowed_tools        JSONB NOT NULL DEFAULT '[]',
    blocked_tools        JSONB NOT NULL DEFAULT '[]',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------
-- Agent Identities
-- -----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agent_identities (
    id              TEXT PRIMARY KEY,
    spiffe_id       TEXT NOT NULL UNIQUE,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    delegator_id    TEXT,
    declared_intent TEXT NOT NULL,
    certificate_pem TEXT NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    labels          JSONB NOT NULL DEFAULT '{}',
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_identities_tenant    ON agent_identities(tenant_id);
CREATE INDEX IF NOT EXISTS idx_identities_spiffe    ON agent_identities(spiffe_id);
CREATE INDEX IF NOT EXISTS idx_identities_expires   ON agent_identities(expires_at);
CREATE INDEX IF NOT EXISTS idx_identities_revoked   ON agent_identities(revoked) WHERE revoked = FALSE;

-- -----------------------------------------------------------------------
-- Access Tokens
-- -----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS access_tokens (
    jti             TEXT PRIMARY KEY,
    agent_id        TEXT NOT NULL REFERENCES agent_identities(id) ON DELETE CASCADE,
    tenant_id       TEXT NOT NULL,
    resource        TEXT NOT NULL,
    scopes          JSONB NOT NULL DEFAULT '[]',
    dpop_thumbprint TEXT,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tokens_agent     ON access_tokens(agent_id);
CREATE INDEX IF NOT EXISTS idx_tokens_tenant    ON access_tokens(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tokens_expires   ON access_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_tokens_revoked   ON access_tokens(revoked) WHERE revoked = FALSE;

-- -----------------------------------------------------------------------
-- Audit Log (append-only, hash-chained)
-- -----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id              TEXT PRIMARY KEY,
    seq             BIGINT NOT NULL UNIQUE,
    prev_hash       TEXT NOT NULL,
    entry_hash      TEXT NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    agent_id        TEXT NOT NULL,
    action          TEXT NOT NULL,
    resource        TEXT NOT NULL,
    decision        TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
    envelope_ref    TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp  ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_agent      ON audit_log(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_action     ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_seq        ON audit_log(seq);

-- Prevent UPDATE and DELETE on audit_log (append-only enforcement)
CREATE OR REPLACE RULE audit_log_no_update AS
    ON UPDATE TO audit_log DO INSTEAD NOTHING;

CREATE OR REPLACE RULE audit_log_no_delete AS
    ON DELETE TO audit_log DO INSTEAD NOTHING;

-- -----------------------------------------------------------------------
-- Policies
-- -----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policies (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT REFERENCES tenants(id) ON DELETE CASCADE,
    package    TEXT NOT NULL,
    source     TEXT NOT NULL,
    version    TEXT NOT NULL DEFAULT 'v1.0.0',
    enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies(tenant_id);

-- -----------------------------------------------------------------------
-- Schema version tracking (for golang-migrate compatibility)
-- -----------------------------------------------------------------------
-- golang-migrate manages its own schema_migrations table automatically.

COMMIT;
