-- Rollback initial schema
-- Run with: migrate -path db/migrations -database $DATABASE_URL down 1

BEGIN;

DROP TABLE IF EXISTS policies;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS access_tokens;
DROP TABLE IF EXISTS agent_identities;
DROP TABLE IF EXISTS tenants;

COMMIT;
