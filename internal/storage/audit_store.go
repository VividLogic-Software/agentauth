package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/VividLogic-Software/agentauth/internal/audit"
)

// PostgresAuditStore implements audit.LogStore using PostgreSQL.
// Entries are append-only; no UPDATE or DELETE is permitted.
type PostgresAuditStore struct {
	db DBExecutor
}

// NewPostgresAuditStore creates a new audit log store backed by PostgreSQL.
func NewPostgresAuditStore(db DBExecutor) *PostgresAuditStore {
	return &PostgresAuditStore{db: db}
}

// Append inserts a new audit log entry. The entry must have a unique ID and
// a SequenceNumber greater than the current maximum.
func (s *PostgresAuditStore) Append(ctx context.Context, entry *audit.LogEntry) error {
	metaJSON, err := json.Marshal(entry.Metadata)
	if err != nil {
		return fmt.Errorf("marshaling metadata: %w", err)
	}

	query := `
		INSERT INTO audit_log (
			id, seq, prev_hash, entry_hash, timestamp,
			agent_id, action, resource, decision, envelope_ref, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err = s.db.ExecContext(ctx, query,
		entry.ID,
		entry.SequenceNumber,
		entry.PrevHash,
		entry.EntryHash,
		entry.Timestamp,
		entry.AgentID,
		string(entry.Action),
		entry.Resource,
		string(entry.Decision),
		entry.EnvelopeRef,
		string(metaJSON),
	)
	if err != nil {
		return fmt.Errorf("inserting audit entry: %w", err)
	}
	return nil
}

// GetLatestHash returns the entry_hash and seq of the most recent audit entry.
// Returns ("", 0, nil) if the log is empty.
func (s *PostgresAuditStore) GetLatestHash(ctx context.Context) (string, int64, error) {
	query := `SELECT entry_hash, seq FROM audit_log ORDER BY seq DESC LIMIT 1`
	row := s.db.QueryRowContext(ctx, query)

	var hash string
	var seq int64
	if err := row.Scan(&hash, &seq); err != nil {
		// Empty table is not an error
		if isNoRows(err) {
			return "", 0, nil
		}
		return "", 0, fmt.Errorf("reading latest audit hash: %w", err)
	}
	return hash, seq, nil
}

// GetEntries returns all audit log entries within the given time range, ordered by seq.
func (s *PostgresAuditStore) GetEntries(ctx context.Context, from, to time.Time) ([]*audit.LogEntry, error) {
	query := `
		SELECT id, seq, prev_hash, entry_hash, timestamp,
		       agent_id, action, resource, decision, envelope_ref, metadata
		FROM audit_log
		WHERE timestamp >= $1 AND timestamp <= $2
		ORDER BY seq ASC
	`
	rows, err := s.db.QueryContext(ctx, query, from, to)
	if err != nil {
		return nil, fmt.Errorf("querying audit entries: %w", err)
	}
	defer rows.Close()

	var entries []*audit.LogEntry
	for rows.Next() {
		entry, err := scanAuditEntry(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning audit entry: %w", err)
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

// scanAuditEntry scans a single row into an audit.LogEntry.
func scanAuditEntry(row RowScanner) (*audit.LogEntry, error) {
	entry := &audit.LogEntry{}
	var action, decision, metaJSON string

	err := row.Scan(
		&entry.ID,
		&entry.SequenceNumber,
		&entry.PrevHash,
		&entry.EntryHash,
		&entry.Timestamp,
		&entry.AgentID,
		&action,
		&entry.Resource,
		&decision,
		&entry.EnvelopeRef,
		&metaJSON,
	)
	if err != nil {
		return nil, err
	}

	entry.Action = audit.ActionType(action)
	entry.Decision = audit.DecisionType(decision)

	if metaJSON != "" && metaJSON != "{}" {
		entry.Metadata = make(map[string]string)
		_ = json.Unmarshal([]byte(metaJSON), &entry.Metadata)
	}

	return entry, nil
}

// isNoRows returns true if the error indicates no rows were found.
// Works with database/sql's ErrNoRows.
func isNoRows(err error) bool {
	return err != nil && err.Error() == "sql: no rows in result set"
}
