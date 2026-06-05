// Package audit provides a tamper-evident append-only audit log for all
// AgentAuth authorization decisions. Each entry is linked to the previous
// via SHA-256 hash chaining to detect tampering.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ActionType identifies the type of event being recorded.
type ActionType string

const (
	ActionIdentityIssued  ActionType = "identity.issued"
	ActionIdentityRevoked ActionType = "identity.revoked"
	ActionTokenMinted     ActionType = "token.minted"
	ActionTokenRevoked    ActionType = "token.revoked"
	ActionPolicyEvaluated ActionType = "policy.evaluated"
	ActionToolCall        ActionType = "tool.call"
	ActionA2ADelegate     ActionType = "a2a.delegate"
	ActionEnvelopeCreated ActionType = "envelope.created"
	ActionEnvelopeVerified ActionType = "envelope.verified"
)

// DecisionType records whether an authorization was allowed or denied.
type DecisionType string

const (
	DecisionAllow DecisionType = "allow"
	DecisionDeny  DecisionType = "deny"
)

// Event is the input to the audit log recorder.
type Event struct {
	// AgentID is the SPIFFE ID or agent identifier of the actor.
	AgentID string

	// Action is the type of event.
	Action ActionType

	// Resource is the resource being acted upon.
	Resource string

	// Decision is whether the action was allowed or denied.
	Decision DecisionType

	// EnvelopeRef is the JWTID of the envelope authorizing this action.
	EnvelopeRef string

	// Metadata contains additional event-specific information.
	Metadata map[string]string
}

// LogEntry is a single immutable record in the audit log.
type LogEntry struct {
	// ID is the unique identifier for this log entry.
	ID string `json:"id"`

	// PrevHash is the SHA-256 hash of the previous entry, enabling chain verification.
	PrevHash string `json:"prev_hash"`

	// EntryHash is the SHA-256 hash of this entry's content (excluding EntryHash itself).
	EntryHash string `json:"entry_hash"`

	// Timestamp is when this event occurred.
	Timestamp time.Time `json:"timestamp"`

	// AgentID is the actor.
	AgentID string `json:"agent_id"`

	// Action is the event type.
	Action ActionType `json:"action"`

	// Resource is the target resource.
	Resource string `json:"resource"`

	// Decision records allow/deny.
	Decision DecisionType `json:"decision"`

	// EnvelopeRef links to the authorizing envelope.
	EnvelopeRef string `json:"envelope_ref,omitempty"`

	// Metadata holds additional event data.
	Metadata map[string]string `json:"metadata,omitempty"`

	// SequenceNumber is the monotonically increasing position in the log.
	SequenceNumber int64 `json:"seq"`
}

// Auditor is the interface for recording audit events.
type Auditor interface {
	Record(ctx context.Context, event *Event) error
}

// LogStore is the persistence interface for the audit log.
type LogStore interface {
	Append(ctx context.Context, entry *LogEntry) error
	GetLatestHash(ctx context.Context) (string, int64, error)
	GetEntries(ctx context.Context, from, to time.Time) ([]*LogEntry, error)
}

// AuditLog is the production audit log with hash chain integrity.
type AuditLog struct {
	store    LogStore
	log      *zap.Logger
	mu       sync.Mutex
	lastHash string
	lastSeq  int64
}

// NewAuditLog creates a new tamper-evident audit log.
func NewAuditLog(store LogStore, log *zap.Logger) (*AuditLog, error) {
	lastHash, lastSeq, err := store.GetLatestHash(context.Background())
	if err != nil {
		return nil, fmt.Errorf("loading audit log state: %w", err)
	}

	return &AuditLog{
		store:    store,
		log:      log,
		lastHash: lastHash,
		lastSeq:  lastSeq,
	}, nil
}

// Record appends a new entry to the audit log.
// The entry is hash-chained to the previous entry for tamper detection.
func (a *AuditLog) Record(ctx context.Context, event *Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	entry := &LogEntry{
		ID:          uuid.New().String(),
		PrevHash:    a.lastHash,
		Timestamp:   time.Now().UTC(),
		AgentID:     event.AgentID,
		Action:      event.Action,
		Resource:    event.Resource,
		Decision:    event.Decision,
		EnvelopeRef: event.EnvelopeRef,
		Metadata:    event.Metadata,
		SequenceNumber: a.lastSeq + 1,
	}

	hash, err := computeEntryHash(entry)
	if err != nil {
		return fmt.Errorf("computing entry hash: %w", err)
	}
	entry.EntryHash = hash

	if err := a.store.Append(ctx, entry); err != nil {
		return fmt.Errorf("appending audit entry: %w", err)
	}

	a.lastHash = hash
	a.lastSeq = entry.SequenceNumber

	a.log.Debug("audit event recorded",
		zap.String("id", entry.ID),
		zap.String("action", string(event.Action)),
		zap.String("agent_id", event.AgentID),
		zap.String("decision", string(event.Decision)),
		zap.Int64("seq", entry.SequenceNumber),
	)

	return nil
}

// GetEntries returns audit log entries within the given time range.
func (a *AuditLog) GetEntries(ctx context.Context, from, to time.Time) ([]*LogEntry, error) {
	return a.store.GetEntries(ctx, from, to)
}

// VerifyChainIntegrity re-reads all entries from the store and validates
// the hash chain is unbroken. Returns nil if the chain is intact.
func (a *AuditLog) VerifyChainIntegrity(ctx context.Context, from, to time.Time) error {
	entries, err := a.store.GetEntries(ctx, from, to)
	if err != nil {
		return fmt.Errorf("loading entries for verification: %w", err)
	}

	if len(entries) == 0 {
		return nil
	}

	for i, entry := range entries {
		// Verify the stored hash matches the recomputed hash
		recomputedHash, err := computeEntryHash(entry)
		if err != nil {
			return fmt.Errorf("recomputing hash for entry %d (%s): %w", i, entry.ID, err)
		}

		if recomputedHash != entry.EntryHash {
			return fmt.Errorf("hash mismatch at entry %d (id=%s): stored=%q, computed=%q",
				i, entry.ID, entry.EntryHash, recomputedHash)
		}

		// Verify chain linkage (skip first entry)
		if i > 0 {
			expectedPrevHash := entries[i-1].EntryHash
			if entry.PrevHash != expectedPrevHash {
				return fmt.Errorf("chain break at entry %d (id=%s): prev_hash=%q, expected=%q",
					i, entry.ID, entry.PrevHash, expectedPrevHash)
			}
		}
	}

	return nil
}

// computeEntryHash computes the SHA-256 hash of a log entry's content fields,
// excluding the EntryHash field itself.
func computeEntryHash(entry *LogEntry) (string, error) {
	// Canonical representation for hashing — exclude EntryHash
	canonical := struct {
		ID          string            `json:"id"`
		PrevHash    string            `json:"prev_hash"`
		Timestamp   time.Time         `json:"timestamp"`
		AgentID     string            `json:"agent_id"`
		Action      ActionType        `json:"action"`
		Resource    string            `json:"resource"`
		Decision    DecisionType      `json:"decision"`
		EnvelopeRef string            `json:"envelope_ref,omitempty"`
		Metadata    map[string]string `json:"metadata,omitempty"`
		Seq         int64             `json:"seq"`
	}{
		ID:          entry.ID,
		PrevHash:    entry.PrevHash,
		Timestamp:   entry.Timestamp,
		AgentID:     entry.AgentID,
		Action:      entry.Action,
		Resource:    entry.Resource,
		Decision:    entry.Decision,
		EnvelopeRef: entry.EnvelopeRef,
		Metadata:    entry.Metadata,
		Seq:         entry.SequenceNumber,
	}

	data, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("marshaling entry for hashing: %w", err)
	}

	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

// NoopAuditor is a no-op auditor for testing.
type NoopAuditor struct{}

// Record does nothing.
func (n *NoopAuditor) Record(ctx context.Context, event *Event) error {
	return nil
}
