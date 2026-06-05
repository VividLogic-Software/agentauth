package audit

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// ChainVerificationResult reports the integrity status of an audit log range.
type ChainVerificationResult struct {
	// Verified is true if the entire chain passed integrity checks.
	Verified bool `json:"verified"`

	// EntriesChecked is the number of entries that were verified.
	EntriesChecked int `json:"entries_checked"`

	// FirstEntryID is the ID of the first entry in the checked range.
	FirstEntryID string `json:"first_entry_id,omitempty"`

	// LastEntryID is the ID of the last entry in the checked range.
	LastEntryID string `json:"last_entry_id,omitempty"`

	// FirstHash is the hash of the first entry.
	FirstHash string `json:"first_hash,omitempty"`

	// LastHash is the hash of the last entry.
	LastHash string `json:"last_hash,omitempty"`

	// BreakPoint is the entry ID where a chain break was detected, if any.
	BreakPoint string `json:"break_point,omitempty"`

	// Error describes the verification failure, if any.
	Error string `json:"error,omitempty"`

	// VerifiedAt is when this verification was performed.
	VerifiedAt time.Time `json:"verified_at"`
}

// ChainVerifier provides utilities for verifying the integrity of audit log chains.
type ChainVerifier struct {
	store LogStore
	log   *zap.Logger
}

// NewChainVerifier creates a new chain verifier.
func NewChainVerifier(store LogStore, log *zap.Logger) *ChainVerifier {
	return &ChainVerifier{store: store, log: log}
}

// VerifyRange verifies the hash chain integrity for the given time range.
func (v *ChainVerifier) VerifyRange(ctx context.Context, from, to time.Time) (*ChainVerificationResult, error) {
	result := &ChainVerificationResult{
		VerifiedAt: time.Now().UTC(),
	}

	entries, err := v.store.GetEntries(ctx, from, to)
	if err != nil {
		result.Error = fmt.Sprintf("loading entries: %v", err)
		return result, fmt.Errorf("loading entries: %w", err)
	}

	if len(entries) == 0 {
		result.Verified = true
		result.EntriesChecked = 0
		return result, nil
	}

	result.FirstEntryID = entries[0].ID
	result.LastEntryID = entries[len(entries)-1].ID
	result.FirstHash = entries[0].EntryHash
	result.LastHash = entries[len(entries)-1].EntryHash

	for i, entry := range entries {
		// Recompute the hash
		computedHash, err := computeEntryHash(entry)
		if err != nil {
			result.BreakPoint = entry.ID
			result.Error = fmt.Sprintf("computing hash for entry %s: %v", entry.ID, err)
			return result, nil
		}

		if computedHash != entry.EntryHash {
			result.BreakPoint = entry.ID
			result.Error = fmt.Sprintf(
				"hash mismatch at entry %s (seq=%d): stored=%q, computed=%q",
				entry.ID, entry.SequenceNumber, entry.EntryHash, computedHash,
			)
			v.log.Error("audit chain integrity violation detected",
				zap.String("entry_id", entry.ID),
				zap.Int64("seq", entry.SequenceNumber),
				zap.String("stored_hash", entry.EntryHash),
				zap.String("computed_hash", computedHash),
			)
			return result, nil
		}

		// Verify chain linkage
		if i > 0 {
			expected := entries[i-1].EntryHash
			if entry.PrevHash != expected {
				result.BreakPoint = entry.ID
				result.Error = fmt.Sprintf(
					"chain break at entry %s (seq=%d): prev_hash=%q, expected=%q",
					entry.ID, entry.SequenceNumber, entry.PrevHash, expected,
				)
				v.log.Error("audit chain link break detected",
					zap.String("entry_id", entry.ID),
					zap.Int64("seq", entry.SequenceNumber),
				)
				return result, nil
			}
		}
	}

	result.Verified = true
	result.EntriesChecked = len(entries)

	v.log.Info("audit chain verified",
		zap.Int("entries", len(entries)),
		zap.Time("from", from),
		zap.Time("to", to),
	)

	return result, nil
}

// ExportSummary returns a summary of the audit log suitable for reporting.
type ExportSummary struct {
	TotalEntries  int64                       `json:"total_entries"`
	ActionCounts  map[ActionType]int64        `json:"action_counts"`
	DecisionRatio map[DecisionType]int64      `json:"decision_ratio"`
	TopAgents     []AgentActivity             `json:"top_agents"`
}

// AgentActivity summarizes an agent's recorded activity.
type AgentActivity struct {
	AgentID string `json:"agent_id"`
	Count   int64  `json:"count"`
}
