package audit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// inMemoryStore is a simple in-memory LogStore for testing.
type inMemoryStore struct {
	entries []*LogEntry
}

func (s *inMemoryStore) Append(_ context.Context, entry *LogEntry) error {
	s.entries = append(s.entries, entry)
	return nil
}

func (s *inMemoryStore) GetLatestHash(_ context.Context) (string, int64, error) {
	if len(s.entries) == 0 {
		return "", 0, nil
	}
	last := s.entries[len(s.entries)-1]
	return last.EntryHash, last.SequenceNumber, nil
}

func (s *inMemoryStore) GetEntries(_ context.Context, from, to time.Time) ([]*LogEntry, error) {
	var result []*LogEntry
	for _, e := range s.entries {
		if (e.Timestamp.Equal(from) || e.Timestamp.After(from)) &&
			(e.Timestamp.Equal(to) || e.Timestamp.Before(to)) {
			result = append(result, e)
		}
	}
	return result, nil
}

func newTestAuditLog(t *testing.T) (*AuditLog, *inMemoryStore) {
	t.Helper()
	store := &inMemoryStore{}
	log := zaptest.NewLogger(t)
	al, err := NewAuditLog(store, log)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	return al, store
}

func recordEvent(t *testing.T, al *AuditLog, action ActionType) {
	t.Helper()
	err := al.Record(context.Background(), &Event{
		AgentID:  "spiffe://agentauth.io/agent/acme/agent-1",
		Action:   action,
		Resource: "test-resource",
		Decision: DecisionAllow,
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
}

// ---- computeEntryHash ----

func TestComputeEntryHash_Deterministic(t *testing.T) {
	entry := &LogEntry{
		ID:             "test-id",
		PrevHash:       "prev-hash",
		Timestamp:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		AgentID:        "agent-1",
		Action:         ActionTokenMinted,
		Resource:       "resource-x",
		Decision:       DecisionAllow,
		SequenceNumber: 1,
	}

	h1, err := computeEntryHash(entry)
	if err != nil {
		t.Fatalf("computeEntryHash: %v", err)
	}
	h2, err := computeEntryHash(entry)
	if err != nil {
		t.Fatalf("computeEntryHash second call: %v", err)
	}
	if h1 != h2 {
		t.Errorf("hash not deterministic: %q != %q", h1, h2)
	}
}

func TestComputeEntryHash_ChangesOnFieldChange(t *testing.T) {
	entry := &LogEntry{
		ID:             "test-id",
		PrevHash:       "prev-hash",
		Timestamp:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		AgentID:        "agent-1",
		Action:         ActionTokenMinted,
		Resource:       "resource-x",
		Decision:       DecisionAllow,
		SequenceNumber: 1,
	}

	h1, _ := computeEntryHash(entry)
	entry.Resource = "resource-y"
	h2, _ := computeEntryHash(entry)

	if h1 == h2 {
		t.Error("expected hash to change when resource changes")
	}
}

func TestComputeEntryHash_IgnoresEntryHashField(t *testing.T) {
	entry := &LogEntry{
		ID:             "id",
		PrevHash:       "prev",
		Timestamp:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		AgentID:        "a",
		Action:         ActionToolCall,
		Resource:       "r",
		Decision:       DecisionDeny,
		SequenceNumber: 5,
	}

	h1, _ := computeEntryHash(entry)
	entry.EntryHash = "something-else"
	h2, _ := computeEntryHash(entry)

	if h1 != h2 {
		t.Error("EntryHash field should not affect the computed hash")
	}
}

// ---- AuditLog.Record ----

func TestRecord_AppendsSingleEntry(t *testing.T) {
	al, store := newTestAuditLog(t)
	recordEvent(t, al, ActionIdentityIssued)

	if len(store.entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(store.entries))
	}
	entry := store.entries[0]
	if entry.Action != ActionIdentityIssued {
		t.Errorf("expected action %q, got %q", ActionIdentityIssued, entry.Action)
	}
	if entry.EntryHash == "" {
		t.Error("expected non-empty entry hash")
	}
	if entry.SequenceNumber != 1 {
		t.Errorf("expected sequence 1, got %d", entry.SequenceNumber)
	}
}

func TestRecord_ChainsPrevHash(t *testing.T) {
	al, store := newTestAuditLog(t)
	recordEvent(t, al, ActionIdentityIssued)
	recordEvent(t, al, ActionTokenMinted)

	if len(store.entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(store.entries))
	}

	first := store.entries[0]
	second := store.entries[1]

	if second.PrevHash != first.EntryHash {
		t.Errorf("second entry PrevHash %q != first EntryHash %q",
			second.PrevHash, first.EntryHash)
	}
	if second.SequenceNumber != 2 {
		t.Errorf("expected sequence 2, got %d", second.SequenceNumber)
	}
}

func TestRecord_FirstEntryHasEmptyPrevHash(t *testing.T) {
	al, store := newTestAuditLog(t)
	recordEvent(t, al, ActionIdentityIssued)
	if store.entries[0].PrevHash != "" {
		t.Errorf("first entry should have empty PrevHash, got %q", store.entries[0].PrevHash)
	}
}

func TestRecord_AssignsUniqueIDs(t *testing.T) {
	al, store := newTestAuditLog(t)
	for i := 0; i < 5; i++ {
		recordEvent(t, al, ActionToolCall)
	}
	seen := make(map[string]bool)
	for _, e := range store.entries {
		if seen[e.ID] {
			t.Errorf("duplicate entry ID: %q", e.ID)
		}
		seen[e.ID] = true
	}
}

// ---- AuditLog.VerifyChainIntegrity ----

func allTime() (time.Time, time.Time) {
	return time.Time{}, time.Now().Add(time.Hour)
}

func TestVerifyChainIntegrity_EmptyLog(t *testing.T) {
	al, _ := newTestAuditLog(t)
	from, to := allTime()
	if err := al.VerifyChainIntegrity(context.Background(), from, to); err != nil {
		t.Errorf("empty log should verify: %v", err)
	}
}

func TestVerifyChainIntegrity_ValidChain(t *testing.T) {
	al, _ := newTestAuditLog(t)
	for i := 0; i < 10; i++ {
		recordEvent(t, al, ActionToolCall)
	}
	from, to := allTime()
	if err := al.VerifyChainIntegrity(context.Background(), from, to); err != nil {
		t.Errorf("valid chain should pass verification: %v", err)
	}
}

func TestVerifyChainIntegrity_DetectsTamperedHash(t *testing.T) {
	al, store := newTestAuditLog(t)
	recordEvent(t, al, ActionIdentityIssued)
	recordEvent(t, al, ActionTokenMinted)

	// Tamper with the first entry's hash
	store.entries[0].EntryHash = "tampered-hash-value"

	from, to := allTime()
	err := al.VerifyChainIntegrity(context.Background(), from, to)
	if err == nil {
		t.Fatal("expected verification to fail after tampering")
	}
}

func TestVerifyChainIntegrity_DetectsBrokenChain(t *testing.T) {
	al, store := newTestAuditLog(t)
	recordEvent(t, al, ActionIdentityIssued)
	recordEvent(t, al, ActionTokenMinted)
	recordEvent(t, al, ActionToolCall)

	// Break the chain link: second entry points to a wrong prev hash
	store.entries[1].PrevHash = "wrong-prev-hash"

	from, to := allTime()
	err := al.VerifyChainIntegrity(context.Background(), from, to)
	if err == nil {
		t.Fatal("expected verification to fail after chain break")
	}
}

// ---- GetEntries ----

func TestGetEntries_TimeRange(t *testing.T) {
	al, _ := newTestAuditLog(t)
	for i := 0; i < 5; i++ {
		recordEvent(t, al, ActionToolCall)
	}
	from := time.Now().Add(-time.Hour)
	to := time.Now().Add(time.Hour)
	entries, err := al.GetEntries(context.Background(), from, to)
	if err != nil {
		t.Fatalf("GetEntries: %v", err)
	}
	if len(entries) != 5 {
		t.Errorf("expected 5 entries, got %d", len(entries))
	}
}

// ---- NoopAuditor ----

func TestNoopAuditor_RecordReturnsNil(t *testing.T) {
	n := &NoopAuditor{}
	err := n.Record(context.Background(), &Event{
		AgentID:  "agent-1",
		Action:   ActionToolCall,
		Resource: "r",
		Decision: DecisionDeny,
	})
	if err != nil {
		t.Errorf("NoopAuditor.Record should return nil, got: %v", err)
	}
}

// ---- errorStore ----

type errorStore struct{}

func (e *errorStore) Append(_ context.Context, _ *LogEntry) error {
	return fmt.Errorf("disk full")
}
func (e *errorStore) GetLatestHash(_ context.Context) (string, int64, error) {
	return "", 0, nil
}
func (e *errorStore) GetEntries(_ context.Context, _, _ time.Time) ([]*LogEntry, error) {
	return nil, fmt.Errorf("db unavailable")
}

func TestRecord_PropagatesStoreError(t *testing.T) {
	al, err := NewAuditLog(&errorStore{}, zap.NewNop())
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	err = al.Record(context.Background(), &Event{
		AgentID:  "a",
		Action:   ActionToolCall,
		Resource: "r",
		Decision: DecisionAllow,
	})
	if err == nil {
		t.Fatal("expected error from store propagated")
	}
}
