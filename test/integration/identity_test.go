//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/VividLogic-Software/agentauth/internal/audit"
	"github.com/VividLogic-Software/agentauth/internal/identity"
	"github.com/VividLogic-Software/agentauth/internal/storage"
	"go.uber.org/zap"
)

func TestIssueIdentity(t *testing.T) {
	if os.Getenv("POSTGRES_DSN") == "" {
		t.Skip("POSTGRES_DSN not set; skipping integration test")
	}

	ctx := context.Background()

	caCert, caKey := generateTestCA(t)
	store := newTestIdentityStore(t)
	auditor := &audit.NoopAuditor{}

	issuer := identity.NewIssuer(
		identity.TrustDomain,
		caCert,
		caKey,
		store,
		auditor,
		newTestLogger(t),
	)

	req := &identity.IssueIdentityRequest{
		DelegatorID:    "user:test@example.com",
		TenantID:       "test-tenant",
		DeclaredIntent: "Integration test agent",
		TTL:            30 * time.Minute,
		Labels:         map[string]string{"env": "test"},
	}

	ident, err := issuer.IssueIdentity(ctx, req)
	if err != nil {
		t.Fatalf("IssueIdentity() error = %v", err)
	}

	// Verify the identity was stored
	if ident.ID == "" {
		t.Error("expected non-empty agent ID")
	}
	if ident.SPIFFEID == "" {
		t.Error("expected non-empty SPIFFE ID")
	}
	if ident.CertificatePEM == "" {
		t.Error("expected non-empty certificate PEM")
	}
	if ident.PrivateKeyPEM == "" {
		t.Error("expected non-empty private key PEM — only returned at issuance")
	}

	// Retrieve from store
	stored, err := issuer.GetIdentity(ctx, ident.ID)
	if err != nil {
		t.Fatalf("GetIdentity() error = %v", err)
	}
	if stored.ID != ident.ID {
		t.Errorf("stored.ID = %q, want %q", stored.ID, ident.ID)
	}

	// Revoke
	if err := issuer.RevokeIdentity(ctx, ident.ID); err != nil {
		t.Fatalf("RevokeIdentity() error = %v", err)
	}

	// Verify revoked
	revoked, err := issuer.GetIdentity(ctx, ident.ID)
	if err != nil {
		t.Fatalf("GetIdentity() after revoke error = %v", err)
	}
	if !revoked.Revoked {
		t.Error("expected identity to be revoked")
	}
}

func TestRotateCredentials(t *testing.T) {
	if os.Getenv("POSTGRES_DSN") == "" {
		t.Skip("POSTGRES_DSN not set; skipping integration test")
	}

	ctx := context.Background()
	caCert, caKey := generateTestCA(t)
	store := newTestIdentityStore(t)
	issuer := identity.NewIssuer(
		identity.TrustDomain, caCert, caKey, store, &audit.NoopAuditor{}, newTestLogger(t),
	)


	// Issue initial
	initial, err := issuer.IssueIdentity(ctx, &identity.IssueIdentityRequest{
		TenantID:       "test-tenant",
		DeclaredIntent: "rotation test",
	})
	if err != nil {
		t.Fatalf("IssueIdentity: %v", err)
	}

	// Rotate
	rotated, err := issuer.RotateCredentials(ctx, initial.ID)
	if err != nil {
		t.Fatalf("RotateCredentials: %v", err)
	}

	if rotated.CertificatePEM == initial.CertificatePEM {
		t.Error("expected rotated certificate to differ from original")
	}
	if rotated.PrivateKeyPEM == initial.PrivateKeyPEM {
		t.Error("expected rotated private key to differ from original")
	}
}

// Test helpers

func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "AgentAuth Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}

	return cert, key
}

func newTestIdentityStore(t *testing.T) storage.IdentityStore {
	t.Helper()
	// In integration tests, this would connect to the test database
	// For now, return a mock
	return &mockIdentityStore{}
}

func newTestLogger(t *testing.T) *zap.Logger {
	t.Helper()
	log, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("creating test logger: %v", err)
	}
	t.Cleanup(func() { _ = log.Sync() })
	return log
}

// mockIdentityStore is a simple in-memory IdentityStore for testing.
type mockIdentityStore struct {
	records map[string]*storage.IdentityRecord
}

func (m *mockIdentityStore) StoreIdentity(ctx context.Context, record *storage.IdentityRecord) error {
	if m.records == nil {
		m.records = make(map[string]*storage.IdentityRecord)
	}
	m.records[record.ID] = record
	return nil
}

func (m *mockIdentityStore) GetIdentity(ctx context.Context, agentID string) (*storage.IdentityRecord, error) {
	if record, ok := m.records[agentID]; ok {
		return record, nil
	}
	return nil, nil
}

func (m *mockIdentityStore) GetIdentityBySPIFFEID(ctx context.Context, spiffeID string) (*storage.IdentityRecord, error) {
	for _, r := range m.records {
		if r.SPIFFEID == spiffeID {
			return r, nil
		}
	}
	return nil, nil
}

func (m *mockIdentityStore) RevokeIdentity(ctx context.Context, agentID string) error {
	if record, ok := m.records[agentID]; ok {
		record.Revoked = true
		now := time.Now()
		record.RevokedAt = &now
	}
	return nil
}

func (m *mockIdentityStore) ListIdentities(ctx context.Context, tenantID string, limit, offset int) ([]*storage.IdentityRecord, error) {
	var records []*storage.IdentityRecord
	for _, r := range m.records {
		if r.TenantID == tenantID {
			records = append(records, r)
		}
	}
	return records, nil
}
