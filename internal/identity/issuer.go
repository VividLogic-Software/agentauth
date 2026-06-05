// Package identity provides SPIFFE/SVID-based identity issuance for AI agents.
// It implements workload attestation and manages the lifecycle of agent identities.
package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/VividLogic-Software/agentauth/internal/audit"
	"github.com/VividLogic-Software/agentauth/internal/storage"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	// DefaultSVIDTTL is the default lifetime for issued SVIDs.
	DefaultSVIDTTL = 1 * time.Hour

	// MaxSVIDTTL is the maximum allowed SVID lifetime.
	MaxSVIDTTL = 24 * time.Hour

	// SPIFFEScheme is the URI scheme for SPIFFE IDs.
	SPIFFEScheme = "spiffe"

	// TrustDomain is the default trust domain for AgentAuth.
	TrustDomain = "agentauth.io"
)

// IssueIdentityRequest contains the parameters for issuing a new agent identity.
type IssueIdentityRequest struct {
	// AgentID is the unique identifier for the agent. If empty, one is generated.
	AgentID string `json:"agent_id"`

	// DelegatorID is the identity of the entity delegating to this agent.
	DelegatorID string `json:"delegator_id"`

	// TenantID scopes this identity to a specific tenant/org.
	TenantID string `json:"tenant_id"`

	// DeclaredIntent describes what this agent is authorized to do.
	DeclaredIntent string `json:"declared_intent"`

	// TTL overrides the default SVID lifetime.
	TTL time.Duration `json:"ttl,omitempty"`

	// Attestation provides workload attestation data (K8s, AWS, etc).
	Attestation *AttestationData `json:"attestation,omitempty"`

	// Labels are arbitrary key-value metadata attached to the identity.
	Labels map[string]string `json:"labels,omitempty"`
}

// AgentIdentity represents a fully issued agent identity including its SVID.
type AgentIdentity struct {
	// ID is the unique AgentAuth-assigned identifier.
	ID string `json:"id"`

	// SPIFFEID is the SPIFFE URI for this agent.
	SPIFFEID string `json:"spiffe_id"`

	// TenantID is the tenant this identity belongs to.
	TenantID string `json:"tenant_id"`

	// DelegatorID is who delegated this identity.
	DelegatorID string `json:"delegator_id"`

	// DeclaredIntent is the human-readable purpose.
	DeclaredIntent string `json:"declared_intent"`

	// CertificatePEM is the X.509 SVID in PEM format.
	CertificatePEM string `json:"certificate_pem"`

	// PrivateKeyPEM is the ECDSA private key in PEM format.
	// Only returned at issuance time — never stored.
	PrivateKeyPEM string `json:"private_key_pem"`

	// IssuedAt is when this identity was created.
	IssuedAt time.Time `json:"issued_at"`

	// ExpiresAt is when this identity expires.
	ExpiresAt time.Time `json:"expires_at"`

	// Labels are the metadata labels.
	Labels map[string]string `json:"labels,omitempty"`
}

// Issuer manages the lifecycle of agent identities, issuing SPIFFE SVIDs
// and handling rotation and revocation.
type Issuer struct {
	trustDomain string
	caCert      *x509.Certificate
	caKey       *ecdsa.PrivateKey
	store       storage.IdentityStore
	auditor     audit.Auditor
	log         *zap.Logger
}

// NewIssuer creates a new identity Issuer backed by the given storage and auditor.
func NewIssuer(
	trustDomain string,
	caCert *x509.Certificate,
	caKey *ecdsa.PrivateKey,
	store storage.IdentityStore,
	auditor audit.Auditor,
	log *zap.Logger,
) *Issuer {
	return &Issuer{
		trustDomain: trustDomain,
		caCert:      caCert,
		caKey:       caKey,
		store:       store,
		auditor:     auditor,
		log:         log,
	}
}

// IssueIdentity mints a new SPIFFE SVID for an AI agent and records the
// identity in the registry. The private key is returned only once and never stored.
func (i *Issuer) IssueIdentity(ctx context.Context, req *IssueIdentityRequest) (*AgentIdentity, error) {
	if req.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}

	agentID := req.AgentID
	if agentID == "" {
		agentID = uuid.New().String()
	}

	ttl := req.TTL
	if ttl == 0 {
		ttl = DefaultSVIDTTL
	}
	if ttl > MaxSVIDTTL {
		return nil, fmt.Errorf("requested TTL %v exceeds maximum %v", ttl, MaxSVIDTTL)
	}

	// Generate agent key pair
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating agent key: %w", err)
	}

	spiffeID, err := i.buildSPIFFEID(req.TenantID, agentID)
	if err != nil {
		return nil, fmt.Errorf("building SPIFFE ID: %w", err)
	}

	now := time.Now().UTC()
	expiry := now.Add(ttl)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("agent:%s", agentID),
			Organization: []string{req.TenantID},
		},
		URIs:                  []*url.URL{spiffeID},
		NotBefore:             now,
		NotAfter:              expiry,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, i.caCert, &agentKey.PublicKey, i.caKey)
	if err != nil {
		return nil, fmt.Errorf("creating certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyBytes, err := x509.MarshalECPrivateKey(agentKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	identity := &AgentIdentity{
		ID:             agentID,
		SPIFFEID:       spiffeID.String(),
		TenantID:       req.TenantID,
		DelegatorID:    req.DelegatorID,
		DeclaredIntent: req.DeclaredIntent,
		CertificatePEM: string(certPEM),
		PrivateKeyPEM:  string(keyPEM),
		IssuedAt:       now,
		ExpiresAt:      expiry,
		Labels:         req.Labels,
	}

	// Store identity record (without private key)
	record := &storage.IdentityRecord{
		ID:             agentID,
		SPIFFEID:       identity.SPIFFEID,
		TenantID:       req.TenantID,
		DelegatorID:    req.DelegatorID,
		DeclaredIntent: req.DeclaredIntent,
		CertificatePEM: identity.CertificatePEM,
		IssuedAt:       now,
		ExpiresAt:      expiry,
		Labels:         req.Labels,
		Revoked:        false,
	}

	if err := i.store.StoreIdentity(ctx, record); err != nil {
		return nil, fmt.Errorf("storing identity: %w", err)
	}

	// Record audit event
	if err := i.auditor.Record(ctx, &audit.Event{
		AgentID:  agentID,
		Action:   audit.ActionIdentityIssued,
		Resource: identity.SPIFFEID,
		Decision: audit.DecisionAllow,
		Metadata: map[string]string{
			"tenant_id":    req.TenantID,
			"delegator_id": req.DelegatorID,
			"ttl":          ttl.String(),
		},
	}); err != nil {
		i.log.Warn("failed to record audit event", zap.Error(err))
	}

	i.log.Info("issued agent identity",
		zap.String("agent_id", agentID),
		zap.String("tenant_id", req.TenantID),
		zap.String("spiffe_id", identity.SPIFFEID),
		zap.Time("expires_at", expiry),
	)

	return identity, nil
}

// RevokeIdentity marks an agent identity as revoked and records the revocation.
// Revoked identities are rejected by all AgentAuth middleware.
func (i *Issuer) RevokeIdentity(ctx context.Context, agentID string) error {
	record, err := i.store.GetIdentity(ctx, agentID)
	if err != nil {
		return fmt.Errorf("looking up identity %s: %w", agentID, err)
	}

	if record.Revoked {
		return fmt.Errorf("identity %s is already revoked", agentID)
	}

	if err := i.store.RevokeIdentity(ctx, agentID); err != nil {
		return fmt.Errorf("revoking identity: %w", err)
	}

	if err := i.auditor.Record(ctx, &audit.Event{
		AgentID:  agentID,
		Action:   audit.ActionIdentityRevoked,
		Resource: record.SPIFFEID,
		Decision: audit.DecisionAllow,
		Metadata: map[string]string{
			"tenant_id": record.TenantID,
		},
	}); err != nil {
		i.log.Warn("failed to record revocation audit event", zap.Error(err))
	}

	i.log.Info("revoked agent identity",
		zap.String("agent_id", agentID),
		zap.String("spiffe_id", record.SPIFFEID),
	)

	return nil
}

// RotateCredentials issues a new SVID for an existing agent identity,
// invalidating the old certificate.
func (i *Issuer) RotateCredentials(ctx context.Context, agentID string) (*AgentIdentity, error) {
	existing, err := i.store.GetIdentity(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("looking up identity %s: %w", agentID, err)
	}

	if existing.Revoked {
		return nil, fmt.Errorf("cannot rotate revoked identity %s", agentID)
	}

	req := &IssueIdentityRequest{
		AgentID:        agentID,
		DelegatorID:    existing.DelegatorID,
		TenantID:       existing.TenantID,
		DeclaredIntent: existing.DeclaredIntent,
		TTL:            DefaultSVIDTTL,
		Labels:         existing.Labels,
	}

	newIdentity, err := i.IssueIdentity(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("issuing rotated identity: %w", err)
	}

	i.log.Info("rotated agent credentials",
		zap.String("agent_id", agentID),
		zap.String("new_spiffe_id", newIdentity.SPIFFEID),
	)

	return newIdentity, nil
}

// GetIdentity retrieves an agent identity by ID.
func (i *Issuer) GetIdentity(ctx context.Context, agentID string) (*storage.IdentityRecord, error) {
	return i.store.GetIdentity(ctx, agentID)
}

// ValidateSPIFFEID verifies a SPIFFE ID belongs to our trust domain
// and that the referenced identity is active (not expired or revoked).
func (i *Issuer) ValidateSPIFFEID(ctx context.Context, spiffeID string) error {
	u, err := url.Parse(spiffeID)
	if err != nil {
		return fmt.Errorf("invalid SPIFFE ID format: %w", err)
	}

	if u.Scheme != SPIFFEScheme {
		return fmt.Errorf("invalid scheme: expected %q, got %q", SPIFFEScheme, u.Scheme)
	}

	if u.Host != i.trustDomain {
		return fmt.Errorf("untrusted trust domain: %q", u.Host)
	}

	// Extract agent ID from path: /agent/{tenant}/{agent_id}
	record, err := i.store.GetIdentityBySPIFFEID(ctx, spiffeID)
	if err != nil {
		return fmt.Errorf("identity not found: %w", err)
	}

	if record.Revoked {
		return fmt.Errorf("identity %s has been revoked", record.ID)
	}

	if time.Now().After(record.ExpiresAt) {
		return fmt.Errorf("identity %s has expired", record.ID)
	}

	return nil
}

// buildSPIFFEID constructs a well-formed SPIFFE URI for the given tenant and agent.
func (i *Issuer) buildSPIFFEID(tenantID, agentID string) (*url.URL, error) {
	raw := fmt.Sprintf("%s://%s/agent/%s/%s", SPIFFEScheme, i.trustDomain, tenantID, agentID)
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("constructing SPIFFE URI: %w", err)
	}
	return u, nil
}
