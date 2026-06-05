// Package broker implements Just-In-Time credential minting for AI agents.
// It issues short-lived, resource-scoped OAuth 2.1 tokens with DPoP binding
// and supports RFC 8693 token exchange for delegation scenarios.
package broker

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/VividLogic-Software/agentauth/internal/audit"
	"github.com/VividLogic-Software/agentauth/internal/envelope"
	"github.com/VividLogic-Software/agentauth/internal/storage"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	// DefaultTokenTTL is the default lifetime for issued access tokens.
	DefaultTokenTTL = 5 * time.Minute

	// MaxTokenTTL is the maximum allowed access token lifetime.
	MaxTokenTTL = 30 * time.Minute

	// TokenTypeBearer is a standard OAuth 2.0 bearer token.
	TokenTypeBearer = "Bearer"

	// TokenTypeDPoP is a DPoP-bound token per RFC 9449.
	TokenTypeDPoP = "DPoP"
)

// MintTokenRequest contains the parameters for minting a new access token.
type MintTokenRequest struct {
	// Envelope is the verified agentic identity envelope authorizing this token.
	Envelope *envelope.AgenticEnvelope

	// Resource is the target resource URI (RFC 8707).
	// Example: "https://api.github.com/repos/myorg/myrepo"
	Resource string `json:"resource"`

	// Scopes are the OAuth 2.0 scopes requested.
	Scopes []string `json:"scopes"`

	// DPoPProof is the DPoP proof JWT (RFC 9449), required for DPoP-bound tokens.
	DPoPProof string `json:"dpop_proof,omitempty"`

	// TTL overrides the default token lifetime.
	TTL time.Duration `json:"ttl,omitempty"`
}

// AccessToken is a minted, short-lived access credential.
type AccessToken struct {
	// Token is the signed JWT access token.
	Token string `json:"access_token"`

	// TokenType is "Bearer" or "DPoP".
	TokenType string `json:"token_type"`

	// ExpiresIn is the token lifetime in seconds.
	ExpiresIn int64 `json:"expires_in"`

	// ExpiresAt is the absolute expiration time.
	ExpiresAt time.Time `json:"expires_at"`

	// Resource is the target resource this token is bound to.
	Resource string `json:"resource"`

	// Scopes are the granted scopes.
	Scopes []string `json:"scope"`

	// DPoPThumbprint is the JWK thumbprint of the DPoP key, if bound.
	DPoPThumbprint string `json:"dpop_thumbprint,omitempty"`

	// JTI is the unique token identifier for revocation.
	JTI string `json:"jti"`
}

// tokenClaims are the JWT claims for a minted access token.
type tokenClaims struct {
	jwt.RegisteredClaims
	AgentID        string   `json:"agent_id"`
	TenantID       string   `json:"tenant_id"`
	TaskID         string   `json:"task_id"`
	SessionID      string   `json:"session_id"`
	DeclaredIntent string   `json:"declared_intent"`
	Resource       string   `json:"resource"`
	Scopes         []string `json:"scp"`
	EnvelopeRef    string   `json:"envelope_ref"`
	DPoPThumbprint string   `json:"cnf_jkt,omitempty"` // RFC 9449 cnf claim
}

// CredentialBroker mints JIT credentials scoped to specific resources and agents.
type CredentialBroker struct {
	signingKey []byte
	issuer     string
	store      storage.TokenStore
	auditor    audit.Auditor
	dpop       *DPoPValidator
	log        *zap.Logger
}

// NewCredentialBroker creates a new credential broker.
func NewCredentialBroker(
	signingKey []byte,
	issuer string,
	store storage.TokenStore,
	auditor audit.Auditor,
	log *zap.Logger,
) *CredentialBroker {
	return &CredentialBroker{
		signingKey: signingKey,
		issuer:     issuer,
		store:      store,
		auditor:    auditor,
		dpop:       NewDPoPValidator(),
		log:        log,
	}
}

// MintToken creates a new short-lived, resource-scoped access token for the given
// agentic envelope. If a DPoP proof is provided, the token is cryptographically
// bound to the agent's private key per RFC 9449.
func (b *CredentialBroker) MintToken(ctx context.Context, req *MintTokenRequest) (*AccessToken, error) {
	if req.Envelope == nil {
		return nil, fmt.Errorf("envelope is required")
	}
	if req.Resource == "" {
		return nil, fmt.Errorf("resource is required")
	}
	if len(req.Scopes) == 0 {
		return nil, fmt.Errorf("at least one scope is required")
	}

	if req.Envelope.IsExpired() {
		return nil, fmt.Errorf("envelope has expired")
	}

	// Validate that the requested scopes are consistent with the envelope's tool scope
	if err := b.validateScopeAlignment(req.Envelope, req.Resource, req.Scopes); err != nil {
		return nil, fmt.Errorf("scope validation failed: %w", err)
	}

	ttl := req.TTL
	if ttl == 0 {
		ttl = DefaultTokenTTL
	}
	if ttl > MaxTokenTTL {
		return nil, fmt.Errorf("requested TTL %v exceeds maximum %v", ttl, MaxTokenTTL)
	}

	// Ensure token doesn't outlive the envelope
	envelopeExpiry := time.Unix(req.Envelope.ExpiresAt, 0)
	if time.Now().Add(ttl).After(envelopeExpiry) {
		ttl = time.Until(envelopeExpiry)
	}

	var dpopThumbprint string
	tokenType := TokenTypeBearer

	if req.DPoPProof != "" {
		// Validate the DPoP proof and extract the public key thumbprint
		thumbprint, err := b.dpop.ValidateProof(ctx, req.DPoPProof, "POST", b.issuer+"/token")
		if err != nil {
			return nil, fmt.Errorf("invalid DPoP proof: %w", err)
		}
		dpopThumbprint = thumbprint
		tokenType = TokenTypeDPoP
	}

	jti := uuid.New().String()
	now := time.Now().UTC()
	expiry := now.Add(ttl)

	// Hash of envelope JWTID for the envelope_ref claim
	envelopeRefHash := sha256sum(req.Envelope.JWTID)

	claims := &tokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    b.issuer,
			Subject:   req.Envelope.AgentID,
			Audience:  jwt.ClaimStrings{req.Resource},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiry),
			ID:        jti,
		},
		AgentID:        req.Envelope.AgentID,
		TenantID:       req.Envelope.TenantID,
		TaskID:         req.Envelope.TaskID,
		SessionID:      req.Envelope.SessionID,
		DeclaredIntent: req.Envelope.DeclaredIntent,
		Resource:       req.Resource,
		Scopes:         req.Scopes,
		EnvelopeRef:    envelopeRefHash,
		DPoPThumbprint: dpopThumbprint,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(b.signingKey)
	if err != nil {
		return nil, fmt.Errorf("signing access token: %w", err)
	}

	// Store token record for revocation lookups
	record := &storage.TokenRecord{
		JTI:            jti,
		AgentID:        req.Envelope.AgentID,
		TenantID:       req.Envelope.TenantID,
		Resource:       req.Resource,
		Scopes:         req.Scopes,
		DPoPThumbprint: dpopThumbprint,
		IssuedAt:       now,
		ExpiresAt:      expiry,
		Revoked:        false,
	}

	if err := b.store.StoreToken(ctx, record); err != nil {
		return nil, fmt.Errorf("storing token record: %w", err)
	}

	if err := b.auditor.Record(ctx, &audit.Event{
		AgentID:  req.Envelope.AgentID,
		Action:   audit.ActionTokenMinted,
		Resource: req.Resource,
		Decision: audit.DecisionAllow,
		Metadata: map[string]string{
			"tenant_id":  req.Envelope.TenantID,
			"task_id":    req.Envelope.TaskID,
			"token_type": tokenType,
			"jti":        jti,
		},
	}); err != nil {
		b.log.Warn("failed to record token mint audit event", zap.Error(err))
	}

	b.log.Info("minted access token",
		zap.String("agent_id", req.Envelope.AgentID),
		zap.String("resource", req.Resource),
		zap.String("token_type", tokenType),
		zap.String("jti", jti),
		zap.Time("expires_at", expiry),
	)

	return &AccessToken{
		Token:          signed,
		TokenType:      tokenType,
		ExpiresIn:      int64(ttl.Seconds()),
		ExpiresAt:      expiry,
		Resource:       req.Resource,
		Scopes:         req.Scopes,
		DPoPThumbprint: dpopThumbprint,
		JTI:            jti,
	}, nil
}

// RevokeToken immediately revokes an access token by JTI.
// The token is marked revoked in the store and will be rejected by all validators.
func (b *CredentialBroker) RevokeToken(ctx context.Context, jti string) error {
	if err := b.store.RevokeToken(ctx, jti); err != nil {
		return fmt.Errorf("revoking token %s: %w", jti, err)
	}

	b.log.Info("revoked access token", zap.String("jti", jti))
	return nil
}

// ValidateToken verifies a signed access token and checks it has not been revoked.
func (b *CredentialBroker) ValidateToken(ctx context.Context, tokenStr string) (*tokenClaims, error) {
	claims := &tokenClaims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return b.signingKey, nil
	}, jwt.WithExpirationRequired())
	if err != nil {
		return nil, fmt.Errorf("parsing access token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("access token is not valid")
	}

	// Check revocation store
	record, err := b.store.GetToken(ctx, claims.ID)
	if err != nil {
		return nil, fmt.Errorf("looking up token record: %w", err)
	}
	if record.Revoked {
		return nil, fmt.Errorf("token has been revoked")
	}

	return claims, nil
}

// validateScopeAlignment ensures the requested scopes are consistent with
// what the envelope's tool scope permits for the given resource.
func (b *CredentialBroker) validateScopeAlignment(
	env *envelope.AgenticEnvelope,
	resource string,
	scopes []string,
) error {
	for _, scope := range scopes {
		if !env.HasToolPermission(resource, scope) {
			return fmt.Errorf("scope %q for resource %q not permitted by envelope tool scope",
				scope, resource)
		}
	}
	return nil
}

// sha256sum returns the base64url-encoded SHA-256 hash of a string.
func sha256sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
