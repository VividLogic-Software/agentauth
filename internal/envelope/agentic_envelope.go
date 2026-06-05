// Package envelope implements the Agentic Identity Envelope — a signed JWT-based
// structure that carries the complete authorization context for an AI agent,
// including its identity, delegation chain, declared intent, and tool scope.
package envelope

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	// EnvelopeVersion is the current envelope format version.
	EnvelopeVersion = "1"

	// DefaultEnvelopeTTL is the default lifetime for a new envelope.
	DefaultEnvelopeTTL = 15 * time.Minute

	// MaxEnvelopeTTL is the maximum allowed envelope lifetime.
	MaxEnvelopeTTL = 4 * time.Hour

	// MaxDelegationDepth is the maximum number of delegation hops allowed.
	MaxDelegationDepth = 8
)

// ToolPermission defines a specific tool and the operations allowed on it.
type ToolPermission struct {
	// Tool is the MCP tool name or resource URI pattern.
	// Examples: "filesystem.read", "github.issues.*", "postgres://db/table/orders"
	Tool string `json:"tool"`

	// Operations are the allowed operations on the tool.
	// Examples: ["read"], ["read", "write"], ["*"]
	Operations []string `json:"operations"`

	// Constraints are optional additional limits on the tool use.
	// Examples: {"max_rows": "1000", "read_only_schema": "public"}
	Constraints map[string]string `json:"constraints,omitempty"`
}

// AgenticEnvelope is the core authorization container for an AI agent.
// It is serialized as a signed JWT with custom claims and must be passed
// with every MCP tool call and A2A agent delegation.
type AgenticEnvelope struct {
	// DelegatorID is the SPIFFE ID of the entity that spawned this agent.
	// For top-level agents, this is the human user's identity.
	DelegatorID string `json:"delegator_id"`

	// AgentID is the SPIFFE SVID of the executing agent.
	AgentID string `json:"agent_id"`

	// TaskID is the unique identifier for this specific task execution.
	TaskID string `json:"task_id"`

	// TenantID scopes all authorization decisions to a specific tenant.
	TenantID string `json:"tenant_id"`

	// SessionID groups all envelopes in a single user session.
	SessionID string `json:"session_id"`

	// DeclaredIntent is a human-readable description of what the agent will do.
	// This is displayed in authorization UIs and audit logs.
	DeclaredIntent string `json:"declared_intent"`

	// ToolScope defines the tools this agent is authorized to use.
	ToolScope []ToolPermission `json:"tool_scope"`

	// ConsentRef is a reference to the recorded user consent for this task.
	ConsentRef string `json:"consent_ref,omitempty"`

	// DelegationChain contains the signed JWT of each parent envelope,
	// building a verifiable chain of custody from the root delegator.
	DelegationChain []string `json:"delegation_chain,omitempty"`

	// IssuedAt is the Unix timestamp when this envelope was created.
	IssuedAt int64 `json:"iat"`

	// ExpiresAt is the Unix timestamp when this envelope expires.
	ExpiresAt int64 `json:"exp"`

	// JWTID is the unique identifier for this envelope, used for revocation.
	JWTID string `json:"jti"`

	// Version is the envelope format version.
	Version string `json:"ver"`
}

// envelopeClaims wraps AgenticEnvelope as JWT claims.
type envelopeClaims struct {
	jwt.RegisteredClaims
	DelegatorID     string           `json:"delegator_id"`
	AgentID         string           `json:"agent_id"`
	TaskID          string           `json:"task_id"`
	TenantID        string           `json:"tenant_id"`
	SessionID       string           `json:"session_id"`
	DeclaredIntent  string           `json:"declared_intent"`
	ToolScope       []ToolPermission `json:"tool_scope"`
	ConsentRef      string           `json:"consent_ref,omitempty"`
	DelegationChain []string         `json:"delegation_chain,omitempty"`
	Version         string           `json:"ver"`
}

// EnvelopeOptions configures envelope creation.
type EnvelopeOptions struct {
	TTL             time.Duration
	ConsentRef      string
	DelegationChain []string
}

// Signer creates and signs Agentic Identity Envelopes.
type Signer struct {
	signingKey *ecdsa.PrivateKey
	issuer     string
}

// NewSigner creates a new envelope signer with the given ECDSA private key.
func NewSigner(signingKeyPEM string, issuer string) (*Signer, error) {
	block, _ := pem.Decode([]byte(signingKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode signing key PEM")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing signing key: %w", err)
	}

	return &Signer{signingKey: key, issuer: issuer}, nil
}

// Sign creates a new signed envelope JWT for the given envelope data.
func (s *Signer) Sign(ctx context.Context, env *AgenticEnvelope, opts *EnvelopeOptions) (string, error) {
	if env.AgentID == "" {
		return "", fmt.Errorf("agent_id is required")
	}
	if env.TenantID == "" {
		return "", fmt.Errorf("tenant_id is required")
	}
	if env.DeclaredIntent == "" {
		return "", fmt.Errorf("declared_intent is required")
	}
	if len(env.ToolScope) == 0 {
		return "", fmt.Errorf("tool_scope must not be empty")
	}

	if opts == nil {
		opts = &EnvelopeOptions{}
	}

	ttl := opts.TTL
	if ttl == 0 {
		ttl = DefaultEnvelopeTTL
	}
	if ttl > MaxEnvelopeTTL {
		return "", fmt.Errorf("TTL %v exceeds maximum %v", ttl, MaxEnvelopeTTL)
	}

	if len(opts.DelegationChain) > MaxDelegationDepth {
		return "", fmt.Errorf("delegation chain depth %d exceeds maximum %d",
			len(opts.DelegationChain), MaxDelegationDepth)
	}

	jwtID := uuid.New().String()
	now := time.Now().UTC()
	expiry := now.Add(ttl)

	if env.TaskID == "" {
		env.TaskID = uuid.New().String()
	}
	if env.SessionID == "" {
		env.SessionID = uuid.New().String()
	}
	if env.JWTID == "" {
		env.JWTID = jwtID
	}
	env.IssuedAt = now.Unix()
	env.ExpiresAt = expiry.Unix()
	env.Version = EnvelopeVersion

	claims := &envelopeClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   env.AgentID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiry),
			ID:        jwtID,
		},
		DelegatorID:     env.DelegatorID,
		AgentID:         env.AgentID,
		TaskID:          env.TaskID,
		TenantID:        env.TenantID,
		SessionID:       env.SessionID,
		DeclaredIntent:  env.DeclaredIntent,
		ToolScope:       env.ToolScope,
		ConsentRef:      opts.ConsentRef,
		DelegationChain: opts.DelegationChain,
		Version:         EnvelopeVersion,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signed, err := token.SignedString(s.signingKey)
	if err != nil {
		return "", fmt.Errorf("signing envelope: %w", err)
	}

	return signed, nil
}

// Verifier validates Agentic Identity Envelopes.
type Verifier struct {
	verifyKey *ecdsa.PublicKey
	issuer    string
}

// NewVerifier creates a new envelope verifier with the given ECDSA public key.
func NewVerifier(publicKeyPEM string, issuer string) (*Verifier, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode public key PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected ECDSA public key, got %T", pub)
	}

	return &Verifier{verifyKey: ecKey, issuer: issuer}, nil
}

// Verify parses and validates a signed envelope JWT, returning the claims.
func (v *Verifier) Verify(ctx context.Context, tokenStr string) (*AgenticEnvelope, error) {
	claims := &envelopeClaims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return v.verifyKey, nil
	},
		jwt.WithIssuer(v.issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("parsing envelope token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("envelope token is not valid")
	}

	return &AgenticEnvelope{
		DelegatorID:     claims.DelegatorID,
		AgentID:         claims.AgentID,
		TaskID:          claims.TaskID,
		TenantID:        claims.TenantID,
		SessionID:       claims.SessionID,
		DeclaredIntent:  claims.DeclaredIntent,
		ToolScope:       claims.ToolScope,
		ConsentRef:      claims.ConsentRef,
		DelegationChain: claims.DelegationChain,
		IssuedAt:        claims.IssuedAt.Unix(),
		ExpiresAt:       claims.ExpiresAt.Unix(),
		JWTID:           claims.ID,
		Version:         claims.Version,
	}, nil
}

// HasToolPermission checks whether the envelope grants the specified
// operation on the given tool.
func (e *AgenticEnvelope) HasToolPermission(tool, operation string) bool {
	for _, perm := range e.ToolScope {
		if matchesPattern(perm.Tool, tool) {
			for _, op := range perm.Operations {
				if op == "*" || op == operation {
					return true
				}
			}
		}
	}
	return false
}

// IsExpired returns true if the envelope has passed its expiration time.
func (e *AgenticEnvelope) IsExpired() bool {
	return time.Now().Unix() > e.ExpiresAt
}

// DelegationDepth returns the number of delegation hops in this envelope.
func (e *AgenticEnvelope) DelegationDepth() int {
	return len(e.DelegationChain)
}

// matchesPattern checks if a string matches a simple wildcard pattern.
// Supports * as a trailing wildcard (e.g., "github.issues.*").
func matchesPattern(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if pattern == value {
		return true
	}
	// Trailing wildcard
	if len(pattern) > 1 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(value) >= len(prefix) && value[:len(prefix)] == prefix
	}
	return false
}
