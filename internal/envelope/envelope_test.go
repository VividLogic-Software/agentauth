package envelope

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

// generateTestKeyPair produces an ephemeral P-256 key pair for tests.
func generateTestKeyPair(t *testing.T) (privPEM, pubPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshaling private key: %v", err)
	}
	privPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}))

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}
	pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	return
}

func newTestSigner(t *testing.T) (*Signer, *Verifier) {
	t.Helper()
	priv, pub := generateTestKeyPair(t)
	signer, err := NewSigner(priv, "agentauth")
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	verifier, err := NewVerifier(pub, "agentauth")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return signer, verifier
}

func baseEnvelope() *AgenticEnvelope {
	return &AgenticEnvelope{
		AgentID:        "spiffe://agentauth.io/agent/acme/agent-1",
		DelegatorID:    "user:alice@acme.com",
		TenantID:       "acme",
		DeclaredIntent: "Process support tickets",
		ToolScope: []ToolPermission{
			{Tool: "zendesk.tickets.*", Operations: []string{"read", "write"}},
			{Tool: "filesystem.read", Operations: []string{"read"}},
		},
	}
}

// ---- matchesPattern ----

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"*", "anything", true},
		{"filesystem.read", "filesystem.read", true},
		{"filesystem.read", "filesystem.write", false},
		{"github.issues.*", "github.issues.create", true},
		{"github.issues.*", "github.issues", true},
		{"github.issues.*", "github.pulls.create", false},
		{"db.*", "db.query", true},
		{"db.*", "other.query", false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"/"+tt.value, func(t *testing.T) {
			if got := matchesPattern(tt.pattern, tt.value); got != tt.want {
				t.Errorf("matchesPattern(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

// ---- HasToolPermission ----

func TestHasToolPermission(t *testing.T) {
	env := baseEnvelope()

	tests := []struct {
		tool string
		op   string
		want bool
	}{
		{"zendesk.tickets.list", "read", true},
		{"zendesk.tickets.create", "write", true},
		{"filesystem.read", "read", true},
		{"filesystem.read", "write", false},
		{"github.issues.create", "write", false},
	}
	for _, tt := range tests {
		t.Run(tt.tool+"/"+tt.op, func(t *testing.T) {
			if got := env.HasToolPermission(tt.tool, tt.op); got != tt.want {
				t.Errorf("HasToolPermission(%q, %q) = %v, want %v", tt.tool, tt.op, got, tt.want)
			}
		})
	}
}

func TestHasToolPermission_WildcardOperation(t *testing.T) {
	env := &AgenticEnvelope{
		ToolScope: []ToolPermission{
			{Tool: "db.query", Operations: []string{"*"}},
		},
	}
	if !env.HasToolPermission("db.query", "delete") {
		t.Error("expected wildcard operation * to allow any operation")
	}
}

// ---- Sign / Verify round-trip ----

func TestSignVerifyRoundTrip(t *testing.T) {
	signer, verifier := newTestSigner(t)
	ctx := context.Background()

	env := baseEnvelope()
	token, err := signer.Sign(ctx, env, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	parsed, err := verifier.Verify(ctx, token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if parsed.AgentID != env.AgentID {
		t.Errorf("AgentID: got %q, want %q", parsed.AgentID, env.AgentID)
	}
	if parsed.TenantID != env.TenantID {
		t.Errorf("TenantID: got %q, want %q", parsed.TenantID, env.TenantID)
	}
	if parsed.DelegatorID != env.DelegatorID {
		t.Errorf("DelegatorID: got %q, want %q", parsed.DelegatorID, env.DelegatorID)
	}
	if parsed.Version != EnvelopeVersion {
		t.Errorf("Version: got %q, want %q", parsed.Version, EnvelopeVersion)
	}
	if len(parsed.ToolScope) != 2 {
		t.Errorf("ToolScope length: got %d, want 2", len(parsed.ToolScope))
	}
}

func TestSign_DefaultsTTL(t *testing.T) {
	signer, verifier := newTestSigner(t)
	ctx := context.Background()

	env := baseEnvelope()
	token, err := signer.Sign(ctx, env, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	parsed, err := verifier.Verify(ctx, token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Default TTL is 15 minutes — expiry should be ~15 min from now.
	remaining := time.Unix(parsed.ExpiresAt, 0).Sub(time.Now())
	if remaining < 14*time.Minute || remaining > 16*time.Minute {
		t.Errorf("expected ~15m TTL, got %v remaining", remaining)
	}
}

func TestSign_CustomTTL(t *testing.T) {
	signer, verifier := newTestSigner(t)
	ctx := context.Background()

	env := baseEnvelope()
	token, err := signer.Sign(ctx, env, &EnvelopeOptions{TTL: 30 * time.Minute})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	parsed, err := verifier.Verify(ctx, token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	remaining := time.Unix(parsed.ExpiresAt, 0).Sub(time.Now())
	if remaining < 29*time.Minute || remaining > 31*time.Minute {
		t.Errorf("expected ~30m TTL, got %v remaining", remaining)
	}
}

func TestSign_RejectsExceededTTL(t *testing.T) {
	signer, _ := newTestSigner(t)
	_, err := signer.Sign(context.Background(), baseEnvelope(), &EnvelopeOptions{
		TTL: MaxEnvelopeTTL + time.Minute,
	})
	if err == nil {
		t.Fatal("expected error for TTL exceeding maximum")
	}
}

func TestSign_RejectsMissingAgentID(t *testing.T) {
	signer, _ := newTestSigner(t)
	env := baseEnvelope()
	env.AgentID = ""
	_, err := signer.Sign(context.Background(), env, nil)
	if err == nil {
		t.Fatal("expected error for missing agent_id")
	}
}

func TestSign_RejectsMissingTenantID(t *testing.T) {
	signer, _ := newTestSigner(t)
	env := baseEnvelope()
	env.TenantID = ""
	_, err := signer.Sign(context.Background(), env, nil)
	if err == nil {
		t.Fatal("expected error for missing tenant_id")
	}
}

func TestSign_RejectsEmptyToolScope(t *testing.T) {
	signer, _ := newTestSigner(t)
	env := baseEnvelope()
	env.ToolScope = nil
	_, err := signer.Sign(context.Background(), env, nil)
	if err == nil {
		t.Fatal("expected error for empty tool_scope")
	}
}

func TestSign_RejectsExcessiveDelegationDepth(t *testing.T) {
	signer, _ := newTestSigner(t)
	chain := make([]string, MaxDelegationDepth+1)
	for i := range chain {
		chain[i] = "jwt"
	}
	_, err := signer.Sign(context.Background(), baseEnvelope(), &EnvelopeOptions{
		DelegationChain: chain,
	})
	if err == nil {
		t.Fatal("expected error for delegation chain exceeding max depth")
	}
}

func TestSign_PopulatesTaskAndSessionIDs(t *testing.T) {
	signer, verifier := newTestSigner(t)
	ctx := context.Background()
	env := baseEnvelope()
	token, err := signer.Sign(ctx, env, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parsed, err := verifier.Verify(ctx, token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if parsed.TaskID == "" {
		t.Error("expected TaskID to be auto-populated")
	}
	if parsed.SessionID == "" {
		t.Error("expected SessionID to be auto-populated")
	}
}

func TestVerify_RejectsInvalidSignature(t *testing.T) {
	signer, _ := newTestSigner(t)
	_, verifier2 := newTestSigner(t) // different key pair
	ctx := context.Background()

	token, err := signer.Sign(ctx, baseEnvelope(), nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	_, err = verifier2.Verify(ctx, token)
	if err == nil {
		t.Fatal("expected error when verifying with wrong key")
	}
}

func TestAgenticEnvelope_IsExpired(t *testing.T) {
	env := &AgenticEnvelope{ExpiresAt: time.Now().Add(-1 * time.Second).Unix()}
	if !env.IsExpired() {
		t.Error("expected expired envelope to return true")
	}
}

func TestAgenticEnvelope_IsNotExpired(t *testing.T) {
	env := &AgenticEnvelope{ExpiresAt: time.Now().Add(time.Hour).Unix()}
	if env.IsExpired() {
		t.Error("expected future envelope to not be expired")
	}
}

func TestAgenticEnvelope_DelegationDepth(t *testing.T) {
	env := &AgenticEnvelope{}
	if env.DelegationDepth() != 0 {
		t.Error("expected 0 delegation depth for root envelope")
	}
	env.DelegationChain = []string{"jwt-1", "jwt-2", "jwt-3"}
	if env.DelegationDepth() != 3 {
		t.Errorf("expected delegation depth 3, got %d", env.DelegationDepth())
	}
}
