//go:build e2e

// Package e2e contains end-to-end tests for AgentAuth.
// These tests run against a live AgentAuth server.
//
// Usage:
//
//	AGENTAUTH_SERVER_URL=http://localhost:8080 \
//	AGENTAUTH_API_KEY=dev-key \
//	go test -tags e2e ./test/e2e/...
package e2e

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/VividLogic-Software/agentauth/pkg/client"
)

func newClient(t *testing.T) *client.Client {
	t.Helper()
	serverURL := os.Getenv("AGENTAUTH_SERVER_URL")
	if serverURL == "" {
		t.Skip("AGENTAUTH_SERVER_URL not set; skipping e2e test")
	}
	apiKey := os.Getenv("AGENTAUTH_API_KEY")
	return client.New(serverURL, apiKey, client.WithTimeout(30*time.Second))
}

func TestE2EFullFlow(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()

	// Issue identity
	identity, err := c.IssueIdentity(ctx, &client.IssueIdentityRequest{
		DelegatorID:    "user:e2e-test@example.com",
		TenantID:       "e2e-test",
		DeclaredIntent: "End-to-end test agent",
		TTL:            "30m",
	})
	if err != nil {
		t.Fatalf("IssueIdentity: %v", err)
	}
	if identity.ID == "" {
		t.Fatal("expected non-empty agent ID")
	}
	t.Logf("issued identity: %s", identity.ID)

	// Create envelope
	env, err := c.CreateEnvelope(ctx, &client.CreateEnvelopeRequest{
		AgentID:        identity.ID,
		DelegatorID:    "user:e2e-test@example.com",
		TenantID:       "e2e-test",
		DeclaredIntent: "E2E test task",
		ToolScope: []client.ToolScope{
			{Tool: "test.tool", Operations: []string{"read"}},
		},
		TTL: "15m",
	})
	if err != nil {
		t.Fatalf("CreateEnvelope: %v", err)
	}
	if env.Token == "" {
		t.Fatal("expected non-empty envelope token")
	}
	t.Logf("created envelope (expires: %s)", env.ExpiresAt)

	// Verify envelope
	claims, err := c.VerifyEnvelope(ctx, env.Token)
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
	t.Logf("verified envelope claims: %v", claims)

	// Mint token
	token, err := c.MintToken(ctx, &client.MintTokenRequest{
		EnvelopeToken: env.Token,
		Resource:      "https://api.example.com/test",
		Scopes:        []string{"read"},
		TTL:           "5m",
	})
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	if token.AccessToken == "" {
		t.Fatal("expected non-empty access token")
	}
	t.Logf("minted token (type: %s, expires_in: %ds)", token.TokenType, token.ExpiresIn)

	// Delegate to sub-agent
	subEnv, err := c.DelegateToAgent(ctx,
		env.Token,
		"e2e-sub-agent",
		"E2E sub-agent task",
		[]client.ToolScope{
			{Tool: "test.tool", Operations: []string{"read"}},
		},
	)
	if err != nil {
		t.Fatalf("DelegateToAgent: %v", err)
	}
	t.Logf("created sub-agent envelope: %s...", subEnv.Token[:20])

	// Revoke identity (cleanup)
	if err := c.RevokeIdentity(ctx, identity.ID); err != nil {
		t.Fatalf("RevokeIdentity: %v", err)
	}
	t.Logf("revoked identity %s", identity.ID)
}

func TestE2EScopeEscalationPrevented(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()

	identity, err := c.IssueIdentity(ctx, &client.IssueIdentityRequest{
		DelegatorID:    "user:e2e-test@example.com",
		TenantID:       "e2e-test",
		DeclaredIntent: "Scope escalation test",
		TTL:            "15m",
	})
	if err != nil {
		t.Fatalf("IssueIdentity: %v", err)
	}
	defer func() { _ = c.RevokeIdentity(ctx, identity.ID) }()

	// Create envelope with limited scope
	env, err := c.CreateEnvelope(ctx, &client.CreateEnvelopeRequest{
		AgentID:        identity.ID,
		TenantID:       "e2e-test",
		DeclaredIntent: "Limited scope test",
		ToolScope: []client.ToolScope{
			{Tool: "database.query", Operations: []string{"read"}},
		},
		TTL: "10m",
	})
	if err != nil {
		t.Fatalf("CreateEnvelope: %v", err)
	}

	// Attempt to delegate with a broader scope — should fail
	_, err = c.DelegateToAgent(ctx,
		env.Token,
		"escalation-attempt",
		"Attempting scope escalation",
		[]client.ToolScope{
			{Tool: "database.*", Operations: []string{"read", "write", "delete"}}, // Escalation!
		},
	)
	if err == nil {
		t.Fatal("expected scope escalation to be rejected, but it succeeded")
	}
	t.Logf("scope escalation correctly rejected: %v", err)
}
