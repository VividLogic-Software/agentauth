// Package main demonstrates agent-to-agent (A2A) delegation with AgentAuth.
// It shows a root agent spawning a sub-agent with a restricted scope,
// and verifying the delegation chain at each hop.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/VividLogic-Software/agentauth/pkg/client"
)

func main() {
	serverURL := os.Getenv("AGENTAUTH_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}
	apiKey := os.Getenv("AGENTAUTH_API_KEY")

	c := client.New(serverURL, apiKey,
		client.WithTimeout(30*time.Second),
	)

	ctx := context.Background()

	fmt.Println("==============================================")
	fmt.Println("AgentAuth A2A Delegation Example")
	fmt.Println("==============================================")

	// --------------------------------------------------------
	// Step 1: Issue identity for the root agent (orchestrator)
	// --------------------------------------------------------
	fmt.Println("\n[1] Issuing root agent identity (orchestrator)...")
	rootIdentity, err := c.IssueIdentity(ctx, &client.IssueIdentityRequest{
		DelegatorID:    "user:alice@example.com",
		TenantID:       "acme-corp",
		DeclaredIntent: "Orchestrate data pipeline for monthly report",
		TTL:            "2h",
		Labels: map[string]string{
			"role": "orchestrator",
		},
	})
	if err != nil {
		log.Fatalf("issue root identity: %v", err)
	}
	fmt.Printf("  Root Agent ID:  %s\n", rootIdentity.ID)
	fmt.Printf("  SPIFFE ID:      %s\n", rootIdentity.SPIFFEID)

	// --------------------------------------------------------
	// Step 2: Create envelope for the root agent
	// --------------------------------------------------------
	fmt.Println("\n[2] Creating root agent envelope...")
	rootEnvelope, err := c.CreateEnvelope(ctx, &client.CreateEnvelopeRequest{
		AgentID:        rootIdentity.ID,
		DelegatorID:    "user:alice@example.com",
		TenantID:       "acme-corp",
		DeclaredIntent: "Orchestrate monthly report data pipeline",
		ToolScope: []client.ToolScope{
			{Tool: "database.*", Operations: []string{"read", "write"}},
			{Tool: "storage.*", Operations: []string{"read", "write"}},
			{Tool: "email.send", Operations: []string{"write"}},
			{Tool: "a2a.invoke", Operations: []string{"delegate"}},
		},
		TTL: "1h",
	})
	if err != nil {
		log.Fatalf("create root envelope: %v", err)
	}
	fmt.Printf("  Envelope (root): %s...\n", rootEnvelope.Token[:40])
	fmt.Printf("  Expires: %s\n", rootEnvelope.ExpiresAt)

	// --------------------------------------------------------
	// Step 3: Root agent delegates to a data-fetcher sub-agent
	// --------------------------------------------------------
	fmt.Println("\n[3] Root agent delegating to data-fetcher sub-agent...")
	fetcherIdentity, err := c.IssueIdentity(ctx, &client.IssueIdentityRequest{
		AgentID:        "data-fetcher-001",
		DelegatorID:    rootIdentity.ID,
		TenantID:       "acme-corp",
		DeclaredIntent: "Fetch raw data from source databases",
		TTL:            "30m",
		Labels:         map[string]string{"role": "data-fetcher"},
	})
	if err != nil {
		log.Fatalf("issue fetcher identity: %v", err)
	}

	// Delegate: sub-agent gets only read access to database (subset of root scope)
	fetcherEnvelope, err := c.DelegateToAgent(ctx,
		rootEnvelope.Token,
		fetcherIdentity.ID,
		"Fetch raw transaction data from the analytics database",
		[]client.ToolScope{
			{
				Tool:       "database.query",
				Operations: []string{"read"},
				Constraints: map[string]string{
					"schema":   "analytics",
					"max_rows": "100000",
				},
			},
		},
	)
	if err != nil {
		log.Fatalf("delegate to fetcher: %v", err)
	}
	fmt.Printf("  Fetcher envelope: %s...\n", fetcherEnvelope.Token[:40])
	fmt.Printf("  Delegation depth: 1\n")

	// --------------------------------------------------------
	// Step 4: Fetcher delegates to a transformer sub-sub-agent
	// --------------------------------------------------------
	fmt.Println("\n[4] Data-fetcher delegating to transformer sub-sub-agent...")
	transformerIdentity, err := c.IssueIdentity(ctx, &client.IssueIdentityRequest{
		AgentID:        "transformer-001",
		DelegatorID:    fetcherIdentity.ID,
		TenantID:       "acme-corp",
		DeclaredIntent: "Transform raw data into report format",
		TTL:            "20m",
		Labels:         map[string]string{"role": "transformer"},
	})
	if err != nil {
		log.Fatalf("issue transformer identity: %v", err)
	}

	// Transformer only needs to read the already-fetched data
	transformerEnvelope, err := c.DelegateToAgent(ctx,
		fetcherEnvelope.Token,
		transformerIdentity.ID,
		"Transform fetched records into aggregated report format",
		[]client.ToolScope{
			{
				Tool:       "database.query",
				Operations: []string{"read"},
				Constraints: map[string]string{
					"schema":   "analytics",
					"max_rows": "50000", // Further restricted from parent
				},
			},
		},
	)
	if err != nil {
		log.Fatalf("delegate to transformer: %v", err)
	}
	fmt.Printf("  Transformer envelope: %s...\n", transformerEnvelope.Token[:40])
	fmt.Printf("  Delegation depth: 2\n")

	// --------------------------------------------------------
	// Step 5: Verify delegation chain integrity
	// --------------------------------------------------------
	fmt.Println("\n[5] Verifying delegation chain...")
	claims, err := c.VerifyEnvelope(ctx, transformerEnvelope.Token)
	if err != nil {
		log.Fatalf("verify transformer envelope: %v", err)
	}

	delegationChain, ok := claims["delegation_chain"].([]interface{})
	if ok {
		fmt.Printf("  Delegation chain depth: %d\n", len(delegationChain))
		fmt.Printf("  Chain is cryptographically verified\n")
	}

	// --------------------------------------------------------
	// Step 6: Demonstrate scope escalation prevention
	// --------------------------------------------------------
	fmt.Println("\n[6] Attempting scope escalation (should fail)...")
	_, err = c.DelegateToAgent(ctx,
		fetcherEnvelope.Token,           // fetcher only has database.query/read
		"malicious-agent",
		"Escalate to full database write access",
		[]client.ToolScope{
			{Tool: "database.*", Operations: []string{"read", "write", "delete"}}, // EXCEEDS parent scope
		},
	)
	if err != nil {
		fmt.Printf("  Scope escalation blocked (correct!): %v\n", err)
	} else {
		fmt.Printf("  ERROR: scope escalation should have been blocked\n")
	}

	// --------------------------------------------------------
	// Step 7: Mint a JIT token for the transformer's database access
	// --------------------------------------------------------
	fmt.Println("\n[7] Minting JIT token for database access...")
	token, err := c.MintToken(ctx, &client.MintTokenRequest{
		EnvelopeToken: transformerEnvelope.Token,
		Resource:      "postgres://analytics-db/analytics",
		Scopes:        []string{"read"},
		TTL:           "5m",
	})
	if err != nil {
		log.Fatalf("mint token: %v", err)
	}
	fmt.Printf("  Token type: %s\n", token.TokenType)
	fmt.Printf("  Expires in: %ds\n", token.ExpiresIn)
	fmt.Printf("  Resource: %s\n", token.Resource)
	fmt.Printf("  JTI: %s\n", token.JTI)

	// --------------------------------------------------------
	// Summary
	// --------------------------------------------------------
	fmt.Println("\n==============================================")
	fmt.Println("A2A Delegation Chain Summary:")
	fmt.Printf("  user:alice@example.com\n")
	fmt.Printf("    └── %s (orchestrator, 1h TTL)\n", rootIdentity.ID)
	fmt.Printf("          └── %s (fetcher, 30m TTL, db/read)\n", fetcherIdentity.ID)
	fmt.Printf("                └── %s (transformer, 20m TTL, db/read 50k rows)\n", transformerIdentity.ID)
	fmt.Println("\nAll delegation hops are cryptographically signed and verifiable.")
	fmt.Println("All actions are recorded in the tamper-evident audit log.")
	fmt.Println("==============================================")
}
