// Command agentauth-cli is the command-line interface for the AgentAuth control plane.
// It provides commands for managing agent identities, envelopes, and tokens.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/VividLogic-Software/agentauth/pkg/client"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// CLI is the top-level CLI struct holding global flags and dependencies.
type CLI struct {
	// Flags
	serverURL string
	apiKey    string
	output    string // "json" or "text"
	verbose   bool

	// Dependencies
	client *client.Client
	log    *zap.Logger
}

func main() {
	cli := &CLI{}

	// Load config from environment or ~/.agentauth/config.yaml
	viper.SetEnvPrefix("AGENTAUTH")
	viper.AutomaticEnv()

	cli.serverURL = envOrDefault("AGENTAUTH_SERVER_URL", "http://localhost:8080")
	cli.apiKey = os.Getenv("AGENTAUTH_API_KEY")
	cli.output = envOrDefault("AGENTAUTH_OUTPUT", "text")

	log, _ := zap.NewDevelopment()
	cli.log = log
	defer log.Sync() //nolint:errcheck

	cli.client = client.New(cli.serverURL, cli.apiKey)

	if len(os.Args) < 2 {
		cli.printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "identity":
		cli.runIdentityCommand(args)
	case "envelope":
		cli.runEnvelopeCommand(args)
	case "token":
		cli.runTokenCommand(args)
	case "audit":
		cli.runAuditCommand(args)
	case "version":
		fmt.Println("agentauth-cli version 0.1.0")
	case "help", "--help", "-h":
		cli.printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		cli.printUsage()
		os.Exit(1)
	}
}

func (c *CLI) runIdentityCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: agentauth identity <issue|get|revoke|rotate|list>")
		return
	}

	switch args[0] {
	case "issue":
		c.issueIdentity(args[1:])
	case "get":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentauth identity get <agent-id>")
			os.Exit(1)
		}
		c.getIdentity(args[1])
	case "revoke":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentauth identity revoke <agent-id>")
			os.Exit(1)
		}
		c.revokeIdentity(args[1])
	default:
		fmt.Fprintf(os.Stderr, "unknown identity subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func (c *CLI) issueIdentity(args []string) {
	// Parse flags manually (in production, use pflag or cobra)
	tenantID := flagValue(args, "--tenant-id", "default")
	delegatorID := flagValue(args, "--delegator-id", "")
	intent := flagValue(args, "--intent", "CLI-issued agent identity")

	req := &client.IssueIdentityRequest{
		TenantID:       tenantID,
		DelegatorID:    delegatorID,
		DeclaredIntent: intent,
		TTL:            "1h",
	}

	resp, err := c.client.IssueIdentity(contextWithTimeout(30*time.Second), req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if c.output == "json" {
		printJSON(resp)
		return
	}

	fmt.Printf("Identity issued successfully:\n")
	fmt.Printf("  Agent ID:   %s\n", resp.ID)
	fmt.Printf("  SPIFFE ID:  %s\n", resp.SPIFFEID)
	fmt.Printf("  Expires At: %s\n", resp.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("\nCertificate written to stdout (save securely):\n")
	fmt.Println(resp.CertificatePEM)
}

func (c *CLI) getIdentity(agentID string) {
	resp, err := c.client.GetIdentity(contextWithTimeout(15*time.Second), agentID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if c.output == "json" {
		printJSON(resp)
		return
	}

	fmt.Printf("Identity: %s\n", resp.ID)
	fmt.Printf("  SPIFFE ID:  %s\n", resp.SPIFFEID)
	fmt.Printf("  Issued At:  %s\n", resp.IssuedAt.Format(time.RFC3339))
	fmt.Printf("  Expires At: %s\n", resp.ExpiresAt.Format(time.RFC3339))
}

func (c *CLI) revokeIdentity(agentID string) {
	if err := c.client.RevokeIdentity(contextWithTimeout(15*time.Second), agentID); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Identity %s revoked successfully.\n", agentID)
}

func (c *CLI) runEnvelopeCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: agentauth envelope <create|verify|delegate>")
		return
	}

	switch args[0] {
	case "create":
		c.createEnvelope(args[1:])
	case "verify":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentauth envelope verify <token>")
			os.Exit(1)
		}
		c.verifyEnvelope(args[1])
	default:
		fmt.Fprintf(os.Stderr, "unknown envelope subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func (c *CLI) createEnvelope(args []string) {
	agentID := flagValue(args, "--agent-id", "")
	if agentID == "" {
		fmt.Fprintln(os.Stderr, "error: --agent-id is required")
		os.Exit(1)
	}

	tenantID := flagValue(args, "--tenant-id", "default")
	intent := flagValue(args, "--intent", "")
	if intent == "" {
		fmt.Fprintln(os.Stderr, "error: --intent is required")
		os.Exit(1)
	}

	req := &client.CreateEnvelopeRequest{
		AgentID:        agentID,
		TenantID:       tenantID,
		DeclaredIntent: intent,
		ToolScope: []client.ToolScope{
			{Tool: "*", Operations: []string{"read"}},
		},
	}

	resp, err := c.client.CreateEnvelope(contextWithTimeout(30*time.Second), req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if c.output == "json" {
		printJSON(resp)
		return
	}

	fmt.Printf("Envelope created (expires %s):\n%s\n",
		resp.ExpiresAt.Format(time.RFC3339), resp.Token)
}

func (c *CLI) verifyEnvelope(token string) {
	claims, err := c.client.VerifyEnvelope(contextWithTimeout(15*time.Second), token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	printJSON(claims)
}

func (c *CLI) runTokenCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: agentauth token <mint|revoke>")
		return
	}

	switch args[0] {
	case "mint":
		c.mintToken(args[1:])
	case "revoke":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentauth token revoke <jti>")
			os.Exit(1)
		}
		if err := c.client.RevokeToken(contextWithTimeout(15*time.Second), args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Token %s revoked.\n", args[1])
	default:
		fmt.Fprintf(os.Stderr, "unknown token subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func (c *CLI) mintToken(args []string) {
	envelopeToken := flagValue(args, "--envelope", "")
	if envelopeToken == "" {
		fmt.Fprintln(os.Stderr, "error: --envelope is required")
		os.Exit(1)
	}
	resource := flagValue(args, "--resource", "")
	if resource == "" {
		fmt.Fprintln(os.Stderr, "error: --resource is required")
		os.Exit(1)
	}

	req := &client.MintTokenRequest{
		EnvelopeToken: envelopeToken,
		Resource:      resource,
		Scopes:        []string{"read"},
	}

	resp, err := c.client.MintToken(contextWithTimeout(30*time.Second), req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if c.output == "json" {
		printJSON(resp)
		return
	}

	fmt.Printf("Token minted (%s, expires in %ds):\n%s\n",
		resp.TokenType, resp.ExpiresIn, resp.AccessToken)
}

func (c *CLI) runAuditCommand(args []string) {
	fmt.Println("audit log commands: list, verify-chain")
}

func (c *CLI) printUsage() {
	fmt.Print(`AgentAuth CLI — The open-source identity & authorization plane for AI agents

Usage:
  agentauth <command> [subcommand] [flags]

Commands:
  identity    Manage agent identities (issue, get, revoke, rotate, list)
  envelope    Manage agentic envelopes (create, verify, delegate)
  token       Manage access tokens (mint, revoke)
  audit       Inspect the audit log (list, verify-chain)
  version     Show version information

Global Flags:
  --server-url    AgentAuth server URL (default: $AGENTAUTH_SERVER_URL or http://localhost:8080)
  --api-key       API key for authentication (default: $AGENTAUTH_API_KEY)
  --output        Output format: text or json (default: text)

Examples:
  # Issue a new agent identity
  agentauth identity issue --tenant-id my-org --intent "Process invoices"

  # Create an envelope for a task
  agentauth envelope create --agent-id <id> --intent "Summarize emails" --tenant-id my-org

  # Mint a token for a specific resource
  agentauth token mint --envelope <token> --resource https://api.github.com

  # Verify audit chain integrity
  agentauth audit verify-chain

Documentation: https://docs.agentauth.io
`)
}

// Helper functions

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func flagValue(args []string, flag, defaultVal string) string {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
		if len(arg) > len(flag)+1 && arg[:len(flag)+1] == flag+"=" {
			return arg[len(flag)+1:]
		}
	}
	return defaultVal
}

func printJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func contextWithTimeout(d time.Duration) interface{} {
	// Simplified — in production use context.WithTimeout
	return nil
}
