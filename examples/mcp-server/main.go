// Package main shows how to build an MCP server protected by AgentAuth.
// Every tool call is gated by envelope verification and OPA policy evaluation.
//
// Run:
//
//	go run ./examples/mcp-server
//	# Then call it with:
//	# curl -H "X-Agent-Envelope: <token>" http://localhost:3000/tools/filesystem/read
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/VividLogic-Software/agentauth/internal/audit"
	"github.com/VividLogic-Software/agentauth/internal/envelope"
	"github.com/VividLogic-Software/agentauth/internal/policy"
	mcpmiddleware "github.com/VividLogic-Software/agentauth/pkg/middleware"
)

func main() {
	// In production, load from environment variables or a secrets manager
	publicKeyPEM := os.Getenv("AGENTAUTH_PUBLIC_KEY_PEM")
	if publicKeyPEM == "" {
		log.Println("WARNING: AGENTAUTH_PUBLIC_KEY_PEM not set — using development mode (no signature verification)")
		publicKeyPEM = devPublicKeyPEM()
	}

	issuer := "agentauth"

	// Initialize the envelope verifier (offline — no server round-trip)
	verifier, err := envelope.NewVerifier(publicKeyPEM, issuer)
	if err != nil {
		log.Fatalf("failed to create envelope verifier: %v", err)
	}

	// Initialize the policy engine with built-in policies
	policyEngine := policy.NewEngine(policy.BuiltinPolicies, true)

	// Use a no-op auditor for this example (in production: use AuditLog backed by Postgres)
	auditor := &audit.NoopAuditor{}

	// Configure the MCP middleware
	mcpCfg := mcpmiddleware.MCPMiddlewareConfig{
		Verifier:        verifier,
		PolicyEngine:    policyEngine,
		Auditor:         auditor,
		RequireEnvelope: true,
		TenantConfig: func(tenantID string) policy.TenantContext {
			// In production: load from database
			return policy.DefaultTenantConfig(tenantID)
		},
		ExtractTool: func(r *http.Request) (tool, operation string) {
			// MCP convention: POST /tools/{category}/{tool_name}
			// We map this to tool = "{category}.{tool_name}", operation = "write"
			params := chi.RouteContext(r.Context())
			category := params.URLParam("category")
			toolName := params.URLParam("tool")
			tool = fmt.Sprintf("%s.%s", category, toolName)
			if r.Method == http.MethodGet {
				operation = "read"
			} else {
				operation = "write"
			}
			return tool, operation
		},
	}

	// Build the HTTP router
	router := chi.NewRouter()
	router.Use(chimiddleware.RequestID)
	router.Use(chimiddleware.Logger)
	router.Use(chimiddleware.Recoverer)

	// Health check — no auth required
	router.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	// MCP tool endpoints — all protected by AgentAuth
	router.Group(func(r chi.Router) {
		r.Use(mcpmiddleware.MCPMiddleware(mcpCfg))

		// Filesystem tools
		r.Get("/tools/filesystem/read", handleFilesystemRead)
		r.Post("/tools/filesystem/write", handleFilesystemWrite)

		// Database tools
		r.Post("/tools/database/query", handleDatabaseQuery)

		// GitHub tools
		r.Get("/tools/github/issues", handleGitHubListIssues)
		r.Post("/tools/github/issues", handleGitHubCreateIssue)

		// Generic pattern: POST /tools/{category}/{tool}
		r.Post("/tools/{category}/{tool}", handleGenericTool)
		r.Get("/tools/{category}/{tool}", handleGenericTool)
	})

	addr := ":3000"
	log.Printf("AgentAuth-protected MCP server starting on %s", addr)
	log.Printf("All tool calls require a valid X-Agent-Envelope header")
	log.Printf("Example: curl -H 'X-Agent-Envelope: <token>' http://localhost:3000/tools/filesystem/read")

	srv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

// ToolResponse is the standard MCP tool response format.
type ToolResponse struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data,omitempty"`
	Error   string          `json:"error,omitempty"`
	AgentID string          `json:"agent_id,omitempty"` // For debugging — shows who called
}

func handleFilesystemRead(w http.ResponseWriter, r *http.Request) {
	env := mcpmiddleware.EnvelopeFromContext(r.Context())

	path := r.URL.Query().Get("path")
	if path == "" {
		writeToolError(w, http.StatusBadRequest, "path parameter is required")
		return
	}

	log.Printf("[MCP] filesystem.read: agent=%s path=%s intent=%q",
		env.AgentID, path, env.DeclaredIntent)

	// Simulate file read
	data, _ := json.Marshal(map[string]string{
		"path":    path,
		"content": "file content here...",
	})

	writeToolResponse(w, http.StatusOK, data, env.AgentID)
}

func handleFilesystemWrite(w http.ResponseWriter, r *http.Request) {
	env := mcpmiddleware.EnvelopeFromContext(r.Context())

	var req struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeToolError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	log.Printf("[MCP] filesystem.write: agent=%s path=%s intent=%q",
		env.AgentID, req.Path, env.DeclaredIntent)

	data, _ := json.Marshal(map[string]interface{}{
		"path":    req.Path,
		"written": len(req.Content),
	})

	writeToolResponse(w, http.StatusOK, data, env.AgentID)
}

func handleDatabaseQuery(w http.ResponseWriter, r *http.Request) {
	env := mcpmiddleware.EnvelopeFromContext(r.Context())

	var req struct {
		Query  string `json:"query"`
		Limit  int    `json:"limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeToolError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	log.Printf("[MCP] database.query: agent=%s query=%q intent=%q",
		env.AgentID, req.Query, env.DeclaredIntent)

	data, _ := json.Marshal(map[string]interface{}{
		"rows":    []map[string]string{{"id": "1", "name": "Example"}},
		"count":   1,
		"elapsed": "2ms",
	})

	writeToolResponse(w, http.StatusOK, data, env.AgentID)
}

func handleGitHubListIssues(w http.ResponseWriter, r *http.Request) {
	env := mcpmiddleware.EnvelopeFromContext(r.Context())
	log.Printf("[MCP] github.issues.list: agent=%s", env.AgentID)

	data, _ := json.Marshal([]map[string]interface{}{
		{"number": 1, "title": "Fix agent auth bug", "state": "open"},
	})
	writeToolResponse(w, http.StatusOK, data, env.AgentID)
}

func handleGitHubCreateIssue(w http.ResponseWriter, r *http.Request) {
	env := mcpmiddleware.EnvelopeFromContext(r.Context())
	log.Printf("[MCP] github.issues.create: agent=%s", env.AgentID)

	data, _ := json.Marshal(map[string]interface{}{"number": 42, "status": "created"})
	writeToolResponse(w, http.StatusCreated, data, env.AgentID)
}

func handleGenericTool(w http.ResponseWriter, r *http.Request) {
	env := mcpmiddleware.EnvelopeFromContext(r.Context())
	category := chi.URLParam(r, "category")
	toolName := chi.URLParam(r, "tool")

	log.Printf("[MCP] %s.%s: agent=%s intent=%q",
		category, toolName, env.AgentID, env.DeclaredIntent)

	data, _ := json.Marshal(map[string]string{
		"tool":   fmt.Sprintf("%s.%s", category, toolName),
		"status": "executed",
	})
	writeToolResponse(w, http.StatusOK, data, env.AgentID)
}

func writeToolResponse(w http.ResponseWriter, status int, data json.RawMessage, agentID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := ToolResponse{
		Success: true,
		Data:    data,
		AgentID: agentID,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func writeToolError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := ToolResponse{Success: false, Error: message}
	_ = json.NewEncoder(w).Encode(resp)
}

// devPublicKeyPEM returns a placeholder public key for development.
// NEVER use this in production.
func devPublicKeyPEM() string {
	return `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDev_placeholder_key_for_dev_only
-----END PUBLIC KEY-----`
}
