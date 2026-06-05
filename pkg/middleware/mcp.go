// Package middleware provides drop-in HTTP middleware for protecting MCP servers
// and A2A agent endpoints with AgentAuth identity and authorization.
package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/VividLogic-Software/agentauth/internal/audit"
	"github.com/VividLogic-Software/agentauth/internal/envelope"
	"github.com/VividLogic-Software/agentauth/internal/policy"
	"go.uber.org/zap"
)

// contextKey is a private type for context keys to avoid collisions.
type contextKey string

const (
	// ContextKeyEnvelope is the context key for the verified AgenticEnvelope.
	ContextKeyEnvelope contextKey = "agentauth:envelope"

	// ContextKeyAgentID is the context key for the verified agent ID.
	ContextKeyAgentID contextKey = "agentauth:agent_id"

	// HeaderAgentEnvelope is the HTTP header carrying the AgenticEnvelope JWT.
	HeaderAgentEnvelope = "X-Agent-Envelope"

	// HeaderDPoP is the HTTP header carrying the DPoP proof JWT.
	HeaderDPoP = "DPoP"
)

// MCPMiddlewareConfig configures the MCP protection middleware.
type MCPMiddlewareConfig struct {
	// Verifier is used to validate incoming envelope JWTs.
	Verifier *envelope.Verifier

	// PolicyEngine evaluates authorization decisions.
	PolicyEngine *policy.Engine

	// Auditor records all authorization decisions.
	Auditor audit.Auditor

	// TenantConfig returns the tenant context for a given tenant ID.
	TenantConfig func(tenantID string) policy.TenantContext

	// ExtractTool extracts the MCP tool name and operation from the request.
	// If nil, uses the URL path and HTTP method as defaults.
	ExtractTool func(r *http.Request) (tool, operation string)

	// OnDeny is called when a request is denied. If nil, a 403 JSON response is sent.
	OnDeny func(w http.ResponseWriter, r *http.Request, reason string)

	// Log is the structured logger. If nil, a no-op logger is used.
	Log *zap.Logger

	// RequireEnvelope controls whether requests without an envelope are rejected.
	// Default: true
	RequireEnvelope bool
}

// MCPMiddleware returns an HTTP middleware that enforces AgentAuth authorization
// on every incoming MCP tool call.
//
// Usage:
//
//	router.Use(middleware.MCPMiddleware(middleware.MCPMiddlewareConfig{
//	    Verifier:     verifier,
//	    PolicyEngine: policyEngine,
//	    Auditor:      auditor,
//	}))
func MCPMiddleware(cfg MCPMiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Log == nil {
		cfg.Log, _ = zap.NewNop().Named("mcp-middleware"), error(nil)
	}
	if cfg.RequireEnvelope == false {
		cfg.RequireEnvelope = true
	}
	if cfg.TenantConfig == nil {
		cfg.TenantConfig = func(tenantID string) policy.TenantContext {
			return policy.DefaultTenantConfig(tenantID)
		}
	}
	if cfg.ExtractTool == nil {
		cfg.ExtractTool = defaultExtractTool
	}
	if cfg.OnDeny == nil {
		cfg.OnDeny = defaultOnDeny
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract the envelope from the request header
			envelopeToken := r.Header.Get(HeaderAgentEnvelope)
			if envelopeToken == "" {
				if cfg.RequireEnvelope {
					cfg.OnDeny(w, r, "missing X-Agent-Envelope header")
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Verify the envelope JWT signature and expiry
			env, err := cfg.Verifier.Verify(r.Context(), envelopeToken)
			if err != nil {
				cfg.Log.Warn("envelope verification failed",
					zap.Error(err),
					zap.String("remote_addr", r.RemoteAddr),
				)
				cfg.OnDeny(w, r, fmt.Sprintf("invalid envelope: %v", err))
				return
			}

			// Extract tool name and operation from the request
			tool, operation := cfg.ExtractTool(r)

			// Build the policy evaluation input
			toolScopeData := make([]map[string]interface{}, 0, len(env.ToolScope))
			for _, ts := range env.ToolScope {
				ops := make([]interface{}, len(ts.Operations))
				for i, op := range ts.Operations {
					ops[i] = op
				}
				toolScopeData = append(toolScopeData, map[string]interface{}{
					"tool":        ts.Tool,
					"operations":  ops,
					"constraints": ts.Constraints,
				})
			}

			tenantCtx := cfg.TenantConfig(env.TenantID)

			input := &policy.EvaluationInput{
				Agent: policy.AgentContext{
					ID:                env.AgentID,
					TenantID:          env.TenantID,
					DelegatorID:       env.DelegatorID,
					DeclaredIntent:    env.DeclaredIntent,
					ToolScope:         toolScopeData,
					DelegationDepth:   env.DelegationDepth(),
					EnvelopeExpiresAt: env.ExpiresAt,
				},
				Request: policy.RequestContext{
					Tool:      tool,
					Operation: operation,
					Resource:  r.URL.Path,
				},
				Tenant: tenantCtx,
				Now:    time.Now().Unix(),
			}

			// Evaluate policy
			result, err := cfg.PolicyEngine.Evaluate(r.Context(), input)
			if err != nil {
				cfg.Log.Error("policy evaluation error",
					zap.Error(err),
					zap.String("agent_id", env.AgentID),
				)
				cfg.OnDeny(w, r, "policy evaluation error")
				return
			}

			// Record the decision in the audit log
			decision := audit.DecisionAllow
			if !result.Allowed {
				decision = audit.DecisionDeny
			}

			_ = cfg.Auditor.Record(r.Context(), &audit.Event{
				AgentID:     env.AgentID,
				Action:      audit.ActionToolCall,
				Resource:    fmt.Sprintf("%s:%s", tool, operation),
				Decision:    decision,
				EnvelopeRef: env.JWTID,
				Metadata: map[string]string{
					"tenant_id": env.TenantID,
					"task_id":   env.TaskID,
					"path":      r.URL.Path,
					"method":    r.Method,
				},
			})

			if !result.Allowed {
				cfg.Log.Info("request denied by policy",
					zap.String("agent_id", env.AgentID),
					zap.String("tool", tool),
					zap.String("operation", operation),
					zap.String("reason", result.Reason),
				)
				cfg.OnDeny(w, r, result.Reason)
				return
			}

			// Inject the verified envelope into the request context
			ctx := context.WithValue(r.Context(), ContextKeyEnvelope, env)
			ctx = context.WithValue(ctx, ContextKeyAgentID, env.AgentID)

			cfg.Log.Debug("request authorized",
				zap.String("agent_id", env.AgentID),
				zap.String("tool", tool),
				zap.String("operation", operation),
				zap.String("declared_intent", env.DeclaredIntent),
			)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// EnvelopeFromContext retrieves the verified AgenticEnvelope from a request context.
// Returns nil if no envelope is present.
func EnvelopeFromContext(ctx context.Context) *envelope.AgenticEnvelope {
	env, _ := ctx.Value(ContextKeyEnvelope).(*envelope.AgenticEnvelope)
	return env
}

// AgentIDFromContext retrieves the verified agent ID from a request context.
func AgentIDFromContext(ctx context.Context) string {
	agentID, _ := ctx.Value(ContextKeyAgentID).(string)
	return agentID
}

// defaultExtractTool extracts the tool name and operation from standard MCP request paths.
// MCP tool calls follow the pattern: POST /tools/{tool_name}
func defaultExtractTool(r *http.Request) (tool, operation string) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 3)

	if len(parts) >= 2 && parts[0] == "tools" {
		tool = parts[1]
	} else {
		tool = path
	}

	switch r.Method {
	case http.MethodGet:
		operation = "read"
	case http.MethodPost:
		operation = "write"
	case http.MethodPut, http.MethodPatch:
		operation = "write"
	case http.MethodDelete:
		operation = "delete"
	default:
		operation = strings.ToLower(r.Method)
	}

	return tool, operation
}

// DenyResponse is the JSON body returned when a request is denied.
type DenyResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// defaultOnDeny sends a standard 403 JSON response.
func defaultOnDeny(w http.ResponseWriter, r *http.Request, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	resp := DenyResponse{
		Error:   "forbidden",
		Code:    "AGENT_AUTH_DENIED",
		Message: reason,
	}
	_ = json.NewEncoder(w).Encode(resp)
}
