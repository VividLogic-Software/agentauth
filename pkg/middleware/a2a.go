package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/VividLogic-Software/agentauth/internal/audit"
	"github.com/VividLogic-Software/agentauth/internal/envelope"
	"github.com/VividLogic-Software/agentauth/internal/policy"
	"go.uber.org/zap"
)

const (
	// HeaderCallerEnvelope is the HTTP header carrying the calling agent's envelope.
	HeaderCallerEnvelope = "X-Caller-Envelope"

	// HeaderCallerID is the HTTP header carrying the calling agent's SPIFFE ID.
	HeaderCallerID = "X-Caller-ID"

	// ContextKeyCallerEnvelope is the context key for the caller's envelope.
	ContextKeyCallerEnvelope contextKey = "agentauth:caller_envelope"
)

// A2AMiddlewareConfig configures the agent-to-agent middleware.
type A2AMiddlewareConfig struct {
	// Verifier validates incoming agent envelope JWTs.
	Verifier *envelope.Verifier

	// DelegationManager verifies delegation chains.
	DelegationManager *envelope.DelegationChainManager

	// PolicyEngine evaluates authorization decisions.
	PolicyEngine *policy.Engine

	// Auditor records delegation events.
	Auditor audit.Auditor

	// TenantConfig returns the tenant context for a given tenant ID.
	TenantConfig func(tenantID string) policy.TenantContext

	// Log is the structured logger.
	Log *zap.Logger

	// MaxDelegationDepth limits how many hops are allowed. Default: 8.
	MaxDelegationDepth int

	// RequireCallerEnvelope controls whether requests without a caller envelope
	// are rejected. Default: true.
	RequireCallerEnvelope bool
}

// A2AMiddleware returns HTTP middleware that enforces AgentAuth identity verification
// on agent-to-agent (A2A) calls. It validates the calling agent's envelope and
// verifies the delegation chain before allowing the request to proceed.
//
// Usage:
//
//	// Sub-agent calls this endpoint; the middleware verifies the calling agent's identity
//	router.With(middleware.A2AMiddleware(a2aCfg)).Post("/agent/invoke", handleInvoke)
func A2AMiddleware(cfg A2AMiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Log == nil {
		cfg.Log, _ = zap.NewNop().Named("a2a-middleware"), error(nil)
	}
	if cfg.MaxDelegationDepth == 0 {
		cfg.MaxDelegationDepth = envelope.MaxDelegationDepth
	}
	if cfg.RequireCallerEnvelope == false {
		cfg.RequireCallerEnvelope = true
	}
	if cfg.TenantConfig == nil {
		cfg.TenantConfig = func(tenantID string) policy.TenantContext {
			return policy.DefaultTenantConfig(tenantID)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract the caller's envelope from headers
			callerToken := r.Header.Get(HeaderCallerEnvelope)
			if callerToken == "" {
				if cfg.RequireCallerEnvelope {
					writeA2ADenyResponse(w, "missing X-Caller-Envelope header", "MISSING_CALLER_ENVELOPE")
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Verify the caller's envelope
			callerEnv, err := cfg.Verifier.Verify(r.Context(), callerToken)
			if err != nil {
				cfg.Log.Warn("A2A caller envelope verification failed",
					zap.Error(err),
					zap.String("remote_addr", r.RemoteAddr),
				)
				writeA2ADenyResponse(w, fmt.Sprintf("invalid caller envelope: %v", err), "INVALID_CALLER_ENVELOPE")
				return
			}

			// Verify the delegation chain is intact and scopes don't escalate
			if cfg.DelegationManager != nil && len(callerEnv.DelegationChain) > 0 {
				chain, err := cfg.DelegationManager.VerifyChain(r.Context(), callerToken)
				if err != nil {
					cfg.Log.Warn("A2A delegation chain verification failed",
						zap.Error(err),
						zap.String("agent_id", callerEnv.AgentID),
					)
					writeA2ADenyResponse(w, fmt.Sprintf("invalid delegation chain: %v", err), "INVALID_DELEGATION_CHAIN")
					return
				}
				if len(chain) > cfg.MaxDelegationDepth {
					writeA2ADenyResponse(w, "delegation depth limit exceeded", "DELEGATION_DEPTH_EXCEEDED")
					return
				}
			}

			// Evaluate policy for the A2A delegation
			toolScopeData := make([]map[string]interface{}, 0, len(callerEnv.ToolScope))
			for _, ts := range callerEnv.ToolScope {
				ops := make([]interface{}, len(ts.Operations))
				for i, op := range ts.Operations {
					ops[i] = op
				}
				toolScopeData = append(toolScopeData, map[string]interface{}{
					"tool":       ts.Tool,
					"operations": ops,
				})
			}

			tenantCtx := cfg.TenantConfig(callerEnv.TenantID)

			input := &policy.EvaluationInput{
				Agent: policy.AgentContext{
					ID:                callerEnv.AgentID,
					TenantID:          callerEnv.TenantID,
					DelegatorID:       callerEnv.DelegatorID,
					DeclaredIntent:    callerEnv.DeclaredIntent,
					ToolScope:         toolScopeData,
					DelegationDepth:   callerEnv.DelegationDepth(),
					EnvelopeExpiresAt: callerEnv.ExpiresAt,
				},
				Request: policy.RequestContext{
					Tool:      "a2a.invoke",
					Operation: "delegate",
					Resource:  r.URL.Path,
				},
				Tenant: tenantCtx,
				Now:    time.Now().Unix(),
			}

			result, err := cfg.PolicyEngine.Evaluate(r.Context(), input)
			if err != nil {
				cfg.Log.Error("A2A policy evaluation error",
					zap.Error(err),
					zap.String("caller_id", callerEnv.AgentID),
				)
				writeA2ADenyResponse(w, "policy evaluation error", "POLICY_ERROR")
				return
			}

			// Record the delegation event
			decision := audit.DecisionAllow
			if !result.Allowed {
				decision = audit.DecisionDeny
			}

			_ = cfg.Auditor.Record(r.Context(), &audit.Event{
				AgentID:     callerEnv.AgentID,
				Action:      audit.ActionA2ADelegate,
				Resource:    r.URL.Path,
				Decision:    decision,
				EnvelopeRef: callerEnv.JWTID,
				Metadata: map[string]string{
					"tenant_id":        callerEnv.TenantID,
					"delegator_id":     callerEnv.DelegatorID,
					"delegation_depth": fmt.Sprintf("%d", callerEnv.DelegationDepth()),
					"declared_intent":  callerEnv.DeclaredIntent,
				},
			})

			if !result.Allowed {
				cfg.Log.Info("A2A request denied",
					zap.String("caller_id", callerEnv.AgentID),
					zap.String("reason", result.Reason),
				)
				writeA2ADenyResponse(w, result.Reason, "A2A_DENIED")
				return
			}

			// Inject caller context
			ctx := context.WithValue(r.Context(), ContextKeyCallerEnvelope, callerEnv)
			ctx = context.WithValue(ctx, ContextKeyAgentID, callerEnv.AgentID)

			cfg.Log.Debug("A2A request authorized",
				zap.String("caller_id", callerEnv.AgentID),
				zap.String("delegator_id", callerEnv.DelegatorID),
				zap.Int("delegation_depth", callerEnv.DelegationDepth()),
			)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CallerEnvelopeFromContext retrieves the caller's envelope from context.
func CallerEnvelopeFromContext(ctx context.Context) *envelope.AgenticEnvelope {
	env, _ := ctx.Value(ContextKeyCallerEnvelope).(*envelope.AgenticEnvelope)
	return env
}

// writeA2ADenyResponse sends a JSON 403 response for A2A denials.
func writeA2ADenyResponse(w http.ResponseWriter, reason, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	resp := DenyResponse{
		Error:   "a2a_forbidden",
		Code:    code,
		Message: reason,
	}
	_ = json.NewEncoder(w).Encode(resp)
}
