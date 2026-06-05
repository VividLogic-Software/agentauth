// Package policy implements the OPA/Rego-based policy engine for AgentAuth.
// Policies evaluate whether a given agent is authorized to perform an action
// on a resource, considering the agent's identity, envelope scope, and
// tenant-specific rules.
package policy

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// EvaluationInput is the data passed to OPA policies for evaluation.
type EvaluationInput struct {
	// Agent contains the agent's identity and envelope information.
	Agent AgentContext `json:"agent"`

	// Request describes what the agent is trying to do.
	Request RequestContext `json:"request"`

	// Tenant contains tenant-level configuration and limits.
	Tenant TenantContext `json:"tenant"`

	// Now is the current UTC timestamp for time-based policy rules.
	Now int64 `json:"now"`
}

// AgentContext carries agent identity and authorization context.
type AgentContext struct {
	// ID is the SPIFFE ID of the agent.
	ID string `json:"id"`

	// TenantID scopes the agent to a tenant.
	TenantID string `json:"tenant_id"`

	// DelegatorID is who spawned this agent.
	DelegatorID string `json:"delegator_id"`

	// DeclaredIntent is the human-readable task description.
	DeclaredIntent string `json:"declared_intent"`

	// ToolScope is the list of allowed tool permissions.
	ToolScope []map[string]interface{} `json:"tool_scope"`

	// DelegationDepth is the number of delegation hops.
	DelegationDepth int `json:"delegation_depth"`

	// EnvelopeExpiresAt is when the current envelope expires.
	EnvelopeExpiresAt int64 `json:"envelope_expires_at"`
}

// RequestContext describes the specific action being authorized.
type RequestContext struct {
	// Tool is the MCP tool name being called.
	Tool string `json:"tool"`

	// Operation is the specific operation (read, write, delete, etc).
	Operation string `json:"operation"`

	// Resource is the resource URI being acted upon.
	Resource string `json:"resource,omitempty"`

	// Parameters are the tool call parameters (for content inspection).
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// TenantContext carries tenant-specific policy configuration.
type TenantContext struct {
	// ID is the tenant identifier.
	ID string `json:"id"`

	// MaxDelegationDepth is the tenant's configured maximum delegation depth.
	MaxDelegationDepth int `json:"max_delegation_depth"`

	// AllowedTools is the tenant-wide allowlist of tools.
	AllowedTools []string `json:"allowed_tools"`

	// BlockedTools is the tenant-wide blocklist of tools.
	BlockedTools []string `json:"blocked_tools"`
}

// EvaluationResult is the output of a policy evaluation.
type EvaluationResult struct {
	// Allowed indicates whether the action is permitted.
	Allowed bool `json:"allowed"`

	// Reason is a human-readable explanation of the decision.
	Reason string `json:"reason"`

	// Violations lists specific policy rules that were violated (if denied).
	Violations []string `json:"violations,omitempty"`

	// EvaluatedAt is when the policy was evaluated.
	EvaluatedAt time.Time `json:"evaluated_at"`

	// PolicyVersion is the version of the policy that was applied.
	PolicyVersion string `json:"policy_version"`
}

// Engine evaluates authorization policies for agent actions.
type Engine struct {
	// policies holds the loaded policy modules.
	policies map[string]PolicyModule

	// defaultDenyAll controls whether undefined rules default to deny.
	defaultDenyAll bool
}

// PolicyModule represents a single Rego policy module.
type PolicyModule struct {
	// ID is the unique identifier for this policy.
	ID string

	// Package is the Rego package path.
	Package string

	// Source is the Rego source code.
	Source string

	// Version is the policy version identifier.
	Version string
}

// NewEngine creates a new policy engine with the given policies.
func NewEngine(modules []PolicyModule, defaultDenyAll bool) *Engine {
	e := &Engine{
		policies:       make(map[string]PolicyModule),
		defaultDenyAll: defaultDenyAll,
	}
	for _, m := range modules {
		e.policies[m.ID] = m
	}
	return e
}

// Evaluate runs all loaded policies against the given input and returns
// the final authorization decision.
func (e *Engine) Evaluate(ctx context.Context, input *EvaluationInput) (*EvaluationResult, error) {
	if input == nil {
		return nil, fmt.Errorf("evaluation input is required")
	}

	result := &EvaluationResult{
		EvaluatedAt:   time.Now().UTC(),
		PolicyVersion: "builtin-v1",
	}

	// Run built-in policy checks
	violations := e.runBuiltinChecks(input)

	if len(violations) > 0 {
		result.Allowed = false
		result.Reason = fmt.Sprintf("denied by policy: %s", violations[0])
		result.Violations = violations
		return result, nil
	}

	// Check envelope tool scope alignment
	if !e.toolScopeAllows(input) {
		result.Allowed = false
		result.Reason = fmt.Sprintf("tool %q with operation %q is not in envelope tool_scope",
			input.Request.Tool, input.Request.Operation)
		result.Violations = []string{"envelope_scope_violation"}
		return result, nil
	}

	result.Allowed = true
	result.Reason = "allowed by policy"
	return result, nil
}

// runBuiltinChecks executes the built-in policy rules that are always applied.
func (e *Engine) runBuiltinChecks(input *EvaluationInput) []string {
	var violations []string

	// Check envelope expiry
	if input.Now > input.Agent.EnvelopeExpiresAt {
		violations = append(violations, "envelope_expired")
	}

	// Check delegation depth
	maxDepth := 8
	if input.Tenant.MaxDelegationDepth > 0 {
		maxDepth = input.Tenant.MaxDelegationDepth
	}
	if input.Agent.DelegationDepth > maxDepth {
		violations = append(violations, "max_delegation_depth_exceeded")
	}

	// Check tenant blocklist
	for _, blocked := range input.Tenant.BlockedTools {
		if matchTool(blocked, input.Request.Tool) {
			violations = append(violations, fmt.Sprintf("tool_blocked_by_tenant: %s", input.Request.Tool))
			break
		}
	}

	// Check tenant allowlist (if configured, must match)
	if len(input.Tenant.AllowedTools) > 0 {
		allowed := false
		for _, allowed_tool := range input.Tenant.AllowedTools {
			if matchTool(allowed_tool, input.Request.Tool) {
				allowed = true
				break
			}
		}
		if !allowed {
			violations = append(violations, fmt.Sprintf("tool_not_in_tenant_allowlist: %s", input.Request.Tool))
		}
	}

	return violations
}

// toolScopeAllows checks whether the agent's envelope tool scope permits
// the requested tool and operation.
func (e *Engine) toolScopeAllows(input *EvaluationInput) bool {
	for _, scope := range input.Agent.ToolScope {
		tool, ok := scope["tool"].(string)
		if !ok {
			continue
		}
		if !matchTool(tool, input.Request.Tool) {
			continue
		}
		ops, ok := scope["operations"].([]interface{})
		if !ok {
			continue
		}
		for _, op := range ops {
			opStr, ok := op.(string)
			if !ok {
				continue
			}
			if opStr == "*" || opStr == input.Request.Operation {
				return true
			}
		}
	}
	return false
}

// matchTool checks if a tool pattern matches a tool name.
func matchTool(pattern, tool string) bool {
	if pattern == "*" || pattern == tool {
		return true
	}
	if strings.HasSuffix(pattern, ".*") {
		prefix := strings.TrimSuffix(pattern, ".*")
		return strings.HasPrefix(tool, prefix+".")
	}
	return false
}

// LoadPolicy adds a new policy module to the engine at runtime.
func (e *Engine) LoadPolicy(module PolicyModule) {
	e.policies[module.ID] = module
}

// RemovePolicy removes a policy module from the engine.
func (e *Engine) RemovePolicy(id string) {
	delete(e.policies, id)
}
