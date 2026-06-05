package envelope

import (
	"context"
	"fmt"
	"time"
)

// DelegationRequest describes the parameters for creating a sub-agent delegation.
type DelegationRequest struct {
	// ParentEnvelopeToken is the signed JWT of the delegating (parent) agent's envelope.
	ParentEnvelopeToken string `json:"parent_envelope_token"`

	// SubAgentID is the SPIFFE ID of the agent being delegated to.
	SubAgentID string `json:"sub_agent_id"`

	// DeclaredIntent is the task description for the sub-agent.
	DeclaredIntent string `json:"declared_intent"`

	// ToolScope is the subset of tools the sub-agent may use.
	// Must be a subset of the parent's tool scope.
	ToolScope []ToolPermission `json:"tool_scope"`

	// TTL is the lifetime of the sub-agent envelope (must be <= parent's remaining TTL).
	TTL time.Duration `json:"ttl,omitempty"`

	// ConsentRef links the delegation to a consent record.
	ConsentRef string `json:"consent_ref,omitempty"`
}

// DelegationChainManager manages agent-to-agent delegation.
type DelegationChainManager struct {
	signer   *Signer
	verifier *Verifier
}

// NewDelegationChainManager creates a new delegation chain manager.
func NewDelegationChainManager(signer *Signer, verifier *Verifier) *DelegationChainManager {
	return &DelegationChainManager{signer: signer, verifier: verifier}
}

// Delegate creates a new sub-agent envelope that is scoped to a subset of
// the parent's permissions and carries the full delegation chain.
func (m *DelegationChainManager) Delegate(ctx context.Context, req *DelegationRequest) (string, error) {
	// Verify and parse the parent envelope
	parent, err := m.verifier.Verify(ctx, req.ParentEnvelopeToken)
	if err != nil {
		return "", fmt.Errorf("verifying parent envelope: %w", err)
	}

	if parent.IsExpired() {
		return "", fmt.Errorf("parent envelope has expired")
	}

	// Validate the delegation depth
	newDepth := parent.DelegationDepth() + 1
	if newDepth > MaxDelegationDepth {
		return "", fmt.Errorf("delegation depth %d would exceed maximum %d",
			newDepth, MaxDelegationDepth)
	}

	// Validate that sub-agent tool scope is a subset of the parent's scope
	if err := m.validateScopeSubset(parent.ToolScope, req.ToolScope); err != nil {
		return "", fmt.Errorf("invalid tool scope for sub-agent: %w", err)
	}

	// TTL must not exceed parent's remaining lifetime
	parentRemaining := time.Until(time.Unix(parent.ExpiresAt, 0))
	ttl := req.TTL
	if ttl == 0 {
		ttl = min(DefaultEnvelopeTTL, parentRemaining)
	}
	if ttl > parentRemaining {
		return "", fmt.Errorf("requested TTL %v exceeds parent's remaining lifetime %v",
			ttl, parentRemaining)
	}

	// Build the new delegation chain: append parent token to existing chain
	newChain := make([]string, 0, len(parent.DelegationChain)+1)
	newChain = append(newChain, parent.DelegationChain...)
	newChain = append(newChain, req.ParentEnvelopeToken)

	subEnvelope := &AgenticEnvelope{
		DelegatorID:    parent.AgentID,
		AgentID:        req.SubAgentID,
		TenantID:       parent.TenantID,
		SessionID:      parent.SessionID,
		DeclaredIntent: req.DeclaredIntent,
		ToolScope:      req.ToolScope,
	}

	opts := &EnvelopeOptions{
		TTL:             ttl,
		ConsentRef:      req.ConsentRef,
		DelegationChain: newChain,
	}

	token, err := m.signer.Sign(ctx, subEnvelope, opts)
	if err != nil {
		return "", fmt.Errorf("signing sub-agent envelope: %w", err)
	}

	return token, nil
}

// VerifyChain verifies the entire delegation chain in an envelope,
// ensuring each link is valid and each parent granted the claimed permissions.
func (m *DelegationChainManager) VerifyChain(ctx context.Context, envelopeToken string) ([]*AgenticEnvelope, error) {
	leaf, err := m.verifier.Verify(ctx, envelopeToken)
	if err != nil {
		return nil, fmt.Errorf("verifying leaf envelope: %w", err)
	}

	chain := []*AgenticEnvelope{leaf}

	for i, parentToken := range leaf.DelegationChain {
		parent, err := m.verifier.Verify(ctx, parentToken)
		if err != nil {
			return nil, fmt.Errorf("verifying delegation chain link %d: %w", i, err)
		}
		chain = append(chain, parent)
	}

	// Validate scope propagation through the chain
	for i := 0; i < len(chain)-1; i++ {
		child := chain[i]
		parent := chain[i+1]
		if err := m.validateScopeSubset(parent.ToolScope, child.ToolScope); err != nil {
			return nil, fmt.Errorf("scope escalation detected at chain link %d: %w", i, err)
		}
	}

	return chain, nil
}

// validateScopeSubset ensures that every permission in the requested scope
// is covered by the parent scope.
func (m *DelegationChainManager) validateScopeSubset(
	parentScope []ToolPermission,
	requestedScope []ToolPermission,
) error {
	for _, req := range requestedScope {
		granted := false
		for _, parent := range parentScope {
			if matchesPattern(parent.Tool, req.Tool) || matchesPattern(req.Tool, parent.Tool) {
				// Check that all requested operations are covered by the parent
				allOpsGranted := true
				for _, reqOp := range req.Operations {
					opGranted := false
					for _, parentOp := range parent.Operations {
						if parentOp == "*" || parentOp == reqOp {
							opGranted = true
							break
						}
					}
					if !opGranted {
						allOpsGranted = false
						break
					}
				}
				if allOpsGranted {
					granted = true
					break
				}
			}
		}
		if !granted {
			return fmt.Errorf("requested permission for tool %q with operations %v is not granted by parent scope",
				req.Tool, req.Operations)
		}
	}
	return nil
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
