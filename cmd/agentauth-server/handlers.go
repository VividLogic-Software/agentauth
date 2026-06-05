package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/VividLogic-Software/agentauth/internal/broker"
	"github.com/VividLogic-Software/agentauth/internal/envelope"
	"github.com/VividLogic-Software/agentauth/internal/identity"
	"github.com/VividLogic-Software/agentauth/internal/policy"
)

// ── Helpers ────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{
		"error":   code,
		"message": message,
	})
}

func decodeBody(r *http.Request, dst interface{}) error {
	return json.NewDecoder(r.Body).Decode(dst)
}

// ── Identity handlers ──────────────────────────────────────────────────────

func (s *Server) handleIssueIdentity() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req identity.IssueIdentityRequest
		if err := decodeBody(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
			return
		}
		ident, err := s.svc.Issuer.IssueIdentity(r.Context(), &req)
		if err != nil {
			s.log.Error("issue identity failed", zap.Error(err))
			writeError(w, http.StatusBadRequest, "issue_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, ident)
	}
}

func (s *Server) handleGetIdentity() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID := chi.URLParam(r, "agentID")
		record, err := s.svc.Issuer.GetIdentity(r.Context(), agentID)
		if err != nil {
			writeError(w, http.StatusNotFound, "not_found", "identity not found")
			return
		}
		writeJSON(w, http.StatusOK, record)
	}
}

func (s *Server) handleRevokeIdentity() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID := chi.URLParam(r, "agentID")
		if err := s.svc.Issuer.RevokeIdentity(r.Context(), agentID); err != nil {
			s.log.Error("revoke identity failed", zap.String("agent_id", agentID), zap.Error(err))
			writeError(w, http.StatusBadRequest, "revoke_failed", err.Error())
			return
		}
		// Also revoke all tokens for the agent
		_ = s.svc.TokenStore.RevokeAllForAgent(r.Context(), agentID)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleRotateIdentity() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID := chi.URLParam(r, "agentID")
		newIdent, err := s.svc.Issuer.RotateCredentials(r.Context(), agentID)
		if err != nil {
			s.log.Error("rotate credentials failed", zap.String("agent_id", agentID), zap.Error(err))
			writeError(w, http.StatusBadRequest, "rotate_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, newIdent)
	}
}

func (s *Server) handleListIdentities() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.URL.Query().Get("tenant_id")
		if tenantID == "" {
			writeError(w, http.StatusBadRequest, "missing_param", "tenant_id query param is required")
			return
		}
		limit := 50
		offset := 0
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 {
				limit = n
			}
		}
		if o := r.URL.Query().Get("offset"); o != "" {
			if n, err := strconv.Atoi(o); err == nil && n >= 0 {
				offset = n
			}
		}
		records, err := s.svc.IdentityStore.ListIdentities(r.Context(), tenantID, limit, offset)
		if err != nil {
			s.log.Error("list identities failed", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "list_failed", "failed to list identities")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"items":  records,
			"limit":  limit,
			"offset": offset,
		})
	}
}

// ── Envelope handlers ──────────────────────────────────────────────────────

type createEnvelopeRequest struct {
	AgentID         string                      `json:"agent_id"`
	DelegatorID     string                      `json:"delegator_id"`
	TenantID        string                      `json:"tenant_id"`
	SessionID       string                      `json:"session_id"`
	DeclaredIntent  string                      `json:"declared_intent"`
	ToolScope       []envelope.ToolPermission   `json:"tool_scope"`
	ConsentRef      string                      `json:"consent_ref"`
	DelegationChain []string                    `json:"delegation_chain"`
	TTL             string                      `json:"ttl"`
}

func (s *Server) handleCreateEnvelope() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createEnvelopeRequest
		if err := decodeBody(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
			return
		}

		env := &envelope.AgenticEnvelope{
			AgentID:        req.AgentID,
			DelegatorID:    req.DelegatorID,
			TenantID:       req.TenantID,
			SessionID:      req.SessionID,
			DeclaredIntent: req.DeclaredIntent,
			ToolScope:      req.ToolScope,
		}

		opts := &envelope.EnvelopeOptions{
			ConsentRef:      req.ConsentRef,
			DelegationChain: req.DelegationChain,
		}
		if req.TTL != "" {
			if d, err := time.ParseDuration(req.TTL); err == nil {
				opts.TTL = d
			}
		}

		token, err := s.svc.EnvSigner.Sign(r.Context(), env, opts)
		if err != nil {
			s.log.Error("sign envelope failed", zap.Error(err))
			writeError(w, http.StatusBadRequest, "sign_failed", err.Error())
			return
		}

		writeJSON(w, http.StatusCreated, map[string]interface{}{
			"token":      token,
			"expires_at": time.Unix(env.ExpiresAt, 0).UTC(),
		})
	}
}

func (s *Server) handleVerifyEnvelope() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Token string `json:"token"`
		}
		if err := decodeBody(r, &body); err != nil || body.Token == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "token field is required")
			return
		}

		env, err := s.svc.EnvVerifier.Verify(r.Context(), body.Token)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"valid":  false,
				"reason": err.Error(),
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"valid":  true,
			"claims": env,
		})
	}
}

func (s *Server) handleDelegateEnvelope() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ParentToken    string                    `json:"parent_token"`
			SubAgentID     string                    `json:"sub_agent_id"`
			DeclaredIntent string                    `json:"declared_intent"`
			ToolScope      []envelope.ToolPermission `json:"tool_scope"`
			TTL            string                    `json:"ttl"`
		}
		if err := decodeBody(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
			return
		}

		// Verify the parent envelope
		parent, err := s.svc.EnvVerifier.Verify(r.Context(), req.ParentToken)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_parent", "parent token verification failed: "+err.Error())
			return
		}

		// Build child envelope — sub-agent gets a subset of parent's scope
		child := &envelope.AgenticEnvelope{
			AgentID:        req.SubAgentID,
			DelegatorID:    parent.AgentID,
			TenantID:       parent.TenantID,
			SessionID:      parent.SessionID,
			DeclaredIntent: req.DeclaredIntent,
			ToolScope:      req.ToolScope,
		}

		chain := append(parent.DelegationChain, req.ParentToken) //nolint:gocritic
		opts := &envelope.EnvelopeOptions{
			DelegationChain: chain,
		}
		if req.TTL != "" {
			if d, err := time.ParseDuration(req.TTL); err == nil {
				opts.TTL = d
			}
		}

		token, err := s.svc.EnvSigner.Sign(r.Context(), child, opts)
		if err != nil {
			s.log.Error("delegate envelope failed", zap.Error(err))
			writeError(w, http.StatusBadRequest, "delegate_failed", err.Error())
			return
		}

		writeJSON(w, http.StatusCreated, map[string]interface{}{
			"token":           token,
			"delegation_depth": len(chain),
			"expires_at":      time.Unix(child.ExpiresAt, 0).UTC(),
		})
	}
}

// ── Token handlers ─────────────────────────────────────────────────────────

func (s *Server) handleMintToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			EnvelopeToken string   `json:"envelope_token"`
			Resource      string   `json:"resource"`
			Scopes        []string `json:"scopes"`
			DPoPProof     string   `json:"dpop_proof"`
			TTL           string   `json:"ttl"`
		}
		if err := decodeBody(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
			return
		}

		env, err := s.svc.EnvVerifier.Verify(r.Context(), req.EnvelopeToken)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_envelope", "envelope verification failed: "+err.Error())
			return
		}

		// Evaluate policy before minting
		input := &policy.EvaluationInput{
			Agent: policy.AgentContext{
				ID:                env.AgentID,
				TenantID:          env.TenantID,
				DelegatorID:       env.DelegatorID,
				DeclaredIntent:    env.DeclaredIntent,
				DelegationDepth:   env.DelegationDepth(),
				EnvelopeExpiresAt: env.ExpiresAt,
			},
			Request: policy.RequestContext{
				Tool:      req.Resource,
				Operation: "token_request",
			},
			Tenant: policy.DefaultTenantConfig(env.TenantID),
			Now:    time.Now().Unix(),
		}
		result, err := s.svc.PolicyEngine.Evaluate(r.Context(), input)
		if err != nil || !result.Allowed {
			reason := "policy denied token request"
			if result != nil {
				reason = result.Reason
			}
			writeError(w, http.StatusForbidden, "policy_denied", reason)
			return
		}

		mintReq := &broker.MintTokenRequest{
			Envelope:  env,
			Resource:  req.Resource,
			Scopes:    req.Scopes,
			DPoPProof: req.DPoPProof,
		}
		if req.TTL != "" {
			if d, err := time.ParseDuration(req.TTL); err == nil {
				mintReq.TTL = d
			}
		}

		token, err := s.svc.Broker.MintToken(r.Context(), mintReq)
		if err != nil {
			s.log.Error("mint token failed", zap.Error(err))
			writeError(w, http.StatusBadRequest, "mint_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, token)
	}
}

func (s *Server) handleRevokeToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jti := chi.URLParam(r, "jti")
		if err := s.svc.Broker.RevokeToken(r.Context(), jti); err != nil {
			writeError(w, http.StatusBadRequest, "revoke_failed", err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleTokenExchange implements RFC 8693 token exchange.
func (s *Server) handleTokenExchange() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "could not parse form")
			return
		}
		subjectToken := r.FormValue("subject_token")
		requestedResource := r.FormValue("resource")
		scope := r.FormValue("scope")

		if subjectToken == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "subject_token is required")
			return
		}

		env, err := s.svc.EnvVerifier.Verify(r.Context(), subjectToken)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_token", "subject_token verification failed")
			return
		}

		scopes := []string{"read"}
		if scope != "" {
			scopes = []string{scope}
		}
		resource := requestedResource
		if resource == "" && len(env.ToolScope) > 0 {
			resource = env.ToolScope[0].Tool
		}

		token, err := s.svc.Broker.MintToken(r.Context(), &broker.MintTokenRequest{
			Envelope: env,
			Resource: resource,
			Scopes:   scopes,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, "exchange_failed", err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"access_token":       token.Token,
			"issued_token_type":  "urn:ietf:params:oauth:token-type:access_token",
			"token_type":         token.TokenType,
			"expires_in":         token.ExpiresIn,
		})
	}
}

// ── Audit handlers ─────────────────────────────────────────────────────────

func (s *Server) handleListAuditEvents() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fromStr := r.URL.Query().Get("from")
		toStr := r.URL.Query().Get("to")

		from := time.Now().Add(-24 * time.Hour)
		to := time.Now()

		if fromStr != "" {
			if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
				from = t
			}
		}
		if toStr != "" {
			if t, err := time.Parse(time.RFC3339, toStr); err == nil {
				to = t
			}
		}

		entries, err := s.svc.AuditLog.GetEntries(r.Context(), from, to)
		if err != nil {
			s.log.Error("list audit events failed", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "list_failed", "failed to list audit events")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"items": entries,
			"from":  from,
			"to":    to,
		})
	}
}

func (s *Server) handleVerifyAuditChain() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fromStr := r.URL.Query().Get("from")
		toStr := r.URL.Query().Get("to")

		from := time.Now().Add(-24 * time.Hour)
		to := time.Now()
		if fromStr != "" {
			if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
				from = t
			}
		}
		if toStr != "" {
			if t, err := time.Parse(time.RFC3339, toStr); err == nil {
				to = t
			}
		}

		result, err := s.svc.ChainVerifier.VerifyRange(r.Context(), from, to)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "verify_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

// ── Policy handlers ────────────────────────────────────────────────────────

func (s *Server) handleListPolicies() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"items": policy.BuiltinPolicies,
		})
	}
}

func (s *Server) handleCreatePolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var module policy.PolicyModule
		if err := decodeBody(r, &module); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
			return
		}
		if module.ID == "" || module.Source == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "id and source are required")
			return
		}
		s.svc.PolicyEngine.LoadPolicy(module)
		writeJSON(w, http.StatusCreated, module)
	}
}

func (s *Server) handleDeletePolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		policyID := chi.URLParam(r, "policyID")
		s.svc.PolicyEngine.RemovePolicy(policyID)
		w.WriteHeader(http.StatusNoContent)
	}
}
