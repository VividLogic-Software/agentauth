package broker

import (
	"context"
	"fmt"
	"time"

	"github.com/VividLogic-Software/agentauth/internal/envelope"
)

// TokenExchangeRequest represents an RFC 8693 token exchange request,
// adapted for agentic delegation scenarios.
type TokenExchangeRequest struct {
	// GrantType must be "urn:ietf:params:oauth:grant-type:token-exchange".
	GrantType string `json:"grant_type"`

	// SubjectToken is the token representing the identity being delegated from.
	SubjectToken string `json:"subject_token"`

	// SubjectTokenType identifies the type of the subject token.
	// Must be "urn:ietf:params:oauth:token-type:jwt" or
	// "urn:agentauth:token-type:envelope".
	SubjectTokenType string `json:"subject_token_type"`

	// ActorToken is the token representing the agent requesting delegation.
	ActorToken string `json:"actor_token,omitempty"`

	// ActorTokenType identifies the type of the actor token.
	ActorTokenType string `json:"actor_token_type,omitempty"`

	// Resource is the target resource (RFC 8707).
	Resource string `json:"resource,omitempty"`

	// Scopes are the requested scopes for the new token.
	Scopes []string `json:"scope,omitempty"`

	// RequestedTokenType specifies the desired token type.
	RequestedTokenType string `json:"requested_token_type,omitempty"`
}

// TokenExchangeResponse represents an RFC 8693 token exchange response.
type TokenExchangeResponse struct {
	// AccessToken is the newly issued token.
	AccessToken string `json:"access_token"`

	// IssuedTokenType identifies the type of the issued token.
	IssuedTokenType string `json:"issued_token_type"`

	// TokenType is "Bearer" or "DPoP".
	TokenType string `json:"token_type"`

	// ExpiresIn is the token lifetime in seconds.
	ExpiresIn int64 `json:"expires_in"`

	// Scopes are the granted scopes.
	Scopes []string `json:"scope,omitempty"`
}

const (
	// GrantTypeTokenExchange is the OAuth 2.0 token exchange grant type.
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

	// TokenTypeJWT is the token type URI for JWTs.
	TokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"

	// TokenTypeEnvelope is the AgentAuth-specific token type for envelopes.
	TokenTypeEnvelope = "urn:agentauth:token-type:envelope"

	// TokenTypeAccessToken is the token type URI for access tokens.
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
)

// TokenExchanger implements RFC 8693 token exchange for agent delegation.
type TokenExchanger struct {
	broker   *CredentialBroker
	verifier *envelope.Verifier
}

// NewTokenExchanger creates a new token exchanger.
func NewTokenExchanger(broker *CredentialBroker, verifier *envelope.Verifier) *TokenExchanger {
	return &TokenExchanger{broker: broker, verifier: verifier}
}

// Exchange performs an RFC 8693 token exchange, minting a new token for the
// requesting agent based on the subject's delegation.
func (e *TokenExchanger) Exchange(ctx context.Context, req *TokenExchangeRequest) (*TokenExchangeResponse, error) {
	if req.GrantType != GrantTypeTokenExchange {
		return nil, fmt.Errorf("unsupported grant_type: %q", req.GrantType)
	}

	if req.SubjectToken == "" {
		return nil, fmt.Errorf("subject_token is required")
	}

	// Parse the subject token as an agentic envelope
	var subjectEnvelope *envelope.AgenticEnvelope
	var err error

	switch req.SubjectTokenType {
	case TokenTypeEnvelope, TokenTypeJWT:
		subjectEnvelope, err = e.verifier.Verify(ctx, req.SubjectToken)
		if err != nil {
			return nil, fmt.Errorf("verifying subject token: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported subject_token_type: %q", req.SubjectTokenType)
	}

	if subjectEnvelope.IsExpired() {
		return nil, fmt.Errorf("subject token has expired")
	}

	// Mint a new access token bound to the subject envelope's scope
	resource := req.Resource
	if resource == "" && len(subjectEnvelope.ToolScope) > 0 {
		resource = subjectEnvelope.ToolScope[0].Tool
	}

	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"read"}
	}

	mintReq := &MintTokenRequest{
		Envelope:  subjectEnvelope,
		Resource:  resource,
		Scopes:    scopes,
		TTL:       DefaultTokenTTL,
	}

	token, err := e.broker.MintToken(ctx, mintReq)
	if err != nil {
		return nil, fmt.Errorf("minting exchanged token: %w", err)
	}

	requestedType := req.RequestedTokenType
	if requestedType == "" {
		requestedType = TokenTypeAccessToken
	}

	return &TokenExchangeResponse{
		AccessToken:     token.Token,
		IssuedTokenType: requestedType,
		TokenType:       token.TokenType,
		ExpiresIn:       int64(time.Until(token.ExpiresAt).Seconds()),
		Scopes:          token.Scopes,
	}, nil
}
