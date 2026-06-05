// Package client provides the Go client library for the AgentAuth control plane API.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is the AgentAuth control plane API client.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// Option configures the AgentAuth client.
type Option func(*Client)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// WithTimeout sets the HTTP request timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

// WithAPIKey sets the API key used for authentication.
// Useful when constructing a client without a key upfront.
func WithAPIKey(key string) Option {
	return func(c *Client) {
		c.apiKey = key
	}
}

// New creates a new AgentAuth client.
func New(baseURL, apiKey string, opts ...Option) *Client {
	c := &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// IssueIdentityRequest is the API request for issuing an agent identity.
type IssueIdentityRequest struct {
	AgentID        string            `json:"agent_id,omitempty"`
	DelegatorID    string            `json:"delegator_id"`
	TenantID       string            `json:"tenant_id"`
	DeclaredIntent string            `json:"declared_intent"`
	TTL            string            `json:"ttl,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
}

// IssueIdentityResponse is the API response for issuing an agent identity.
type IssueIdentityResponse struct {
	ID             string    `json:"id"`
	SPIFFEID       string    `json:"spiffe_id"`
	CertificatePEM string    `json:"certificate_pem"`
	PrivateKeyPEM  string    `json:"private_key_pem"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// CreateEnvelopeRequest is the API request for creating an agentic envelope.
type CreateEnvelopeRequest struct {
	AgentID        string      `json:"agent_id"`
	DelegatorID    string      `json:"delegator_id"`
	TenantID       string      `json:"tenant_id"`
	SessionID      string      `json:"session_id,omitempty"`
	DeclaredIntent string      `json:"declared_intent"`
	ToolScope      []ToolScope `json:"tool_scope"`
	ConsentRef     string      `json:"consent_ref,omitempty"`
	TTL            string      `json:"ttl,omitempty"`
}

// ToolScope defines a tool permission for the envelope.
type ToolScope struct {
	Tool        string            `json:"tool"`
	Operations  []string          `json:"operations"`
	Constraints map[string]string `json:"constraints,omitempty"`
}

// CreateEnvelopeResponse is the API response for envelope creation.
type CreateEnvelopeResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// MintTokenRequest is the API request for minting an access token.
type MintTokenRequest struct {
	EnvelopeToken string   `json:"envelope_token"`
	Resource      string   `json:"resource"`
	Scopes        []string `json:"scopes"`
	DPoPProof     string   `json:"dpop_proof,omitempty"`
	TTL           string   `json:"ttl,omitempty"`
}

// MintTokenResponse is the API response for token minting.
type MintTokenResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresIn   int64     `json:"expires_in"`
	ExpiresAt   time.Time `json:"expires_at"`
	Resource    string    `json:"resource"`
	Scopes      []string  `json:"scope"`
}

// APIError represents an error response from the AgentAuth API.
type APIError struct {
	StatusCode int    `json:"-"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("agentauth API error %d: [%s] %s", e.StatusCode, e.Code, e.Message)
}

// IssueIdentity calls the AgentAuth API to issue a new agent identity.
func (c *Client) IssueIdentity(ctx context.Context, req *IssueIdentityRequest) (*IssueIdentityResponse, error) {
	var resp IssueIdentityResponse
	if err := c.post(ctx, "/v1/identities", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetIdentity retrieves an agent identity by ID.
func (c *Client) GetIdentity(ctx context.Context, agentID string) (*IssueIdentityResponse, error) {
	var resp IssueIdentityResponse
	if err := c.get(ctx, fmt.Sprintf("/v1/identities/%s", agentID), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RevokeIdentity revokes an agent identity.
func (c *Client) RevokeIdentity(ctx context.Context, agentID string) error {
	return c.post(ctx, fmt.Sprintf("/v1/identities/%s/revoke", agentID), nil, nil)
}

// CreateEnvelope creates a new signed agentic identity envelope.
func (c *Client) CreateEnvelope(ctx context.Context, req *CreateEnvelopeRequest) (*CreateEnvelopeResponse, error) {
	var resp CreateEnvelopeResponse
	if err := c.post(ctx, "/v1/envelopes", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// VerifyEnvelope verifies a signed envelope token and returns its claims.
func (c *Client) VerifyEnvelope(ctx context.Context, token string) (map[string]interface{}, error) {
	req := map[string]string{"token": token}
	var resp map[string]interface{}
	if err := c.post(ctx, "/v1/envelopes/verify", req, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// MintToken mints a short-lived, resource-scoped access token.
func (c *Client) MintToken(ctx context.Context, req *MintTokenRequest) (*MintTokenResponse, error) {
	var resp MintTokenResponse
	if err := c.post(ctx, "/v1/tokens", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RevokeToken immediately revokes an access token by JTI.
func (c *Client) RevokeToken(ctx context.Context, jti string) error {
	return c.post(ctx, fmt.Sprintf("/v1/tokens/%s/revoke", jti), nil, nil)
}

// DelegateToAgent creates a sub-agent envelope delegating permissions to another agent.
func (c *Client) DelegateToAgent(ctx context.Context, parentToken, subAgentID, intent string, scope []ToolScope) (*CreateEnvelopeResponse, error) {
	req := map[string]interface{}{
		"parent_envelope_token": parentToken,
		"sub_agent_id":          subAgentID,
		"declared_intent":       intent,
		"tool_scope":            scope,
	}
	var resp CreateEnvelopeResponse
	if err := c.post(ctx, "/v1/envelopes/delegate", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// post makes an authenticated POST request to the AgentAuth API.
func (c *Client) post(ctx context.Context, path string, body, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshaling request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	return c.do(req, result)
}

// get makes an authenticated GET request to the AgentAuth API.
func (c *Client) get(ctx context.Context, path string, result interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	return c.do(req, result)
}

// do executes an HTTP request and decodes the response.
func (c *Client) do(req *http.Request, result interface{}) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		var apiErr APIError
		apiErr.StatusCode = resp.StatusCode
		if err := json.Unmarshal(body, &apiErr); err != nil {
			apiErr.Message = string(body)
			apiErr.Code = "UNKNOWN"
		}
		return &apiErr
	}

	if result != nil && len(body) > 0 {
		if err := json.Unmarshal(body, result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}

	return nil
}
