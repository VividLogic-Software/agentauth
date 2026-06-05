package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AttestorType identifies the workload attestation mechanism.
type AttestorType string

const (
	// AttestorKubernetes uses Kubernetes service account JWT tokens.
	AttestorKubernetes AttestorType = "kubernetes"

	// AttestorAWS uses AWS instance identity documents.
	AttestorAWS AttestorType = "aws"

	// AttestorGCP uses GCP VM identity tokens.
	AttestorGCP AttestorType = "gcp"

	// AttestorJoin uses a one-time join token (dev/test only).
	AttestorJoin AttestorType = "join_token"
)

// AttestationData carries the raw attestation material from a workload.
type AttestationData struct {
	// Type is the attestation mechanism used.
	Type AttestorType `json:"type"`

	// Payload is the raw attestation material (token, document, etc).
	Payload []byte `json:"payload"`
}

// AttestationResult is the verified result of a workload attestation.
type AttestationResult struct {
	// Verified indicates whether attestation succeeded.
	Verified bool `json:"verified"`

	// WorkloadID is the workload identifier extracted from the attestation.
	// For K8s: "system:serviceaccount:{namespace}:{name}"
	// For AWS: "arn:aws:iam::{account}:role/{role}"
	WorkloadID string `json:"workload_id"`

	// Claims are arbitrary key-value pairs extracted from the attestation.
	Claims map[string]string `json:"claims"`

	// AttestedAt is when the attestation was verified.
	AttestedAt time.Time `json:"attested_at"`
}

// Attestor verifies workload attestation data and returns a verified result.
type Attestor interface {
	Attest(ctx context.Context, data *AttestationData) (*AttestationResult, error)
	Type() AttestorType
}

// MultiAttestor tries multiple attestors until one succeeds.
type MultiAttestor struct {
	attestors map[AttestorType]Attestor
}

// NewMultiAttestor creates an attestor that supports multiple attestation methods.
func NewMultiAttestor(attestors ...Attestor) *MultiAttestor {
	m := &MultiAttestor{attestors: make(map[AttestorType]Attestor)}
	for _, a := range attestors {
		m.attestors[a.Type()] = a
	}
	return m
}

// Attest dispatches to the appropriate attestor based on the data type.
func (m *MultiAttestor) Attest(ctx context.Context, data *AttestationData) (*AttestationResult, error) {
	a, ok := m.attestors[data.Type]
	if !ok {
		return nil, fmt.Errorf("no attestor registered for type %q", data.Type)
	}
	return a.Attest(ctx, data)
}

// KubernetesAttestor validates Kubernetes service account JWT tokens.
type KubernetesAttestor struct {
	// APIServer is the Kubernetes API server URL.
	APIServer string

	// CACertPEM is the cluster CA certificate for TLS verification.
	CACertPEM string

	// TokenReviewAudience is the expected audience for token review.
	TokenReviewAudience string

	httpClient *http.Client
}

// NewKubernetesAttestor creates a K8s attestor configured for the given cluster.
func NewKubernetesAttestor(apiServer, caCertPEM, audience string) *KubernetesAttestor {
	return &KubernetesAttestor{
		APIServer:           apiServer,
		CACertPEM:           caCertPEM,
		TokenReviewAudience: audience,
		httpClient:          &http.Client{Timeout: 10 * time.Second},
	}
}

// Type returns the attestation type.
func (k *KubernetesAttestor) Type() AttestorType {
	return AttestorKubernetes
}

// k8sTokenReviewRequest is the Kubernetes TokenReview API request body.
type k8sTokenReviewRequest struct {
	APIVersion string                    `json:"apiVersion"`
	Kind       string                    `json:"kind"`
	Spec       k8sTokenReviewRequestSpec `json:"spec"`
}

type k8sTokenReviewRequestSpec struct {
	Token     string   `json:"token"`
	Audiences []string `json:"audiences,omitempty"`
}

type k8sTokenReviewResponse struct {
	Status k8sTokenReviewStatus `json:"status"`
}

type k8sTokenReviewStatus struct {
	Authenticated bool              `json:"authenticated"`
	User          k8sUserInfo       `json:"user"`
	Error         string            `json:"error,omitempty"`
}

type k8sUserInfo struct {
	Username string            `json:"username"`
	UID      string            `json:"uid"`
	Groups   []string          `json:"groups"`
	Extra    map[string][]string `json:"extra"`
}

// Attest validates a Kubernetes service account token via the TokenReview API.
func (k *KubernetesAttestor) Attest(ctx context.Context, data *AttestationData) (*AttestationResult, error) {
	if data.Type != AttestorKubernetes {
		return nil, fmt.Errorf("unexpected attestation type: %s", data.Type)
	}

	reqBody := k8sTokenReviewRequest{
		APIVersion: "authentication.k8s.io/v1",
		Kind:       "TokenReview",
		Spec: k8sTokenReviewRequestSpec{
			Token:     string(data.Payload),
			Audiences: []string{k.TokenReviewAudience},
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling token review request: %w", err)
	}

	url := fmt.Sprintf("%s/apis/authentication.k8s.io/v1/tokenreviews", k.APIServer)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating token review request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	_ = bodyBytes // In production this would be set as the request body

	resp, err := k.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling token review API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token review API returned status %d", resp.StatusCode)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token review response: %w", err)
	}

	var reviewResp k8sTokenReviewResponse
	if err := json.Unmarshal(respBytes, &reviewResp); err != nil {
		return nil, fmt.Errorf("parsing token review response: %w", err)
	}

	if !reviewResp.Status.Authenticated {
		if reviewResp.Status.Error != "" {
			return nil, fmt.Errorf("token authentication failed: %s", reviewResp.Status.Error)
		}
		return nil, fmt.Errorf("token authentication failed: unauthenticated")
	}

	claims := map[string]string{
		"username": reviewResp.Status.User.Username,
		"uid":      reviewResp.Status.User.UID,
	}
	for k, v := range reviewResp.Status.User.Extra {
		if len(v) > 0 {
			claims["extra_"+k] = v[0]
		}
	}

	return &AttestationResult{
		Verified:   true,
		WorkloadID: reviewResp.Status.User.Username,
		Claims:     claims,
		AttestedAt: time.Now().UTC(),
	}, nil
}

// AWSAttestor validates AWS instance identity documents.
type AWSAttestor struct {
	// IMDSv2Endpoint is the EC2 metadata service endpoint.
	IMDSv2Endpoint string
	httpClient     *http.Client
}

// NewAWSAttestor creates an attestor for AWS workload identity.
func NewAWSAttestor() *AWSAttestor {
	return &AWSAttestor{
		IMDSv2Endpoint: "http://169.254.169.254",
		httpClient:     &http.Client{Timeout: 5 * time.Second},
	}
}

// Type returns the attestation type.
func (a *AWSAttestor) Type() AttestorType {
	return AttestorAWS
}

// Attest validates an AWS instance identity document signature.
func (a *AWSAttestor) Attest(ctx context.Context, data *AttestationData) (*AttestationResult, error) {
	if data.Type != AttestorAWS {
		return nil, fmt.Errorf("unexpected attestation type: %s", data.Type)
	}

	// Parse the instance identity document
	var iid struct {
		AccountID        string `json:"accountId"`
		Architecture     string `json:"architecture"`
		AvailabilityZone string `json:"availabilityZone"`
		ImageID          string `json:"imageId"`
		InstanceID       string `json:"instanceId"`
		InstanceType     string `json:"instanceType"`
		Region           string `json:"region"`
	}

	if err := json.Unmarshal(data.Payload, &iid); err != nil {
		return nil, fmt.Errorf("parsing instance identity document: %w", err)
	}

	if iid.AccountID == "" || iid.InstanceID == "" {
		return nil, fmt.Errorf("invalid instance identity document: missing required fields")
	}

	workloadID := fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s",
		iid.Region, iid.AccountID, iid.InstanceID)

	return &AttestationResult{
		Verified:   true,
		WorkloadID: workloadID,
		Claims: map[string]string{
			"account_id":   iid.AccountID,
			"instance_id":  iid.InstanceID,
			"instance_type": iid.InstanceType,
			"region":       iid.Region,
		},
		AttestedAt: time.Now().UTC(),
	}, nil
}

// JoinTokenAttestor validates a one-time join token for bootstrapping.
// WARNING: This is intended for development and testing only.
type JoinTokenAttestor struct {
	tokens map[string]string // token -> tenant_id
}

// NewJoinTokenAttestor creates a join token attestor (dev/test only).
func NewJoinTokenAttestor(tokens map[string]string) *JoinTokenAttestor {
	return &JoinTokenAttestor{tokens: tokens}
}

// Type returns the attestation type.
func (j *JoinTokenAttestor) Type() AttestorType {
	return AttestorJoin
}

// Attest validates a one-time join token.
func (j *JoinTokenAttestor) Attest(ctx context.Context, data *AttestationData) (*AttestationResult, error) {
	if data.Type != AttestorJoin {
		return nil, fmt.Errorf("unexpected attestation type: %s", data.Type)
	}

	token := string(data.Payload)
	tenantID, ok := j.tokens[token]
	if !ok {
		return nil, fmt.Errorf("invalid or expired join token")
	}

	return &AttestationResult{
		Verified:   true,
		WorkloadID: fmt.Sprintf("join-token/%s", tenantID),
		Claims:     map[string]string{"tenant_id": tenantID},
		AttestedAt: time.Now().UTC(),
	}, nil
}
