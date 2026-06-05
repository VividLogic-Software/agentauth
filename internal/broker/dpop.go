package broker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// DPoPMaxAge is the maximum age of a DPoP proof JWT before it is rejected.
	// This prevents replay attacks.
	DPoPMaxAge = 60 * time.Second

	// DPoPTokenType is the JWT type header value for DPoP proof JWTs.
	DPoPTokenType = "dpop+jwt"
)

// DPoPClaims represents the payload of a DPoP proof JWT per RFC 9449.
type DPoPClaims struct {
	jwt.RegisteredClaims

	// HTM is the HTTP method of the request the DPoP proof covers.
	HTM string `json:"htm"`

	// HTU is the HTTP URI of the request the DPoP proof covers (without query/fragment).
	HTU string `json:"htu"`

	// ATH is the base64url-encoded SHA-256 hash of the access token, if binding to a token.
	ATH string `json:"ath,omitempty"`
}

// DPoPValidator validates DPoP proof JWTs per RFC 9449.
type DPoPValidator struct {
	// nonces tracks seen JTI values to prevent replay attacks.
	// In production, this should be backed by Redis with TTL.
	nonces map[string]time.Time
}

// NewDPoPValidator creates a new DPoP validator.
func NewDPoPValidator() *DPoPValidator {
	return &DPoPValidator{
		nonces: make(map[string]time.Time),
	}
}

// ValidateProof validates a DPoP proof JWT for a given HTTP method and URI,
// returning the JWK thumbprint of the public key bound in the proof.
func (v *DPoPValidator) ValidateProof(ctx context.Context, proofJWT, method, uri string) (string, error) {
	// Parse without verification first to extract the header JWK
	parts, err := splitJWT(proofJWT)
	if err != nil {
		return "", fmt.Errorf("malformed DPoP proof: %w", err)
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("decoding DPoP header: %w", err)
	}

	var header struct {
		Type string          `json:"typ"`
		Alg  string          `json:"alg"`
		JWK  json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", fmt.Errorf("parsing DPoP header: %w", err)
	}

	if header.Type != DPoPTokenType {
		return "", fmt.Errorf("invalid DPoP typ header: expected %q, got %q", DPoPTokenType, header.Type)
	}

	if header.JWK == nil {
		return "", fmt.Errorf("DPoP proof missing jwk header")
	}

	// Extract the public key from the JWK
	pubKey, thumbprint, err := parseJWK(header.JWK)
	if err != nil {
		return "", fmt.Errorf("parsing DPoP JWK: %w", err)
	}

	// Now verify the signature using the embedded public key
	claims := &DPoPClaims{}
	token, err := jwt.ParseWithClaims(proofJWT, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("DPoP proof must use ECDSA signing, got %v", t.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		return "", fmt.Errorf("verifying DPoP proof signature: %w", err)
	}
	if !token.Valid {
		return "", fmt.Errorf("DPoP proof signature is invalid")
	}

	// Validate the htm and htu claims
	if claims.HTM != method {
		return "", fmt.Errorf("DPoP htm %q does not match request method %q", claims.HTM, method)
	}
	if claims.HTU != uri {
		return "", fmt.Errorf("DPoP htu %q does not match request URI %q", claims.HTU, uri)
	}

	// Validate the iat claim (proof freshness)
	if claims.IssuedAt == nil {
		return "", fmt.Errorf("DPoP proof missing iat claim")
	}
	age := time.Since(claims.IssuedAt.Time)
	if age > DPoPMaxAge {
		return "", fmt.Errorf("DPoP proof is too old: %v (max %v)", age, DPoPMaxAge)
	}
	if claims.IssuedAt.Time.After(time.Now().Add(5 * time.Second)) {
		return "", fmt.Errorf("DPoP proof issued in the future")
	}

	// Validate JTI uniqueness to prevent replay
	if claims.ID == "" {
		return "", fmt.Errorf("DPoP proof missing jti claim")
	}
	if _, seen := v.nonces[claims.ID]; seen {
		return "", fmt.Errorf("DPoP proof jti %q has already been used (replay attack)", claims.ID)
	}

	// Record the nonce with expiry
	v.nonces[claims.ID] = time.Now().Add(DPoPMaxAge * 2)

	// Periodically clean up old nonces (simplified - production would use Redis TTL)
	v.evictExpiredNonces()

	return thumbprint, nil
}

// ValidateTokenBinding verifies that a DPoP proof binds to the given access token.
func (v *DPoPValidator) ValidateTokenBinding(proofJWT, accessToken string) error {
	parts, err := splitJWT(proofJWT)
	if err != nil {
		return fmt.Errorf("malformed DPoP proof: %w", err)
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("decoding DPoP payload: %w", err)
	}

	var claims DPoPClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return fmt.Errorf("parsing DPoP claims: %w", err)
	}

	if claims.ATH == "" {
		return fmt.Errorf("DPoP proof missing ath claim for token binding")
	}

	// Compute SHA-256 of access token
	h := sha256.Sum256([]byte(accessToken))
	expected := base64.RawURLEncoding.EncodeToString(h[:])

	if claims.ATH != expected {
		return fmt.Errorf("DPoP ath claim does not match access token hash")
	}

	return nil
}

// parseJWK extracts an ECDSA public key and its JWK thumbprint from raw JWK JSON.
func parseJWK(raw json.RawMessage) (*ecdsa.PublicKey, string, error) {
	var jwk struct {
		KTY string `json:"kty"`
		CRV string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}

	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, "", fmt.Errorf("parsing JWK: %w", err)
	}

	if jwk.KTY != "EC" {
		return nil, "", fmt.Errorf("DPoP key must be EC, got %q", jwk.KTY)
	}

	var curve elliptic.Curve
	switch jwk.CRV {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	default:
		return nil, "", fmt.Errorf("unsupported curve %q", jwk.CRV)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, "", fmt.Errorf("decoding JWK x coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, "", fmt.Errorf("decoding JWK y coordinate: %w", err)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	// Compute JWK thumbprint per RFC 7638
	thumbprintInput := fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`,
		jwk.CRV, jwk.X, jwk.Y)
	h := sha256.Sum256([]byte(thumbprintInput))
	thumbprint := base64.RawURLEncoding.EncodeToString(h[:])

	return pubKey, thumbprint, nil
}

// splitJWT splits a JWT token string into its three parts.
func splitJWT(token string) ([]string, error) {
	parts := make([]string, 0, 3)
	start := 0
	count := 0
	for i, c := range token {
		if c == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
			count++
		}
	}
	parts = append(parts, token[start:])
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3 JWT parts, got %d", len(parts))
	}
	return parts, nil
}

// evictExpiredNonces removes expired nonce entries to prevent unbounded growth.
func (v *DPoPValidator) evictExpiredNonces() {
	now := time.Now()
	for jti, expiry := range v.nonces {
		if now.After(expiry) {
			delete(v.nonces, jti)
		}
	}
}
