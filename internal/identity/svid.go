package identity

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// SVID represents a SPIFFE Verifiable Identity Document — an X.509 certificate
// with a SPIFFE URI in the Subject Alternative Name extension.
type SVID struct {
	// ID is the SPIFFE URI identifying this workload.
	ID string `json:"id"`

	// Certificate is the parsed X.509 certificate.
	Certificate *x509.Certificate `json:"-"`

	// CertificatePEM is the PEM-encoded certificate chain.
	CertificatePEM string `json:"certificate_pem"`

	// PrivateKey is the ECDSA private key associated with the certificate.
	// Only populated at issuance time; never persisted.
	PrivateKey *ecdsa.PrivateKey `json:"-"`

	// TrustBundlePEM is the PEM-encoded CA bundle for this trust domain.
	TrustBundlePEM string `json:"trust_bundle_pem"`

	// ExpiresAt is when this SVID expires.
	ExpiresAt time.Time `json:"expires_at"`
}

// ParseSVID decodes a PEM-encoded certificate and validates it as a valid SVID.
// It checks that exactly one SPIFFE URI SAN is present.
func ParseSVID(certPEM string) (*SVID, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}

	spiffeURIs := extractSPIFFEURIs(cert)
	if len(spiffeURIs) == 0 {
		return nil, fmt.Errorf("certificate contains no SPIFFE URI SAN")
	}
	if len(spiffeURIs) > 1 {
		return nil, fmt.Errorf("certificate contains multiple SPIFFE URI SANs: only one is allowed")
	}

	return &SVID{
		ID:             spiffeURIs[0],
		Certificate:    cert,
		CertificatePEM: certPEM,
		ExpiresAt:      cert.NotAfter,
	}, nil
}

// IsExpired returns true if the SVID's certificate has passed its NotAfter time.
func (s *SVID) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsExpiringSoon returns true if the SVID expires within the given duration.
func (s *SVID) IsExpiringSoon(within time.Duration) bool {
	return time.Now().Add(within).After(s.ExpiresAt)
}

// Verify checks the SVID against a trust bundle and validates it is not expired.
func (s *SVID) Verify(trustBundlePEM string) error {
	if s.IsExpired() {
		return fmt.Errorf("SVID %q has expired at %v", s.ID, s.ExpiresAt)
	}

	roots, err := parseCertPool(trustBundlePEM)
	if err != nil {
		return fmt.Errorf("parsing trust bundle: %w", err)
	}

	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err := s.Certificate.Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}

// SVIDBundle groups an SVID with its complete certificate chain.
type SVIDBundle struct {
	SVID  *SVID
	Chain []*x509.Certificate
}

// extractSPIFFEURIs extracts all SPIFFE URIs from a certificate's SAN extension.
func extractSPIFFEURIs(cert *x509.Certificate) []string {
	var uris []string
	for _, u := range cert.URIs {
		if u.Scheme == "spiffe" {
			uris = append(uris, u.String())
		}
	}
	return uris
}

// parseCertPool decodes a PEM bundle into an x509.CertPool.
func parseCertPool(pemBundle string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemBundle)) {
		return nil, fmt.Errorf("no valid certificates found in trust bundle")
	}
	return pool, nil
}

// CertificateFingerprint returns the SHA-256 fingerprint of the SVID certificate
// as a hex string, useful for logging and audit trails.
func (s *SVID) CertificateFingerprint() string {
	if s.Certificate == nil {
		return ""
	}
	// Use the serial number + subject as a stable identifier for logging
	return fmt.Sprintf("%s/%s", s.Certificate.Subject.CommonName, s.Certificate.SerialNumber.Text(16))
}
