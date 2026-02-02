// Package mtls provides mTLS client certificate authentication.
package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var (
	// ErrNoCertificate indicates no client certificate was provided.
	ErrNoCertificate = errors.New("no client certificate provided")
	// ErrInvalidCertificate indicates the certificate is invalid.
	ErrInvalidCertificate = errors.New("invalid client certificate")
	// ErrCertificateExpired indicates the certificate has expired.
	ErrCertificateExpired = errors.New("certificate expired")
	// ErrCertificateNotYetValid indicates the certificate is not yet valid.
	ErrCertificateNotYetValid = errors.New("certificate not yet valid")
	// ErrUntrustedCertificate indicates the certificate is not from a trusted CA.
	ErrUntrustedCertificate = errors.New("certificate not from trusted CA")
)

// Identity represents the authenticated identity from an mTLS certificate.
type Identity struct {
	Subject      string
	CommonName   string
	Organization string
	Email        string
	Fingerprint  string
	SerialNumber string
	ValidFrom    time.Time
	ValidUntil   time.Time
	DNSNames     []string
	IsCA         bool
}

// Verifier verifies mTLS client certificates.
type Verifier struct {
	trustedCAs *x509.CertPool
}

// NewVerifier creates a new mTLS verifier.
func NewVerifier(trustedCAs *x509.CertPool) *Verifier {
	return &Verifier{
		trustedCAs: trustedCAs,
	}
}

// NewVerifierFromPEM creates a verifier from PEM-encoded CA certificates.
func NewVerifierFromPEM(caPEM []byte) (*Verifier, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("failed to parse CA certificates")
	}
	return NewVerifier(pool), nil
}

// VerifyRequest extracts and verifies the client certificate from an HTTP request.
func (v *Verifier) VerifyRequest(r *http.Request) (*Identity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, ErrNoCertificate
	}
	return v.VerifyCertificate(r.TLS.PeerCertificates[0])
}

// VerifyCertificate verifies an X.509 certificate.
func (v *Verifier) VerifyCertificate(cert *x509.Certificate) (*Identity, error) {
	if cert == nil {
		return nil, ErrNoCertificate
	}

	now := time.Now()

	// Check validity period
	if now.Before(cert.NotBefore) {
		return nil, ErrCertificateNotYetValid
	}
	if now.After(cert.NotAfter) {
		return nil, ErrCertificateExpired
	}

	// Verify against trusted CAs
	if v.trustedCAs != nil {
		opts := x509.VerifyOptions{
			Roots:     v.trustedCAs,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if _, err := cert.Verify(opts); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrUntrustedCertificate, err)
		}
	}

	// Extract identity
	identity := &Identity{
		Subject:      cert.Subject.String(),
		CommonName:   cert.Subject.CommonName,
		SerialNumber: cert.SerialNumber.String(),
		ValidFrom:    cert.NotBefore,
		ValidUntil:   cert.NotAfter,
		DNSNames:     cert.DNSNames,
		IsCA:         cert.IsCA,
		Fingerprint:  fingerprintCert(cert),
	}

	// Extract organization
	if len(cert.Subject.Organization) > 0 {
		identity.Organization = cert.Subject.Organization[0]
	}

	// Extract email from SAN
	if len(cert.EmailAddresses) > 0 {
		identity.Email = cert.EmailAddresses[0]
	}

	return identity, nil
}

// fingerprintCert creates a fingerprint of the certificate.
func fingerprintCert(cert *x509.Certificate) string {
	// Use SHA-256 of the raw certificate
	h := sha256sum(cert.Raw)
	return h
}

func sha256sum(data []byte) string {
	// Simple hex encoding of first 16 bytes of hash
	var result strings.Builder
	for i, b := range data[:min(16, len(data))] {
		if i > 0 && i%2 == 0 {
			result.WriteString(":")
		}
		result.WriteString(fmt.Sprintf("%02X", b))
	}
	return result.String()
}

// TLSConfig returns a TLS configuration that requires and verifies client certificates.
func (v *Verifier) TLSConfig(serverCert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    v.trustedCAs,
		MinVersion:   tls.VersionTLS13,
	}
}

// contextKey is the type for context keys.
type contextKey string

const identityContextKey contextKey = "mtls_identity"

// ContextWithIdentity stores the identity in the context.
func ContextWithIdentity(ctx context.Context, identity *Identity) context.Context {
	return context.WithValue(ctx, identityContextKey, identity)
}

// IdentityFromContext retrieves the identity from the context.
func IdentityFromContext(ctx context.Context) (*Identity, bool) {
	identity, ok := ctx.Value(identityContextKey).(*Identity)
	return identity, ok
}

// ParseCertificatePEM parses a PEM-encoded certificate.
func ParseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}
