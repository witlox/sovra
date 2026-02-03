// Package mtls provides mTLS client certificate authentication.
package mtls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
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
	// ErrCertificateRevoked indicates the certificate has been revoked.
	ErrCertificateRevoked = errors.New("certificate revoked")
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

	// CRL configuration
	crlURLs       []string
	crlRefreshTTL time.Duration
	crlMu         sync.RWMutex
	crlCache      map[string]*cachedCRL
	crlHTTPClient *http.Client
}

// cachedCRL holds a cached CRL with expiry information.
type cachedCRL struct {
	crl       *x509.RevocationList
	fetchedAt time.Time
	serials   map[string]bool // revoked serial numbers for fast lookup
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithCRLURLs configures CRL URLs to check for revocation.
func WithCRLURLs(urls []string) VerifierOption {
	return func(v *Verifier) {
		v.crlURLs = urls
	}
}

// WithCRLRefreshTTL configures how long to cache CRLs.
func WithCRLRefreshTTL(ttl time.Duration) VerifierOption {
	return func(v *Verifier) {
		v.crlRefreshTTL = ttl
	}
}

// NewVerifier creates a new mTLS verifier.
func NewVerifier(trustedCAs *x509.CertPool, opts ...VerifierOption) *Verifier {
	v := &Verifier{
		trustedCAs:    trustedCAs,
		crlRefreshTTL: 1 * time.Hour,
		crlCache:      make(map[string]*cachedCRL),
		crlHTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
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
	return v.VerifyCertificateWithContext(r.Context(), r.TLS.PeerCertificates[0])
}

// VerifyCertificate verifies an X.509 certificate (uses background context for CRL).
func (v *Verifier) VerifyCertificate(cert *x509.Certificate) (*Identity, error) {
	return v.VerifyCertificateWithContext(context.Background(), cert)
}

// VerifyCertificateWithContext verifies an X.509 certificate with context for CRL fetching.
func (v *Verifier) VerifyCertificateWithContext(ctx context.Context, cert *x509.Certificate) (*Identity, error) {
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

	// Check CRL for revocation
	if len(v.crlURLs) > 0 {
		if revoked, err := v.isRevokedWithContext(ctx, cert); err != nil {
			return nil, fmt.Errorf("CRL check failed: %w", err)
		} else if revoked {
			return nil, ErrCertificateRevoked
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
	hash := sha256.Sum256(data)
	var result strings.Builder
	for i, b := range hash[:] {
		if i > 0 && i%2 == 0 {
			result.WriteString(":")
		}
		result.WriteString(fmt.Sprintf("%02X", b))
	}
	return result.String()
}

// isRevokedWithContext checks if a certificate is revoked according to configured CRLs.
func (v *Verifier) isRevokedWithContext(ctx context.Context, cert *x509.Certificate) (bool, error) {
	serialStr := cert.SerialNumber.String()

	for _, crlURL := range v.crlURLs {
		cached, err := v.getCRL(ctx, crlURL)
		if err != nil {
			// Log but continue to next CRL
			continue
		}
		if cached != nil && cached.serials[serialStr] {
			return true, nil
		}
	}
	return false, nil
}

// getCRL fetches and caches a CRL from the given URL.
func (v *Verifier) getCRL(ctx context.Context, crlURL string) (*cachedCRL, error) {
	// Check cache first
	v.crlMu.RLock()
	cached, ok := v.crlCache[crlURL]
	if ok && time.Since(cached.fetchedAt) < v.crlRefreshTTL {
		v.crlMu.RUnlock()
		return cached, nil
	}
	v.crlMu.RUnlock()

	// Fetch new CRL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, crlURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create CRL request: %w", err)
	}
	resp, err := v.crlHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch CRL: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRL fetch returned status %d", resp.StatusCode)
	}

	crlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read CRL response: %w", err)
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, fmt.Errorf("parse CRL: %w", err)
	}

	// Build serial number lookup
	serials := make(map[string]bool)
	for _, revoked := range crl.RevokedCertificateEntries {
		serials[revoked.SerialNumber.String()] = true
	}

	newCached := &cachedCRL{
		crl:       crl,
		fetchedAt: time.Now(),
		serials:   serials,
	}

	// Update cache
	v.crlMu.Lock()
	v.crlCache[crlURL] = newCached
	v.crlMu.Unlock()

	return newCached, nil
}

// AddCRLURL adds a CRL URL to check for revocation.
func (v *Verifier) AddCRLURL(url string) {
	v.crlMu.Lock()
	defer v.crlMu.Unlock()
	v.crlURLs = append(v.crlURLs, url)
}

// SetCRLRefreshTTL sets the CRL cache TTL.
func (v *Verifier) SetCRLRefreshTTL(ttl time.Duration) {
	v.crlMu.Lock()
	defer v.crlMu.Unlock()
	v.crlRefreshTTL = ttl
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
