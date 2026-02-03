// Package mtls tests mTLS certificate verification.
package mtls_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/witlox/sovra/internal/auth/mtls"
)

// generateCA creates a self-signed CA certificate for testing.
func generateCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return cert, privateKey, certPEM
}

// generateClientCert creates a client certificate signed by the CA.
func generateClientCert(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, org, cn string, valid bool) *x509.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	var notBefore, notAfter time.Time
	if valid {
		notBefore = time.Now().Add(-time.Hour)
		notAfter = time.Now().Add(24 * time.Hour)
	} else {
		notBefore = time.Now().Add(-48 * time.Hour)
		notAfter = time.Now().Add(-24 * time.Hour) // Expired
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   cn,
		},
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		EmailAddresses: []string{"test@example.com"},
		DNSNames:       []string{"client.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &privateKey.PublicKey, caKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func TestNewVerifier(t *testing.T) {
	pool := x509.NewCertPool()
	verifier := mtls.NewVerifier(pool)
	require.NotNil(t, verifier)
}

func TestNewVerifierFromPEM(t *testing.T) {
	_, _, caPEM := generateCA(t)

	verifier, err := mtls.NewVerifierFromPEM(caPEM)
	require.NoError(t, err)
	require.NotNil(t, verifier)
}

func TestNewVerifierFromPEM_Invalid(t *testing.T) {
	_, err := mtls.NewVerifierFromPEM([]byte("invalid pem"))
	require.Error(t, err)
}

func TestVerifyCertificate_Valid(t *testing.T) {
	ca, caKey, caPEM := generateCA(t)
	clientCert := generateClientCert(t, ca, caKey, "Test Org", "test-user", true)

	verifier, err := mtls.NewVerifierFromPEM(caPEM)
	require.NoError(t, err)

	identity, err := verifier.VerifyCertificate(clientCert)
	require.NoError(t, err)
	require.NotNil(t, identity)

	assert.Equal(t, "test-user", identity.CommonName)
	assert.Equal(t, "Test Org", identity.Organization)
	assert.Equal(t, "test@example.com", identity.Email)
	assert.Contains(t, identity.DNSNames, "client.example.com")
	assert.False(t, identity.IsCA)
	assert.NotEmpty(t, identity.Fingerprint)
	assert.NotEmpty(t, identity.SerialNumber)
	assert.NotEmpty(t, identity.Subject)
}

func TestVerifyCertificate_Nil(t *testing.T) {
	verifier := mtls.NewVerifier(nil)
	_, err := verifier.VerifyCertificate(nil)
	assert.ErrorIs(t, err, mtls.ErrNoCertificate)
}

func TestVerifyCertificate_Expired(t *testing.T) {
	ca, caKey, caPEM := generateCA(t)
	expiredCert := generateClientCert(t, ca, caKey, "Test Org", "test-user", false)

	verifier, err := mtls.NewVerifierFromPEM(caPEM)
	require.NoError(t, err)

	_, err = verifier.VerifyCertificate(expiredCert)
	assert.ErrorIs(t, err, mtls.ErrCertificateExpired)
}

func TestVerifyCertificate_NoCA(t *testing.T) {
	ca, caKey, _ := generateCA(t)
	clientCert := generateClientCert(t, ca, caKey, "Test Org", "test-user", true)

	// Verifier with nil CA pool (no verification)
	verifier := mtls.NewVerifier(nil)
	identity, err := verifier.VerifyCertificate(clientCert)
	require.NoError(t, err)
	assert.Equal(t, "test-user", identity.CommonName)
}

func TestContextWithIdentity(t *testing.T) {
	identity := &mtls.Identity{
		CommonName:   "test-user",
		Organization: "Test Org",
		Email:        "test@example.com",
	}

	ctx := context.Background()
	ctx = mtls.ContextWithIdentity(ctx, identity)

	retrieved, ok := mtls.IdentityFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, identity.CommonName, retrieved.CommonName)
	assert.Equal(t, identity.Organization, retrieved.Organization)
}

func TestIdentityFromContext_NotFound(t *testing.T) {
	ctx := context.Background()
	identity, ok := mtls.IdentityFromContext(ctx)
	assert.False(t, ok)
	assert.Nil(t, identity)
}

func TestParseCertificatePEM(t *testing.T) {
	_, _, caPEM := generateCA(t)

	cert, err := mtls.ParseCertificatePEM(caPEM)
	require.NoError(t, err)
	assert.Equal(t, "Test CA", cert.Subject.CommonName)
}

func TestParseCertificatePEM_Invalid(t *testing.T) {
	_, err := mtls.ParseCertificatePEM([]byte("invalid pem"))
	require.Error(t, err)
}

func TestIdentity_Fields(t *testing.T) {
	now := time.Now()
	identity := mtls.Identity{
		Subject:      "CN=test,O=TestOrg",
		CommonName:   "test",
		Organization: "TestOrg",
		Email:        "test@example.com",
		Fingerprint:  "AA:BB:CC:DD",
		SerialNumber: "12345",
		ValidFrom:    now.Add(-time.Hour),
		ValidUntil:   now.Add(24 * time.Hour),
		DNSNames:     []string{"example.com", "*.example.com"},
		IsCA:         false,
	}

	assert.Equal(t, "test", identity.CommonName)
	assert.Equal(t, "TestOrg", identity.Organization)
	assert.Equal(t, "test@example.com", identity.Email)
	assert.Equal(t, "AA:BB:CC:DD", identity.Fingerprint)
	assert.Len(t, identity.DNSNames, 2)
	assert.False(t, identity.IsCA)
}

func TestErrorTypes(t *testing.T) {
	require.Error(t, mtls.ErrNoCertificate)
	require.Error(t, mtls.ErrInvalidCertificate)
	require.Error(t, mtls.ErrCertificateExpired)
	require.Error(t, mtls.ErrCertificateNotYetValid)
	require.Error(t, mtls.ErrUntrustedCertificate)
}

func TestMiddleware_NoCertificate(t *testing.T) {
	verifier := mtls.NewVerifier(nil)

	handler := mtls.Middleware(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestOptionalMiddleware_NoCertificate(t *testing.T) {
	verifier := mtls.NewVerifier(nil)

	handler := mtls.OptionalMiddleware(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := mtls.IdentityFromContext(r.Context())
		if ok {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code) // No identity in context
}
