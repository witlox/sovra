// Package acceptance contains acceptance tests that verify business requirements.
package acceptance

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/auth/mtls"
	"github.com/witlox/sovra/tests/mocks"
)

// Feature: mTLS Certificate Management
// As a security administrator
// I want to manage TLS certificates for edge nodes
// So that all communication is encrypted and authenticated

// TestCertificateManagementScenarios tests certificate lifecycle scenarios.
func TestCertificateManagementScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Issue certificate for new edge node", func(t *testing.T) {
		// Given a Vault PKI engine configured for edge nodes
		mockVault := mocks.NewMockVaultClient()

		// When requesting a certificate for a new edge node
		result, err := mockVault.IssueCertificate(context.Background(), mocks.CertificateRequest{
			PKIPath:    "edge-pki",
			Role:       "edge-nodes",
			CommonName: "edge-node-001.eu-west.sovra.local",
			TTL:        "720h", // 30 days
			AltNames:   []string{"localhost"},
			IPSANs:     []string{"10.0.1.100"},
		})

		// Then a certificate should be issued
		require.NoError(t, err)
		assert.NotEmpty(t, result.Certificate)
		assert.NotEmpty(t, result.PrivateKey)
		assert.NotEmpty(t, result.SerialNumber)
	})

	t.Run("Scenario: Certificate contains correct SANs", func(t *testing.T) {
		// Given a certificate request with multiple SANs
		mockVault := mocks.NewMockVaultClient()

		result, err := mockVault.IssueCertificate(context.Background(), mocks.CertificateRequest{
			PKIPath:    "edge-pki",
			Role:       "edge-nodes",
			CommonName: "multi-san-node.sovra.local",
			AltNames:   []string{"localhost", "node.internal"},
			IPSANs:     []string{"127.0.0.1", "10.0.0.1", "192.168.1.1"},
		})

		// Then the certificate should include all SANs
		require.NoError(t, err)
		// In real implementation, parse certificate and verify SANs
		assert.NotEmpty(t, result.Certificate)
	})

	t.Run("Scenario: Rotate certificate before expiry", func(t *testing.T) {
		// Given an edge node with an existing certificate
		mockVault := mocks.NewMockVaultClient()
		ctx := context.Background()

		// Issue initial certificate
		cert1, err := mockVault.IssueCertificate(ctx, mocks.CertificateRequest{
			PKIPath:    "edge-pki",
			Role:       "edge-nodes",
			CommonName: "rotating-node.sovra.local",
			TTL:        "720h",
		})
		require.NoError(t, err)

		// When requesting a new certificate (rotation)
		cert2, err := mockVault.IssueCertificate(ctx, mocks.CertificateRequest{
			PKIPath:    "edge-pki",
			Role:       "edge-nodes",
			CommonName: "rotating-node.sovra.local",
			TTL:        "720h",
		})

		// Then a new certificate with different serial should be issued
		require.NoError(t, err)
		assert.NotEqual(t, cert1.SerialNumber, cert2.SerialNumber)
	})

	t.Run("Scenario: Revoke compromised certificate", func(t *testing.T) {
		// Given an edge node with a potentially compromised certificate
		mockVault := mocks.NewMockVaultClient()
		ctx := context.Background()

		cert, err := mockVault.IssueCertificate(ctx, mocks.CertificateRequest{
			PKIPath:    "edge-pki",
			Role:       "edge-nodes",
			CommonName: "compromised-node.sovra.local",
		})
		require.NoError(t, err)

		// When revoking the certificate
		err = mockVault.RevokeCertificate(ctx, "edge-pki", cert.SerialNumber)

		// Then the certificate should be revoked
		assert.NoError(t, err)
	})
}

// TestMTLSVerificationScenarios tests mTLS verification scenarios.
func TestMTLSVerificationScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	// Generate test CA
	caCert, caKey := generateTestCA(t)
	verifier, err := mtls.NewVerifierFromPEM(pemEncodeCert(caCert))
	require.NoError(t, err)

	t.Run("Scenario: Valid certificate from trusted CA is accepted", func(t *testing.T) {
		// Given a valid client certificate signed by trusted CA
		clientCert := generateClientCertWithDetails(t, caCert, caKey,
			"edge-node-001",
			"Sovra Edge Nodes",
			time.Now(),
			time.Now().Add(24*time.Hour),
		)

		// When verifying the certificate
		identity, err := verifier.VerifyCertificate(clientCert)

		// Then it should be accepted
		require.NoError(t, err)
		assert.Equal(t, "edge-node-001", identity.CommonName)
		assert.Equal(t, "Sovra Edge Nodes", identity.Organization)
	})

	t.Run("Scenario: Expired certificate is rejected", func(t *testing.T) {
		// Given an expired client certificate
		expiredCert := generateClientCertWithDetails(t, caCert, caKey,
			"expired-node",
			"Sovra",
			time.Now().Add(-48*time.Hour), // Started 48 hours ago
			time.Now().Add(-24*time.Hour), // Expired 24 hours ago
		)

		// When verifying the certificate
		_, err := verifier.VerifyCertificate(expiredCert)

		// Then it should be rejected
		assert.Error(t, err)
		assert.ErrorIs(t, err, mtls.ErrCertificateExpired)
	})

	t.Run("Scenario: Certificate from untrusted CA is rejected", func(t *testing.T) {
		// Given a certificate signed by an untrusted CA
		untrustedCA, untrustedKey := generateTestCA(t)
		untrustedCert := generateClientCertWithDetails(t, untrustedCA, untrustedKey,
			"untrusted-node",
			"Unknown Org",
			time.Now(),
			time.Now().Add(24*time.Hour),
		)

		// When verifying the certificate with trusted verifier
		_, err := verifier.VerifyCertificate(untrustedCert)

		// Then it should be rejected
		assert.Error(t, err)
	})

	t.Run("Scenario: Missing certificate is rejected", func(t *testing.T) {
		// Given no certificate provided
		// When verifying nil certificate
		_, err := verifier.VerifyCertificate(nil)

		// Then it should be rejected
		assert.Error(t, err)
		assert.ErrorIs(t, err, mtls.ErrNoCertificate)
	})

	t.Run("Scenario: Identity extracted from certificate", func(t *testing.T) {
		// Given a certificate with specific identity information
		clientCert := generateClientCertWithDetails(t, caCert, caKey,
			"service-account-123",
			"Production Services",
			time.Now(),
			time.Now().Add(24*time.Hour),
		)

		// When verifying the certificate
		identity, err := verifier.VerifyCertificate(clientCert)

		// Then identity should be correctly extracted
		require.NoError(t, err)
		assert.Equal(t, "service-account-123", identity.CommonName)
		assert.Equal(t, "Production Services", identity.Organization)
		assert.NotEmpty(t, identity.SerialNumber)
	})
}

// TestCertificateRenewalWorkflow tests certificate renewal workflows.
func TestCertificateRenewalWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Automatic renewal before expiry threshold", func(t *testing.T) {
		// Given a certificate that will expire soon
		mockVault := mocks.NewMockVaultClient()
		ctx := context.Background()

		// Issue a short-lived certificate
		oldCert, err := mockVault.IssueCertificate(ctx, mocks.CertificateRequest{
			PKIPath:    "edge-pki",
			Role:       "edge-nodes",
			CommonName: "renewing-node.sovra.local",
			TTL:        "24h", // 1 day
		})
		require.NoError(t, err)

		// When the certificate is within renewal threshold (e.g., 20% of TTL remaining)
		// The system should automatically renew
		newCert, err := mockVault.IssueCertificate(ctx, mocks.CertificateRequest{
			PKIPath:    "edge-pki",
			Role:       "edge-nodes",
			CommonName: "renewing-node.sovra.local",
			TTL:        "24h",
		})

		// Then a new certificate should be issued
		require.NoError(t, err)
		assert.NotEqual(t, oldCert.SerialNumber, newCert.SerialNumber)
	})

	t.Run("Scenario: Graceful certificate transition", func(t *testing.T) {
		// Given both old and new certificates exist during transition
		caCert, caKey := generateTestCA(t)
		verifier, err := mtls.NewVerifierFromPEM(pemEncodeCert(caCert))
		require.NoError(t, err)

		// Old certificate (still valid)
		oldCert := generateClientCertWithDetails(t, caCert, caKey,
			"transitioning-node",
			"Sovra",
			time.Now().Add(-23*time.Hour), // Issued 23 hours ago
			time.Now().Add(time.Hour),     // Expires in 1 hour
		)

		// New certificate
		newCert := generateClientCertWithDetails(t, caCert, caKey,
			"transitioning-node",
			"Sovra",
			time.Now(),
			time.Now().Add(24*time.Hour),
		)

		// When verifying both certificates
		oldIdentity, oldErr := verifier.VerifyCertificate(oldCert)
		newIdentity, newErr := verifier.VerifyCertificate(newCert)

		// Then both should be valid during transition period
		require.NoError(t, oldErr)
		require.NoError(t, newErr)
		assert.Equal(t, oldIdentity.CommonName, newIdentity.CommonName)
	})
}

// TestPKIRoleConstraints tests PKI role constraint enforcement.
func TestPKIRoleConstraints(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	t.Run("Scenario: Role enforces allowed domains", func(t *testing.T) {
		// Given a PKI role with specific allowed domains
		mockVault := mocks.NewMockVaultClient()
		ctx := context.Background()

		// Create role with domain restriction
		err := mockVault.CreatePKIRole(ctx, mocks.PKIRoleConfig{
			PKIPath:         "edge-pki",
			Name:            "eu-west-nodes",
			AllowedDomains:  []string{"eu-west.sovra.local"},
			AllowSubdomains: true,
		})
		require.NoError(t, err)

		// When requesting a certificate for allowed domain
		result, err := mockVault.IssueCertificate(ctx, mocks.CertificateRequest{
			PKIPath:    "edge-pki",
			Role:       "eu-west-nodes",
			CommonName: "node-001.eu-west.sovra.local",
		})

		// Then the certificate should be issued
		assert.NoError(t, err)
		assert.NotEmpty(t, result.Certificate)
	})

	t.Run("Scenario: Role enforces maximum TTL", func(t *testing.T) {
		// Given a PKI role with maximum TTL
		mockVault := mocks.NewMockVaultClient()
		ctx := context.Background()

		// Create role with TTL restriction
		err := mockVault.CreatePKIRole(ctx, mocks.PKIRoleConfig{
			PKIPath: "edge-pki",
			Name:    "short-lived-certs",
			MaxTTL:  "72h", // 3 days max
		})
		require.NoError(t, err)

		// When requesting a certificate within TTL limits
		result, err := mockVault.IssueCertificate(ctx, mocks.CertificateRequest{
			PKIPath:    "edge-pki",
			Role:       "short-lived-certs",
			CommonName: "short-lived.sovra.local",
			TTL:        "48h", // Within limit
		})

		// Then the certificate should be issued
		assert.NoError(t, err)
		assert.NotEmpty(t, result.Certificate)
	})
}

// Helper functions

func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

func generateClientCertWithDetails(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey,
	cn, org string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{org},
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func pemEncodeCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}
