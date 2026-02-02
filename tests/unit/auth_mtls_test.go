package unit_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/witlox/sovra/internal/auth/mtls"
)

func TestMTLSVerifier(t *testing.T) {
	// Generate a test CA
	caCert, caKey := generateTestCA(t)
	caPEM := pemEncodeCert(caCert)

	verifier, err := mtls.NewVerifierFromPEM(caPEM)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	t.Run("valid certificate", func(t *testing.T) {
		// Generate a valid client certificate
		clientCert := generateClientCert(t, caCert, caKey, "test-client", "TestOrg")

		identity, err := verifier.VerifyCertificate(clientCert)
		if err != nil {
			t.Fatalf("expected valid certificate to pass: %v", err)
		}

		if identity.CommonName != "test-client" {
			t.Errorf("expected CN 'test-client', got %s", identity.CommonName)
		}
		if identity.Organization != "TestOrg" {
			t.Errorf("expected org 'TestOrg', got %s", identity.Organization)
		}
	})

	t.Run("expired certificate", func(t *testing.T) {
		// Generate an expired certificate
		clientCert := generateExpiredCert(t, caCert, caKey)

		_, err := verifier.VerifyCertificate(clientCert)
		if !errors.Is(err, mtls.ErrCertificateExpired) {
			t.Errorf("expected ErrCertificateExpired, got %v", err)
		}
	})

	t.Run("nil certificate", func(t *testing.T) {
		_, err := verifier.VerifyCertificate(nil)
		if !errors.Is(err, mtls.ErrNoCertificate) {
			t.Errorf("expected ErrNoCertificate, got %v", err)
		}
	})
}

func TestIdentityContext(t *testing.T) {
	identity := &mtls.Identity{
		CommonName:   "test-user",
		Organization: "TestOrg",
	}

	ctx := mtls.ContextWithIdentity(context.Background(), identity)

	retrieved, ok := mtls.IdentityFromContext(ctx)
	if !ok {
		t.Error("expected to find identity in context")
	}
	if retrieved.CommonName != "test-user" {
		t.Errorf("expected CN 'test-user', got %s", retrieved.CommonName)
	}
}

func TestNoIdentityInContext(t *testing.T) {
	ctx := context.Background()
	_, ok := mtls.IdentityFromContext(ctx)
	if ok {
		t.Error("expected no identity in empty context")
	}
}

// Helper functions

func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

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
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}

	return cert, key
}

func generateClientCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn, org string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{org},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create client cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse client cert: %v", err)
	}

	return cert
}

func generateExpiredCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "expired",
		},
		NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter:  time.Now().Add(-24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create expired cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse expired cert: %v", err)
	}

	return cert
}

func pemEncodeCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}
