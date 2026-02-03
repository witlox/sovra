// Package integration contains integration tests with real infrastructure.
package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/auth/jwt"
	"github.com/witlox/sovra/internal/auth/mtls"
	"github.com/witlox/sovra/pkg/vault"
)

// TestAuthenticationFlows tests end-to-end authentication flows.
func TestAuthenticationFlows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Run("mTLS authentication flow", func(t *testing.T) {
		// Generate CA
		caCert, caKey := generateTestCA(t)
		caPEM := pemEncodeCert(caCert)

		// Create verifier
		verifier, err := mtls.NewVerifierFromPEM(caPEM)
		require.NoError(t, err)

		// Generate client certificate
		clientCert := generateClientCert(t, caCert, caKey, "edge-node-1", "Sovra")

		// Verify certificate
		identity, err := verifier.VerifyCertificate(clientCert)
		require.NoError(t, err)

		assert.Equal(t, "edge-node-1", identity.CommonName)
		assert.Equal(t, "Sovra", identity.Organization)
	})

	t.Run("mTLS middleware integration", func(t *testing.T) {
		// Generate CA and client cert
		caCert, caKey := generateTestCA(t)
		caPEM := pemEncodeCert(caCert)
		clientCert := generateClientCert(t, caCert, caKey, "test-client", "TestOrg")

		verifier, err := mtls.NewVerifierFromPEM(caPEM)
		require.NoError(t, err)

		// Create a handler that checks for identity in context
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, ok := mtls.IdentityFromContext(r.Context())
			if !ok {
				http.Error(w, "no identity", http.StatusUnauthorized)
				return
			}

			response := map[string]string{
				"common_name":  identity.CommonName,
				"organization": identity.Organization,
			}
			json.NewEncoder(w).Encode(response)
		})

		// Wrap with mTLS middleware (simulated)
		wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// In real scenario, TLS connection would provide cert
			// Here we simulate by calling verifier directly
			identity, err := verifier.VerifyCertificate(clientCert)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			ctx := mtls.ContextWithIdentity(r.Context(), identity)
			handler.ServeHTTP(w, r.WithContext(ctx))
		})

		req := httptest.NewRequest(http.MethodGet, "/api/v1/resource", nil)
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "test-client", response["common_name"])
	})

	t.Run("JWT claims context integration", func(t *testing.T) {
		claims := &jwt.Claims{
			Subject:      "user-123",
			Issuer:       "https://auth.sovra.local",
			ExpiresAt:    time.Now().Add(time.Hour).Unix(),
			IssuedAt:     time.Now().Unix(),
			Organization: "test-org",
			Roles:        []string{"admin", "operator"},
		}

		// Handler that uses claims from context
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := jwt.ClaimsFromContext(r.Context())
			if !ok {
				http.Error(w, "no claims", http.StatusUnauthorized)
				return
			}

			response := map[string]interface{}{
				"subject": claims.Subject,
				"org":     claims.Organization,
				"roles":   claims.Roles,
			}
			json.NewEncoder(w).Encode(response)
		})

		// Simulate middleware that injects claims
		wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := jwt.ContextWithClaims(r.Context(), claims)
			handler.ServeHTTP(w, r.WithContext(ctx))
		})

		req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "user-123", response["subject"])
		assert.Equal(t, "test-org", response["org"])
	})
}

// TestVaultAppRoleFlow tests the complete AppRole authentication flow.
func TestVaultAppRoleFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	WithVault(t, func(t *testing.T, vc *VaultContainer) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		client, err := vault.NewClient(vault.Config{
			Address: vc.Address,
			Token:   vc.Token,
		})
		require.NoError(t, err)

		// Step 1: Create a policy
		policyName := "sovra-service-policy"
		policyRules := `
path "secret/data/sovra/*" {
  capabilities = ["create", "read", "update", "list"]
}

path "transit/encrypt/sovra-*" {
  capabilities = ["update"]
}
`
		err = client.CreatePolicy(ctx, policyName, policyRules)
		require.NoError(t, err)

		// Step 2: Configure AppRole auth
		err = client.ConfigureAppRoleAuth(ctx, &vault.AppRoleConfig{
			Path:        "sovra-service",
			Description: "Sovra service authentication",
		})
		require.NoError(t, err)

		// Step 3: Create AppRole with the policy
		err = client.CreateAppRole(ctx, "sovra-service", &vault.AppRoleRoleConfig{
			Name:               "edge-node-role",
			BindSecretID:       true,
			TokenPolicies:      []string{policyName},
			TokenTTL:           "1h",
			TokenMaxTTL:        "4h",
			SecretIDTTL:        "24h",
			SecretIDNumUses:    0,          // Unlimited
			SecretIDBoundCIDRs: []string{}, // No CIDR restriction for test
		})
		require.NoError(t, err)

		// Step 4: Get role ID
		roleID, err := client.GetAppRoleRoleID(ctx, "sovra-service", "edge-node-role")
		require.NoError(t, err)
		require.NotEmpty(t, roleID)

		// Step 5: Generate secret ID with metadata
		secretID, accessor, err := client.GenerateAppRoleSecretID(ctx, "sovra-service", "edge-node-role", map[string]string{
			"node_id": "edge-001",
			"region":  "eu-west-1",
		})
		require.NoError(t, err)
		require.NotEmpty(t, secretID)
		require.NotEmpty(t, accessor)

		// Step 6: Login with AppRole credentials
		token, err := client.LoginWithAppRole(ctx, "sovra-service", roleID, secretID)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		t.Logf("Successfully obtained token via AppRole flow")

		// Step 7: Verify the token works
		// Create a new client with the obtained token
		serviceClient, err := vault.NewClient(vault.Config{
			Address: vc.Address,
			Token:   token,
		})
		require.NoError(t, err)

		// Health check should work
		health, err := serviceClient.Health(ctx)
		require.NoError(t, err)
		assert.True(t, health.Initialized)
	})
}

// TestCertificateLifecycle tests the complete certificate lifecycle.
func TestCertificateLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	WithVault(t, func(t *testing.T, vc *VaultContainer) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		client, err := vault.NewClient(vault.Config{
			Address: vc.Address,
			Token:   vc.Token,
		})
		require.NoError(t, err)

		pki := client.PKI("edge-pki")

		// Step 1: Enable PKI engine
		err = pki.Enable(ctx, map[string]interface{}{
			"description": "Edge PKI Engine",
			"config": map[string]interface{}{
				"max_lease_ttl": "87600h",
			},
		})
		require.NoError(t, err)

		// Step 2: Generate root CA
		caResult, err := pki.GenerateRoot(ctx, "Sovra Edge CA", 87600*time.Hour, "rsa", 2048)
		require.NoError(t, err)
		require.NotEmpty(t, caResult.Certificate)

		// Step 3: Create role for edge nodes
		err = pki.CreateRole(ctx, "edge-nodes", &vault.RoleConfig{
			AllowedDomains:  []string{"edge.sovra.local"},
			AllowSubdomains: true,
			AllowLocalhost:  true,
			MaxTTL:          8760 * time.Hour, // 1 year
			KeyType:         "ec",
			KeyBits:         256,
			AllowIPSANs:     true,
			RequireCN:       true,
			AllowedURISANs:  []string{"spiffe://sovra.local/*"},
		})
		require.NoError(t, err)

		// Step 4: Issue certificate for edge node
		cert1, err := pki.IssueCertificate(ctx, "edge-nodes", &vault.CertificateRequest{
			CommonName: "node-001.edge.sovra.local",
			TTL:        720 * time.Hour, // 30 days
			AltNames:   []string{"localhost"},
			IPSANs:     []string{"127.0.0.1", "10.0.0.1"},
		})
		require.NoError(t, err)
		require.NotEmpty(t, cert1.Certificate)
		require.NotEmpty(t, cert1.PrivateKey)
		require.NotEmpty(t, cert1.SerialNumber)

		t.Logf("Issued certificate with serial: %s", cert1.SerialNumber)

		// Step 5: Verify certificate can be parsed
		block, _ := pem.Decode([]byte(cert1.Certificate))
		require.NotNil(t, block)

		parsedCert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		assert.Equal(t, "node-001.edge.sovra.local", parsedCert.Subject.CommonName)
		assert.Contains(t, parsedCert.DNSNames, "localhost")

		// Step 6: Issue another certificate (simulate rotation)
		cert2, err := pki.IssueCertificate(ctx, "edge-nodes", &vault.CertificateRequest{
			CommonName: "node-001.edge.sovra.local",
			TTL:        720 * time.Hour,
		})
		require.NoError(t, err)
		assert.NotEqual(t, cert1.SerialNumber, cert2.SerialNumber)

		t.Logf("Issued rotated certificate with serial: %s", cert2.SerialNumber)

		// Step 7: Revoke old certificate
		err = pki.RevokeCertificate(ctx, cert1.SerialNumber)
		require.NoError(t, err)

		t.Logf("Revoked old certificate: %s", cert1.SerialNumber)
	})
}

// Helper functions (duplicated from unit tests for integration context)

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

func pemEncodeCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// Suppress unused import warning
var _ = bytes.Buffer{}
