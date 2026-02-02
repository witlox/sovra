// Package federation contains unit tests for federation management.
package federation

import (
	"context"
	"testing"

	"github.com/sovra-project/sovra/internal/federation"
	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/sovra-project/sovra/tests/testutil"
	"github.com/sovra-project/sovra/tests/testutil/inmemory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestService creates a federation service with inmemory dependencies.
func createTestService(orgID string) federation.Service {
	repo := inmemory.NewFederationRepository()
	certMgr := inmemory.NewFederationCertManager()
	mtlsClient := inmemory.NewFederationMTLSClient()
	svc := federation.NewService(repo, certMgr, mtlsClient)
	// Initialize with org ID
	_, _ = svc.Init(context.Background(), federation.InitRequest{OrgID: orgID})
	return svc
}

func TestFederationInitialization(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := inmemory.NewFederationRepository()
	certMgr := inmemory.NewFederationCertManager()
	mtlsClient := inmemory.NewFederationMTLSClient()
	svc := federation.NewService(repo, certMgr, mtlsClient)

	t.Run("initializes federation for organization", func(t *testing.T) {
		resp, err := svc.Init(ctx, federation.InitRequest{
			OrgID: "org-eth",
		})

		require.NoError(t, err)
		assert.Equal(t, "org-eth", resp.OrgID)
		assert.NotEmpty(t, resp.CSR)
		assert.NotEmpty(t, resp.Certificate)
	})

	t.Run("generates CSR for federation", func(t *testing.T) {
		csr, err := certMgr.GenerateCSR("org-uzh")

		require.NoError(t, err)
		assert.NotEmpty(t, csr)
	})

	t.Run("validates partner certificate", func(t *testing.T) {
		cert := []byte("valid-certificate-data")

		parsed, err := certMgr.ValidateCertificate(cert)

		require.NoError(t, err)
		assert.NotNil(t, parsed)
	})

	t.Run("rejects empty certificate", func(t *testing.T) {
		_, err := certMgr.ValidateCertificate([]byte{})

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCertificateInvalid)
	})
}

func TestFederationEstablishment(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc := createTestService("org-eth")

	t.Run("establishes federation with partner", func(t *testing.T) {
		req := federation.EstablishRequest{
			PartnerOrgID: "org-partner",
			PartnerURL:   "https://partner.example.com",
			PartnerCert:  []byte("partner-certificate-data"),
		}

		fed, err := svc.Establish(ctx, req)

		require.NoError(t, err)
		assert.NotEmpty(t, fed.ID)
		assert.Equal(t, "org-partner", fed.PartnerOrgID)
		assert.Equal(t, models.FederationStatusActive, fed.Status)
	})

	t.Run("retrieves federation status", func(t *testing.T) {
		req := federation.EstablishRequest{
			PartnerOrgID: "org-status-test",
			PartnerURL:   "https://status.example.com",
			PartnerCert:  []byte("status-cert"),
		}
		_, _ = svc.Establish(ctx, req)

		status, err := svc.Status(ctx, "org-status-test")

		require.NoError(t, err)
		assert.Equal(t, models.FederationStatusActive, status.Status)
	})
}

func TestFederationListing(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc := createTestService("org-eth")

	// Create federations
	partners := []string{"org-partner-1", "org-partner-2", "org-partner-3"}
	for _, partner := range partners {
		req := federation.EstablishRequest{
			PartnerOrgID: partner,
			PartnerURL:   "https://" + partner + ".example.com",
			PartnerCert:  []byte(partner + "-cert"),
		}
		_, _ = svc.Establish(ctx, req)
	}

	t.Run("lists all federations for organization", func(t *testing.T) {
		federations, err := svc.List(ctx)

		require.NoError(t, err)
		assert.Len(t, federations, 3)
	})
}

func TestFederationHealthCheck(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc := createTestService("org-eth")

	t.Run("performs health check on federated partners", func(t *testing.T) {
		req := federation.EstablishRequest{
			PartnerOrgID: "org-healthy",
			PartnerURL:   "https://healthy.example.com",
			PartnerCert:  []byte("healthy-cert"),
		}
		_, _ = svc.Establish(ctx, req)

		results, err := svc.HealthCheck(ctx)

		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, "org-healthy", results[0].PartnerOrgID)
		assert.True(t, results[0].Healthy)
	})
}

func TestFederationRevocation(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc := createTestService("org-eth")

	t.Run("revokes federation", func(t *testing.T) {
		req := federation.EstablishRequest{
			PartnerOrgID: "org-ex-partner",
			PartnerURL:   "https://ex-partner.example.com",
			PartnerCert:  []byte("ex-partner-cert"),
		}
		_, _ = svc.Establish(ctx, req)

		err := svc.Revoke(ctx, federation.RevocationRequest{
			PartnerOrgID: "org-ex-partner",
		})

		require.NoError(t, err)

		status, _ := svc.Status(ctx, "org-ex-partner")
		assert.Equal(t, models.FederationStatusRevoked, status.Status)
	})
}

func TestFederationPublicKeyRequest(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc := createTestService("org-eth")

	t.Run("requests public key from partner", func(t *testing.T) {
		req := federation.EstablishRequest{
			PartnerOrgID: "org-key-partner",
			PartnerURL:   "https://key-partner.example.com",
			PartnerCert:  []byte("key-partner-cert"),
		}
		_, _ = svc.Establish(ctx, req)

		pubKey, err := svc.RequestPublicKey(ctx, "org-key-partner")

		require.NoError(t, err)
		assert.NotEmpty(t, pubKey)
	})
}

func BenchmarkFederationOperations(b *testing.B) {
	ctx := context.Background()
	svc := createTestService("org-bench")

	b.Run("Establish", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			req := federation.EstablishRequest{
				PartnerOrgID: "org-partner",
				PartnerURL:   "https://partner.example.com",
				PartnerCert:  []byte("cert"),
			}
			_, _ = svc.Establish(ctx, req)
		}
	})

	b.Run("HealthCheck", func(b *testing.B) {
		req := federation.EstablishRequest{
			PartnerOrgID: "org-health-bench",
			PartnerURL:   "https://health-bench.example.com",
			PartnerCert:  []byte("health-bench-cert"),
		}
		_, _ = svc.Establish(ctx, req)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = svc.HealthCheck(ctx)
		}
	})
}
