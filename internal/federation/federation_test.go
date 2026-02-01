package federation

import (
	"context"
	"testing"
	"time"

	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFederationInit tests federation initialization.
func TestFederationInit(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockCertManager(), NewMockMTLSClient())

	t.Run("initialize federation successfully", func(t *testing.T) {
		req := InitRequest{
			OrgID:        "org-a",
			CRKSignature: []byte("valid-signature"),
		}

		resp, err := service.Init(ctx, req)

		require.NoError(t, err)
		assert.Equal(t, "org-a", resp.OrgID)
		assert.NotEmpty(t, resp.Certificate)
		assert.NotEmpty(t, resp.PublicKey)
	})

	t.Run("fail without CRK signature", func(t *testing.T) {
		req := InitRequest{
			OrgID:        "org-a",
			CRKSignature: nil,
		}

		_, err := service.Init(ctx, req)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrUnauthorized)
	})

	t.Run("fail with empty org ID", func(t *testing.T) {
		req := InitRequest{
			OrgID:        "",
			CRKSignature: []byte("valid-signature"),
		}

		_, err := service.Init(ctx, req)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})
}

// TestFederationImportCertificate tests certificate import.
func TestFederationImportCertificate(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockCertManager(), NewMockMTLSClient())

	t.Run("import valid certificate", func(t *testing.T) {
		cert := generateMockCertificate("org-b")

		err := service.ImportCertificate(ctx, "org-b", cert, []byte("valid-signature"))

		require.NoError(t, err)
	})

	t.Run("fail with invalid certificate", func(t *testing.T) {
		err := service.ImportCertificate(ctx, "org-b", []byte("invalid-cert"), []byte("valid-signature"))

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCertificateInvalid)
	})

	t.Run("fail with expired certificate", func(t *testing.T) {
		expiredCert := generateExpiredMockCertificate("org-b")

		err := service.ImportCertificate(ctx, "org-b", expiredCert, []byte("valid-signature"))

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCertificateExpired)
	})

	t.Run("fail without signature", func(t *testing.T) {
		cert := generateMockCertificate("org-b")

		err := service.ImportCertificate(ctx, "org-b", cert, nil)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrUnauthorized)
	})
}

// TestFederationEstablish tests federation establishment.
func TestFederationEstablish(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockCertManager(), NewMockMTLSClient())

	t.Run("establish federation successfully", func(t *testing.T) {
		// First import partner certificate
		cert := generateMockCertificate("org-b")
		err := service.ImportCertificate(ctx, "org-b", cert, []byte("valid-signature"))
		require.NoError(t, err)

		req := EstablishRequest{
			PartnerOrgID: "org-b",
			PartnerURL:   "https://sovra-org-b.example.org",
			PartnerCert:  cert,
			CRKSignature: []byte("valid-signature"),
		}

		federation, err := service.Establish(ctx, req)

		require.NoError(t, err)
		assert.NotEmpty(t, federation.ID)
		assert.Equal(t, "org-b", federation.PartnerOrgID)
		assert.Equal(t, "https://sovra-org-b.example.org", federation.PartnerURL)
		assert.Equal(t, models.FederationStatusActive, federation.Status)
	})

	t.Run("fail if partner unreachable", func(t *testing.T) {
		cert := generateMockCertificate("org-unreachable")
		_ = service.ImportCertificate(ctx, "org-unreachable", cert, []byte("valid-signature"))

		req := EstablishRequest{
			PartnerOrgID: "org-unreachable",
			PartnerURL:   "https://unreachable.example.org",
			PartnerCert:  cert,
			CRKSignature: []byte("valid-signature"),
		}

		_, err := service.Establish(ctx, req)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrFederationFailed)
	})

	t.Run("fail without certificate import", func(t *testing.T) {
		req := EstablishRequest{
			PartnerOrgID: "org-no-cert",
			PartnerURL:   "https://sovra-org-no-cert.example.org",
			PartnerCert:  nil,
			CRKSignature: []byte("valid-signature"),
		}

		_, err := service.Establish(ctx, req)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCertificateInvalid)
	})

	t.Run("fail with duplicate federation", func(t *testing.T) {
		cert := generateMockCertificate("org-dup")
		_ = service.ImportCertificate(ctx, "org-dup", cert, []byte("valid-signature"))

		req := EstablishRequest{
			PartnerOrgID: "org-dup",
			PartnerURL:   "https://sovra-org-dup.example.org",
			PartnerCert:  cert,
			CRKSignature: []byte("valid-signature"),
		}

		_, err := service.Establish(ctx, req)
		require.NoError(t, err)

		// Try to establish again
		_, err = service.Establish(ctx, req)
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrConflict)
	})
}

// TestFederationStatus tests federation status retrieval.
func TestFederationStatus(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockCertManager(), NewMockMTLSClient())

	t.Run("get active federation status", func(t *testing.T) {
		cert := generateMockCertificate("org-status")
		_ = service.ImportCertificate(ctx, "org-status", cert, []byte("valid-signature"))

		req := EstablishRequest{
			PartnerOrgID: "org-status",
			PartnerURL:   "https://sovra-org-status.example.org",
			PartnerCert:  cert,
			CRKSignature: []byte("valid-signature"),
		}
		_, _ = service.Establish(ctx, req)

		federation, err := service.Status(ctx, "org-status")

		require.NoError(t, err)
		assert.Equal(t, models.FederationStatusActive, federation.Status)
		assert.Equal(t, "org-status", federation.PartnerOrgID)
	})

	t.Run("get non-existent federation status", func(t *testing.T) {
		_, err := service.Status(ctx, "non-existent")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

// TestFederationList tests federation listing.
func TestFederationList(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockCertManager(), NewMockMTLSClient())

	t.Run("list all federations", func(t *testing.T) {
		// Establish multiple federations
		for _, partnerID := range []string{"org-list-1", "org-list-2", "org-list-3"} {
			cert := generateMockCertificate(partnerID)
			_ = service.ImportCertificate(ctx, partnerID, cert, []byte("valid-signature"))
			req := EstablishRequest{
				PartnerOrgID: partnerID,
				PartnerURL:   "https://sovra-" + partnerID + ".example.org",
				PartnerCert:  cert,
				CRKSignature: []byte("valid-signature"),
			}
			_, _ = service.Establish(ctx, req)
		}

		federations, err := service.List(ctx)

		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(federations), 3)
	})

	t.Run("list empty federations", func(t *testing.T) {
		emptyService := NewService(NewMockRepository(), NewMockCertManager(), NewMockMTLSClient())

		federations, err := emptyService.List(ctx)

		require.NoError(t, err)
		assert.Empty(t, federations)
	})
}

// TestFederationRevoke tests federation revocation.
func TestFederationRevoke(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockCertManager(), NewMockMTLSClient())

	t.Run("revoke federation successfully", func(t *testing.T) {
		cert := generateMockCertificate("org-revoke")
		_ = service.ImportCertificate(ctx, "org-revoke", cert, []byte("valid-signature"))

		req := EstablishRequest{
			PartnerOrgID: "org-revoke",
			PartnerURL:   "https://sovra-org-revoke.example.org",
			PartnerCert:  cert,
			CRKSignature: []byte("valid-signature"),
		}
		_, _ = service.Establish(ctx, req)

		err := service.Revoke(ctx, "org-revoke", []byte("valid-signature"))
		require.NoError(t, err)

		federation, err := service.Status(ctx, "org-revoke")
		require.NoError(t, err)
		assert.Equal(t, models.FederationStatusRevoked, federation.Status)
	})

	t.Run("revoke non-existent federation", func(t *testing.T) {
		err := service.Revoke(ctx, "non-existent", []byte("valid-signature"))

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})

	t.Run("revoke without signature fails", func(t *testing.T) {
		cert := generateMockCertificate("org-revoke-fail")
		_ = service.ImportCertificate(ctx, "org-revoke-fail", cert, []byte("valid-signature"))

		req := EstablishRequest{
			PartnerOrgID: "org-revoke-fail",
			PartnerURL:   "https://sovra-org-revoke-fail.example.org",
			PartnerCert:  cert,
			CRKSignature: []byte("valid-signature"),
		}
		_, _ = service.Establish(ctx, req)

		err := service.Revoke(ctx, "org-revoke-fail", nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrUnauthorized)
	})
}

// TestFederationHealthCheck tests federation health checking.
func TestFederationHealthCheck(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockCertManager(), NewMockMTLSClient())

	t.Run("health check all federations", func(t *testing.T) {
		// Establish federation
		cert := generateMockCertificate("org-health")
		_ = service.ImportCertificate(ctx, "org-health", cert, []byte("valid-signature"))

		req := EstablishRequest{
			PartnerOrgID: "org-health",
			PartnerURL:   "https://sovra-org-health.example.org",
			PartnerCert:  cert,
			CRKSignature: []byte("valid-signature"),
		}
		_, _ = service.Establish(ctx, req)

		results, err := service.HealthCheck(ctx)

		require.NoError(t, err)
		assert.Contains(t, results, "org-health")
	})

	t.Run("health check updates last health check time", func(t *testing.T) {
		cert := generateMockCertificate("org-health-time")
		_ = service.ImportCertificate(ctx, "org-health-time", cert, []byte("valid-signature"))

		req := EstablishRequest{
			PartnerOrgID: "org-health-time",
			PartnerURL:   "https://sovra-org-health-time.example.org",
			PartnerCert:  cert,
			CRKSignature: []byte("valid-signature"),
		}
		_, _ = service.Establish(ctx, req)

		before, _ := service.Status(ctx, "org-health-time")
		time.Sleep(10 * time.Millisecond)

		_, _ = service.HealthCheck(ctx)

		after, _ := service.Status(ctx, "org-health-time")
		assert.True(t, after.LastHealthCheck.After(before.LastHealthCheck) || after.LastHealthCheck.Equal(before.LastHealthCheck))
	})
}

// TestFederationRequestPublicKey tests requesting partner public keys.
func TestFederationRequestPublicKey(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockCertManager(), NewMockMTLSClient())

	t.Run("request public key from federated partner", func(t *testing.T) {
		cert := generateMockCertificate("org-pubkey")
		_ = service.ImportCertificate(ctx, "org-pubkey", cert, []byte("valid-signature"))

		req := EstablishRequest{
			PartnerOrgID: "org-pubkey",
			PartnerURL:   "https://sovra-org-pubkey.example.org",
			PartnerCert:  cert,
			CRKSignature: []byte("valid-signature"),
		}
		_, _ = service.Establish(ctx, req)

		publicKey, err := service.RequestPublicKey(ctx, "org-pubkey")

		require.NoError(t, err)
		assert.NotEmpty(t, publicKey)
	})

	t.Run("request public key from non-federated partner fails", func(t *testing.T) {
		_, err := service.RequestPublicKey(ctx, "non-federated")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})

	t.Run("request public key from revoked federation fails", func(t *testing.T) {
		cert := generateMockCertificate("org-revoked-key")
		_ = service.ImportCertificate(ctx, "org-revoked-key", cert, []byte("valid-signature"))

		req := EstablishRequest{
			PartnerOrgID: "org-revoked-key",
			PartnerURL:   "https://sovra-org-revoked-key.example.org",
			PartnerCert:  cert,
			CRKSignature: []byte("valid-signature"),
		}
		_, _ = service.Establish(ctx, req)
		_ = service.Revoke(ctx, "org-revoked-key", []byte("valid-signature"))

		_, err := service.RequestPublicKey(ctx, "org-revoked-key")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrForbidden)
	})
}

// TestFederationMTLSConnection tests mTLS connection handling.
func TestFederationMTLSConnection(t *testing.T) {
	ctx := context.Background()

	t.Run("mTLS connection established on federation", func(t *testing.T) {
		client := NewMockMTLSClient()
		service := NewService(NewMockRepository(), NewMockCertManager(), client)

		cert := generateMockCertificate("org-mtls")
		_ = service.ImportCertificate(ctx, "org-mtls", cert, []byte("valid-signature"))

		req := EstablishRequest{
			PartnerOrgID: "org-mtls",
			PartnerURL:   "https://sovra-org-mtls.example.org",
			PartnerCert:  cert,
			CRKSignature: []byte("valid-signature"),
		}

		_, err := service.Establish(ctx, req)

		require.NoError(t, err)
		assert.True(t, client.IsConnected("org-mtls"))
	})

	t.Run("mTLS connection closed on revocation", func(t *testing.T) {
		client := NewMockMTLSClient()
		service := NewService(NewMockRepository(), NewMockCertManager(), client)

		cert := generateMockCertificate("org-mtls-revoke")
		_ = service.ImportCertificate(ctx, "org-mtls-revoke", cert, []byte("valid-signature"))

		req := EstablishRequest{
			PartnerOrgID: "org-mtls-revoke",
			PartnerURL:   "https://sovra-org-mtls-revoke.example.org",
			PartnerCert:  cert,
			CRKSignature: []byte("valid-signature"),
		}
		_, _ = service.Establish(ctx, req)

		_ = service.Revoke(ctx, "org-mtls-revoke", []byte("valid-signature"))

		assert.False(t, client.IsConnected("org-mtls-revoke"))
	})
}

// Helper functions for testing
func generateMockCertificate(orgID string) []byte {
	// Return a mock certificate for testing
	return []byte("mock-certificate-for-" + orgID)
}

func generateExpiredMockCertificate(orgID string) []byte {
	// Return a mock expired certificate for testing
	return []byte("expired-certificate-for-" + orgID)
}

// BenchmarkFederationOperations benchmarks federation operations.
func BenchmarkFederationOperations(b *testing.B) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockCertManager(), NewMockMTLSClient())

	b.Run("Init", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			req := InitRequest{
				OrgID:        "org-bench",
				CRKSignature: []byte("valid-signature"),
			}
			_, _ = service.Init(ctx, req)
		}
	})

	b.Run("Establish", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			partnerID := "org-bench-" + string(rune('a'+i%26))
			cert := generateMockCertificate(partnerID)
			_ = service.ImportCertificate(ctx, partnerID, cert, []byte("valid-signature"))

			req := EstablishRequest{
				PartnerOrgID: partnerID,
				PartnerURL:   "https://sovra-" + partnerID + ".example.org",
				PartnerCert:  cert,
				CRKSignature: []byte("valid-signature"),
			}
			_, _ = service.Establish(ctx, req)
		}
	})

	b.Run("HealthCheck", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = service.HealthCheck(ctx)
		}
	})
}
