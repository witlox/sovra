// Package federation contains unit tests for federation management.
package federation

import (
	"context"
	"testing"

	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/sovra-project/sovra/tests/mocks"
	"github.com/sovra-project/sovra/tests/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFederationInitialization(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewFederationRepository()

	t.Run("stores organization certificate", func(t *testing.T) {
		cert := []byte("-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----")

		err := repo.StoreCertificate(ctx, "org-eth", cert)

		require.NoError(t, err)

		retrieved, err := repo.GetCertificate(ctx, "org-eth")
		require.NoError(t, err)
		assert.Equal(t, cert, retrieved)
	})

	t.Run("returns error for missing certificate", func(t *testing.T) {
		_, err := repo.GetCertificate(ctx, "org-unknown")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

func TestFederationEstablishment(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewFederationRepository()
	mtlsClient := mocks.NewFederationMTLSClient()

	t.Run("establishes federation with partner", func(t *testing.T) {
		partnerCert := []byte("partner-certificate")

		// Connect to partner
		err := mtlsClient.Connect(ctx, "org-partner", partnerCert)
		require.NoError(t, err)

		// Store federation
		fed := testutil.TestFederation("org-eth", "org-partner")
		err = repo.Create(ctx, fed)

		require.NoError(t, err)
		assert.NotEmpty(t, fed.ID)
		assert.Equal(t, models.FederationStatusActive, fed.Status)
	})

	t.Run("fails when partner unreachable", func(t *testing.T) {
		mtlsClient.Unreachable["org-unreachable"] = true

		err := mtlsClient.Connect(ctx, "org-unreachable", []byte("cert"))

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrFederationFailed)
	})

	t.Run("requires bilateral establishment", func(t *testing.T) {
		// Org A -> Org B
		fedAB := testutil.TestFederation("org-a", "org-b")
		_ = repo.Create(ctx, fedAB)

		// Org B -> Org A
		fedBA := testutil.TestFederation("org-b", "org-a")
		_ = repo.Create(ctx, fedBA)

		// Both directions should exist
		abFed, err := repo.Get(ctx, "org-a", "org-b")
		require.NoError(t, err)
		assert.NotNil(t, abFed)

		baFed, err := repo.Get(ctx, "org-b", "org-a")
		require.NoError(t, err)
		assert.NotNil(t, baFed)
	})
}

func TestFederationListing(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewFederationRepository()

	// Create federations
	partners := []string{"org-partner-1", "org-partner-2", "org-partner-3"}
	for _, partner := range partners {
		fed := testutil.TestFederation("org-eth", partner)
		_ = repo.Create(ctx, fed)
	}

	t.Run("lists all federations for organization", func(t *testing.T) {
		federations, err := repo.List(ctx, "org-eth")

		require.NoError(t, err)
		assert.Len(t, federations, 3)
	})

	t.Run("returns empty list for unfederated org", func(t *testing.T) {
		federations, err := repo.List(ctx, "org-isolated")

		require.NoError(t, err)
		assert.Empty(t, federations)
	})
}

func TestFederationHealthCheck(t *testing.T) {
	ctx := testutil.TestContext(t)
	mtlsClient := mocks.NewFederationMTLSClient()

	t.Run("healthy partner returns true", func(t *testing.T) {
		healthy, err := mtlsClient.HealthCheck(ctx, "org-healthy")

		require.NoError(t, err)
		assert.True(t, healthy)
	})

	t.Run("unreachable partner returns false", func(t *testing.T) {
		mtlsClient.Unreachable["org-down"] = true

		healthy, err := mtlsClient.HealthCheck(ctx, "org-down")

		require.NoError(t, err)
		assert.False(t, healthy)
	})
}

func TestFederationRevocation(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewFederationRepository()

	t.Run("revokes federation", func(t *testing.T) {
		fed := testutil.TestFederation("org-eth", "org-ex-partner")
		_ = repo.Create(ctx, fed)

		fed.Status = models.FederationStatusRevoked
		err := repo.Update(ctx, fed)

		require.NoError(t, err)

		updated, _ := repo.Get(ctx, "org-eth", "org-ex-partner")
		assert.Equal(t, models.FederationStatusRevoked, updated.Status)
	})

	t.Run("deletes federation record", func(t *testing.T) {
		fed := testutil.TestFederation("org-eth", "org-delete")
		_ = repo.Create(ctx, fed)

		err := repo.Delete(ctx, fed.ID)

		require.NoError(t, err)
	})
}

func BenchmarkFederationOperations(b *testing.B) {
	ctx := context.Background()
	repo := mocks.NewFederationRepository()
	mtlsClient := mocks.NewFederationMTLSClient()

	b.Run("Establish", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = mtlsClient.Connect(ctx, "org-partner", []byte("cert"))
			fed := testutil.TestFederation("org-eth", "org-partner")
			_ = repo.Create(ctx, fed)
		}
	})

	b.Run("HealthCheck", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = mtlsClient.HealthCheck(ctx, "org-partner")
		}
	})
}
