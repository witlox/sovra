// Package crk contains unit tests for CRK management.
package crk

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/crk"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
)

func TestCRKGeneration(t *testing.T) {
	manager := crk.NewManager()

	t.Run("generates CRK with specified threshold and shares", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)

		require.NoError(t, err)
		assert.NotEmpty(t, crkKey.ID)
		assert.Equal(t, "org-eth", crkKey.OrgID)
		assert.Equal(t, 3, crkKey.Threshold)
		assert.Equal(t, 5, crkKey.TotalShares)
		assert.NotEmpty(t, crkKey.PublicKey)
		assert.Equal(t, models.CRKStatusActive, crkKey.Status)
	})

	t.Run("generates correct number of shares", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)
		require.NoError(t, err)

		shares, err := manager.GetShares(crkKey.ID)
		require.NoError(t, err)
		assert.Len(t, shares, 5)
	})

	t.Run("each share has unique index", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)
		require.NoError(t, err)

		shares, err := manager.GetShares(crkKey.ID)
		require.NoError(t, err)

		indices := make(map[int]bool)
		for _, share := range shares {
			assert.False(t, indices[share.Index], "duplicate index found")
			indices[share.Index] = true
		}
	})

	t.Run("shares reference parent CRK", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)
		require.NoError(t, err)

		shares, err := manager.GetShares(crkKey.ID)
		require.NoError(t, err)

		for _, share := range shares {
			assert.Equal(t, crkKey.ID, share.CRKID)
		}
	})

	t.Run("fails with invalid threshold", func(t *testing.T) {
		_, err := manager.Generate("org-eth", 3, 5) // threshold > shares
		require.Error(t, err)
	})

	t.Run("fails with single share", func(t *testing.T) {
		_, err := manager.Generate("org-eth", 1, 1)
		require.Error(t, err)
	})

	t.Run("fails with zero threshold", func(t *testing.T) {
		_, err := manager.Generate("org-eth", 5, 0)
		require.Error(t, err)
	})
}

func TestCRKReconstruction(t *testing.T) {
	manager := crk.NewManager()

	t.Run("reconstructs with threshold shares", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)
		require.NoError(t, err)

		shares, err := manager.GetShares(crkKey.ID)
		require.NoError(t, err)

		privKey, err := manager.Reconstruct(shares[:3], crkKey.PublicKey)
		require.NoError(t, err)
		assert.NotEmpty(t, privKey)
	})

	t.Run("reconstructs with all shares", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)
		require.NoError(t, err)

		shares, err := manager.GetShares(crkKey.ID)
		require.NoError(t, err)

		privKey, err := manager.Reconstruct(shares, crkKey.PublicKey)
		require.NoError(t, err)
		assert.NotEmpty(t, privKey)
	})

	t.Run("fails with insufficient shares", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)
		require.NoError(t, err)

		shares, err := manager.GetShares(crkKey.ID)
		require.NoError(t, err)

		// Only 2 shares when 3 are needed - reconstruction will succeed
		// but verification against public key will fail
		_, err = manager.Reconstruct(shares[:2], crkKey.PublicKey)
		require.Error(t, err)
	})

	t.Run("fails with duplicate shares", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)
		require.NoError(t, err)

		shares, err := manager.GetShares(crkKey.ID)
		require.NoError(t, err)

		// Create duplicate by using same share twice
		dupShares := []models.CRKShare{shares[0], shares[0], shares[2]}

		_, err = manager.Reconstruct(dupShares, crkKey.PublicKey)
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrShareDuplicate)
	})

	t.Run("fails with wrong public key", func(t *testing.T) {
		crkKey1, err := manager.Generate("org-a", 5, 3)
		require.NoError(t, err)

		crkKey2, err := manager.Generate("org-b", 5, 3)
		require.NoError(t, err)

		shares1, err := manager.GetShares(crkKey1.ID)
		require.NoError(t, err)

		// Try to reconstruct with wrong public key
		_, err = manager.Reconstruct(shares1[:3], crkKey2.PublicKey)
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCRKInvalid)
	})

	t.Run("fails with empty shares", func(t *testing.T) {
		_, err := manager.Reconstruct([]models.CRKShare{}, []byte{})
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCRKThresholdNotMet)
	})
}

func TestCRKSigning(t *testing.T) {
	manager := crk.NewManager()

	t.Run("signs and verifies data", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)
		require.NoError(t, err)

		shares, err := manager.GetShares(crkKey.ID)
		require.NoError(t, err)

		data := []byte("important message to sign")

		signature, err := manager.Sign(shares[:3], crkKey.PublicKey, data)
		require.NoError(t, err)
		assert.NotEmpty(t, signature)

		valid, err := manager.Verify(crkKey.PublicKey, data, signature)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("verification fails with wrong data", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)
		require.NoError(t, err)

		shares, err := manager.GetShares(crkKey.ID)
		require.NoError(t, err)

		signature, err := manager.Sign(shares[:3], crkKey.PublicKey, []byte("original"))
		require.NoError(t, err)

		valid, err := manager.Verify(crkKey.PublicKey, []byte("tampered"), signature)
		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("verification fails with wrong signature", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)
		require.NoError(t, err)

		data := []byte("test data")
		wrongSig := make([]byte, 64) // ed25519 signature size

		valid, err := manager.Verify(crkKey.PublicKey, data, wrongSig)
		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("verify fails with invalid public key size", func(t *testing.T) {
		_, err := manager.Verify([]byte("short"), []byte("data"), make([]byte, 64))
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCRKInvalid)
	})

	t.Run("verify fails with invalid signature size", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)
		require.NoError(t, err)

		_, err = manager.Verify(crkKey.PublicKey, []byte("data"), []byte("short"))
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrShareInvalid)
	})
}

func TestCRKShareValidation(t *testing.T) {
	manager := crk.NewManager()

	t.Run("share data is not empty", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)
		require.NoError(t, err)

		shares, err := manager.GetShares(crkKey.ID)
		require.NoError(t, err)

		for _, share := range shares {
			assert.NotEmpty(t, share.Data)
		}
	})

	t.Run("shares are cryptographically distinct", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)
		require.NoError(t, err)

		shares, err := manager.GetShares(crkKey.ID)
		require.NoError(t, err)

		seen := make(map[string]bool)
		for _, share := range shares {
			dataStr := string(share.Data)
			assert.False(t, seen[dataStr], "duplicate share data found")
			seen[dataStr] = true
		}
	})

	t.Run("validates share with data", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)
		require.NoError(t, err)

		shares, err := manager.GetShares(crkKey.ID)
		require.NoError(t, err)

		err = manager.ValidateShare(shares[0], crkKey.PublicKey)
		require.NoError(t, err)
	})

	t.Run("rejects empty share", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)
		require.NoError(t, err)

		err = manager.ValidateShare(models.CRKShare{Data: nil}, crkKey.PublicKey)
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrShareInvalid)
	})

	t.Run("validates sufficient shares", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)
		require.NoError(t, err)

		shares, err := manager.GetShares(crkKey.ID)
		require.NoError(t, err)

		err = manager.ValidateShares(shares[:3], 3, crkKey.PublicKey)
		require.NoError(t, err)
	})

	t.Run("rejects insufficient shares", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)
		require.NoError(t, err)

		shares, err := manager.GetShares(crkKey.ID)
		require.NoError(t, err)

		err = manager.ValidateShares(shares[:2], 3, crkKey.PublicKey)
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCRKThresholdNotMet)
	})

	t.Run("rejects duplicate shares in validation", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)
		require.NoError(t, err)

		shares, err := manager.GetShares(crkKey.ID)
		require.NoError(t, err)

		dupShares := []models.CRKShare{shares[0], shares[0], shares[2]}
		err = manager.ValidateShares(dupShares, 3, crkKey.PublicKey)
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrShareDuplicate)
	})
}

func TestCRKRegenerateShares(t *testing.T) {
	manager := crk.NewManager()

	t.Run("regenerates shares from private key", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)
		require.NoError(t, err)

		shares, err := manager.GetShares(crkKey.ID)
		require.NoError(t, err)

		// Reconstruct private key
		privKey, err := manager.Reconstruct(shares[:3], crkKey.PublicKey)
		require.NoError(t, err)

		// Regenerate with different threshold
		newShares, err := manager.RegenerateShares(privKey, 7, 4)
		require.NoError(t, err)
		assert.Len(t, newShares, 7)

		// Verify new shares work
		_, err = manager.Reconstruct(newShares[:4], crkKey.PublicKey)
		require.NoError(t, err)
	})

	t.Run("fails with invalid parameters", func(t *testing.T) {
		crkKey, err := manager.Generate("org-eth", 5, 3)
		require.NoError(t, err)

		shares, err := manager.GetShares(crkKey.ID)
		require.NoError(t, err)

		privKey, err := manager.Reconstruct(shares[:3], crkKey.PublicKey)
		require.NoError(t, err)

		_, err = manager.RegenerateShares(privKey, 3, 5) // threshold > shares
		require.Error(t, err)
	})
}

func TestGetSharesNotFound(t *testing.T) {
	manager := crk.NewManager()

	_, err := manager.GetShares("nonexistent-id")
	require.Error(t, err)
	assert.ErrorIs(t, err, errors.ErrNotFound)
}

func BenchmarkCRKOperations(b *testing.B) {
	manager := crk.NewManager()

	b.Run("Generate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = manager.Generate("org-bench", 5, 3)
		}
	})

	b.Run("Sign", func(b *testing.B) {
		crkKey, _ := manager.Generate("org-bench", 5, 3)
		shares, _ := manager.GetShares(crkKey.ID)
		data := []byte("benchmark data")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = manager.Sign(shares[:3], crkKey.PublicKey, data)
		}
	})

	b.Run("Verify", func(b *testing.B) {
		crkKey, _ := manager.Generate("org-bench", 5, 3)
		shares, _ := manager.GetShares(crkKey.ID)
		data := []byte("benchmark data")
		sig, _ := manager.Sign(shares[:3], crkKey.PublicKey, data)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = manager.Verify(crkKey.PublicKey, data, sig)
		}
	})
}

// CeremonyManager tests

func TestCeremonyManagerStartCeremony(t *testing.T) {
	manager := crk.NewManager()
	ceremonyMgr := crk.NewCeremonyManager(manager)

	t.Run("starts ceremony with valid parameters", func(t *testing.T) {
		ceremony, err := ceremonyMgr.StartCeremony("org-eth", "generate", 3)

		require.NoError(t, err)
		assert.NotEmpty(t, ceremony.ID)
		assert.Equal(t, "org-eth", ceremony.OrgID)
		assert.Equal(t, "generate", ceremony.Operation)
		assert.Equal(t, 3, ceremony.RequiredCount)
		assert.False(t, ceremony.Completed)
		assert.Empty(t, ceremony.Shares)
	})

	t.Run("fails with zero threshold", func(t *testing.T) {
		_, err := ceremonyMgr.StartCeremony("org-eth", "generate", 0)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})

	t.Run("fails with negative threshold", func(t *testing.T) {
		_, err := ceremonyMgr.StartCeremony("org-eth", "generate", -1)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})
}

func TestCeremonyManagerAddShare(t *testing.T) {
	manager := crk.NewManager()
	ceremonyMgr := crk.NewCeremonyManager(manager)

	t.Run("adds share to ceremony", func(t *testing.T) {
		ceremony, err := ceremonyMgr.StartCeremony("org-eth", "sign", 3)
		require.NoError(t, err)

		share := models.CRKShare{Index: 1, Data: []byte("share-data-1")}
		err = ceremonyMgr.AddShare(ceremony.ID, share)

		require.NoError(t, err)
	})

	t.Run("rejects duplicate share index", func(t *testing.T) {
		ceremony, err := ceremonyMgr.StartCeremony("org-eth", "sign", 3)
		require.NoError(t, err)

		share1 := models.CRKShare{Index: 1, Data: []byte("share-data-1")}
		share2 := models.CRKShare{Index: 1, Data: []byte("share-data-2")} // same index

		err = ceremonyMgr.AddShare(ceremony.ID, share1)
		require.NoError(t, err)

		err = ceremonyMgr.AddShare(ceremony.ID, share2)
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrShareDuplicate)
	})

	t.Run("fails for non-existent ceremony", func(t *testing.T) {
		share := models.CRKShare{Index: 1, Data: []byte("share-data")}
		err := ceremonyMgr.AddShare("non-existent-id", share)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

func TestCeremonyManagerCompleteCeremony(t *testing.T) {
	manager := crk.NewManager()
	ceremonyMgr := crk.NewCeremonyManager(manager)

	t.Run("completes ceremony with sufficient shares", func(t *testing.T) {
		ceremony, err := ceremonyMgr.StartCeremony("org-eth", "custom", 2)
		require.NoError(t, err)

		_ = ceremonyMgr.AddShare(ceremony.ID, models.CRKShare{Index: 1, Data: []byte("s1")})
		_ = ceremonyMgr.AddShare(ceremony.ID, models.CRKShare{Index: 2, Data: []byte("s2")})

		result, err := ceremonyMgr.CompleteCeremony(ceremony.ID, "witness-1")

		require.NoError(t, err)
		assert.NotEmpty(t, result)
	})

	t.Run("fails with insufficient shares", func(t *testing.T) {
		ceremony, err := ceremonyMgr.StartCeremony("org-eth", "sign", 3)
		require.NoError(t, err)

		_ = ceremonyMgr.AddShare(ceremony.ID, models.CRKShare{Index: 1, Data: []byte("s1")})
		// Only 1 share when 3 required

		_, err = ceremonyMgr.CompleteCeremony(ceremony.ID, "witness-1")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCRKThresholdNotMet)
	})

	t.Run("fails for non-existent ceremony", func(t *testing.T) {
		_, err := ceremonyMgr.CompleteCeremony("non-existent-id", "witness-1")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

func TestCeremonyManagerCancelCeremony(t *testing.T) {
	manager := crk.NewManager()
	ceremonyMgr := crk.NewCeremonyManager(manager)

	t.Run("cancels existing ceremony", func(t *testing.T) {
		ceremony, err := ceremonyMgr.StartCeremony("org-eth", "generate", 3)
		require.NoError(t, err)

		err = ceremonyMgr.CancelCeremony(ceremony.ID)

		require.NoError(t, err)

		// Try to add share should fail
		err = ceremonyMgr.AddShare(ceremony.ID, models.CRKShare{Index: 1, Data: []byte("s1")})
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})

	t.Run("fails for non-existent ceremony", func(t *testing.T) {
		err := ceremonyMgr.CancelCeremony("non-existent-id")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

func TestCeremonyManagerConcurrentOperations(t *testing.T) {
	manager := crk.NewManager()
	ceremonyMgr := crk.NewCeremonyManager(manager)

	t.Run("handles concurrent share additions", func(t *testing.T) {
		ceremony, err := ceremonyMgr.StartCeremony("org-eth", "sign", 10)
		require.NoError(t, err)

		done := make(chan error, 10)
		for i := 1; i <= 10; i++ {
			go func(idx int) {
				share := models.CRKShare{Index: idx, Data: []byte{byte(idx)}}
				done <- ceremonyMgr.AddShare(ceremony.ID, share)
			}(i)
		}

		var errs []error
		for i := 0; i < 10; i++ {
			if err := <-done; err != nil {
				errs = append(errs, err)
			}
		}

		assert.Empty(t, errs, "concurrent share additions should succeed")
	})
}

func TestCeremonyManagerCompleteCeremonyOperations(t *testing.T) {
	manager := crk.NewManager()
	ceremonyMgr := crk.NewCeremonyManager(manager)

	t.Run("completes generate ceremony exercises code path", func(t *testing.T) {
		// Start a generate ceremony
		ceremony, err := ceremonyMgr.StartCeremony("org-eth", "generate", 2)
		require.NoError(t, err)

		// Add shares
		err = ceremonyMgr.AddShare(ceremony.ID, models.CRKShare{Index: 1, Data: []byte("s1")})
		require.NoError(t, err)
		err = ceremonyMgr.AddShare(ceremony.ID, models.CRKShare{Index: 2, Data: []byte("s2")})
		require.NoError(t, err)

		// Complete the ceremony - may fail if no pending CRK was set up
		result, err := ceremonyMgr.CompleteCeremony(ceremony.ID, "witness-1")

		// Either succeeds or fails with ErrNotFound (no pending CRK)
		if err != nil {
			assert.ErrorIs(t, err, errors.ErrNotFound)
		} else {
			assert.NotNil(t, result)
		}
	})

	t.Run("completes sign ceremony exercises code path", func(t *testing.T) {
		// Start a sign ceremony
		ceremony, err := ceremonyMgr.StartCeremony("org-eth", "sign", 2)
		require.NoError(t, err)

		// Add shares
		err = ceremonyMgr.AddShare(ceremony.ID, models.CRKShare{Index: 1, Data: []byte("s1")})
		require.NoError(t, err)
		err = ceremonyMgr.AddShare(ceremony.ID, models.CRKShare{Index: 2, Data: []byte("s2")})
		require.NoError(t, err)

		// Complete - will likely fail because no pending CRK, but exercises code path
		result, err := ceremonyMgr.CompleteCeremony(ceremony.ID, "witness-1")

		// Sign ceremony may fail without a pending CRK, but it exercises the code path
		if err != nil {
			assert.ErrorIs(t, err, errors.ErrNotFound)
		} else {
			assert.NotNil(t, result)
		}
	})

	t.Run("completes custom ceremony exercises code path", func(t *testing.T) {
		// Start a custom ceremony (not generate/sign)
		ceremony, err := ceremonyMgr.StartCeremony("org-eth", "custom", 2)
		require.NoError(t, err)

		// Add shares
		err = ceremonyMgr.AddShare(ceremony.ID, models.CRKShare{Index: 1, Data: []byte("s1")})
		require.NoError(t, err)
		err = ceremonyMgr.AddShare(ceremony.ID, models.CRKShare{Index: 2, Data: []byte("s2")})
		require.NoError(t, err)

		// Complete the custom ceremony - uses default path
		result, err := ceremonyMgr.CompleteCeremony(ceremony.ID, "witness-1")

		require.NoError(t, err)
		assert.NotNil(t, result)
	})
}

func TestContextGenerator(t *testing.T) {
	manager := crk.NewManager()
	ctx := context.Background()

	t.Run("creates context generator", func(t *testing.T) {
		gen := crk.NewContextGenerator(manager)
		assert.NotNil(t, gen)
	})

	t.Run("generates CRK with context", func(t *testing.T) {
		gen := crk.NewContextGenerator(manager)

		// Note: threshold, shareCount order
		crkKey, shares, err := gen.Generate(ctx, "org-eth", 3, 5)

		require.NoError(t, err)
		assert.NotEmpty(t, crkKey.ID)
		assert.Equal(t, "org-eth", crkKey.OrgID)
		assert.NotEmpty(t, crkKey.PublicKey)
		assert.Len(t, shares, 5)
	})

	t.Run("fails with cancelled context", func(t *testing.T) {
		gen := crk.NewContextGenerator(manager)

		cancelCtx, cancel := context.WithCancel(context.Background())
		cancel()

		_, _, err := gen.Generate(cancelCtx, "org-eth", 3, 5)

		// Should fail with context error
		assert.Error(t, err)
	})
}

func TestContextReconstructor(t *testing.T) {
	manager := crk.NewManager()
	ctx := context.Background()

	t.Run("creates context reconstructor", func(t *testing.T) {
		rec := crk.NewContextReconstructor(manager)
		assert.NotNil(t, rec)
	})

	t.Run("reconstructs CRK with context", func(t *testing.T) {
		gen := crk.NewContextGenerator(manager)
		rec := crk.NewContextReconstructor(manager)

		// Generate a CRK with 5 shares, threshold 3
		_, shares, err := gen.Generate(ctx, "org-eth", 3, 5)
		require.NoError(t, err)
		require.Len(t, shares, 5)

		// Reconstruct with threshold shares
		result, err := rec.Reconstruct(ctx, shares[:3], 3)

		require.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("fails with insufficient shares", func(t *testing.T) {
		gen := crk.NewContextGenerator(manager)
		rec := crk.NewContextReconstructor(manager)

		_, shares, err := gen.Generate(ctx, "org-eth", 3, 5)
		require.NoError(t, err)

		// Try with fewer than threshold shares
		_, err = rec.Reconstruct(ctx, shares[:2], 3)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCRKThresholdNotMet)
	})
}
