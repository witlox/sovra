// Package crk contains unit tests for CRK management.
package crk

import (
	"testing"

	"github.com/sovra-project/sovra/internal/crk"
	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
