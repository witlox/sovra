package crk

import (
	"crypto/ed25519"
	"testing"

	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCRKGenerate tests CRK generation with Shamir Secret Sharing.
func TestCRKGenerate(t *testing.T) {
	manager := NewManager()

	t.Run("generate valid CRK with 5 shares and threshold 3", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)

		require.NoError(t, err)
		assert.Equal(t, "org-test", crk.OrgID)
		assert.Len(t, crk.Shares, 5)
		assert.Equal(t, 3, crk.Threshold)
		assert.Equal(t, 5, crk.TotalShares)
		assert.NotEmpty(t, crk.PublicKey)
		assert.Len(t, crk.PublicKey, ed25519.PublicKeySize)

		// Verify all shares have unique numbers
		shareNumbers := make(map[int]bool)
		for _, share := range crk.Shares {
			assert.False(t, shareNumbers[share.ShareNumber], "duplicate share number")
			shareNumbers[share.ShareNumber] = true
			assert.NotEmpty(t, share.ShareData)
		}
	})

	t.Run("generate CRK with 7 shares and threshold 4", func(t *testing.T) {
		crk, err := manager.Generate("org-high-security", 7, 4)

		require.NoError(t, err)
		assert.Len(t, crk.Shares, 7)
		assert.Equal(t, 4, crk.Threshold)
	})

	t.Run("generate CRK with minimum shares (2-of-2)", func(t *testing.T) {
		crk, err := manager.Generate("org-minimal", 2, 2)

		require.NoError(t, err)
		assert.Len(t, crk.Shares, 2)
		assert.Equal(t, 2, crk.Threshold)
	})

	t.Run("fail when threshold greater than total shares", func(t *testing.T) {
		_, err := manager.Generate("org-invalid", 3, 5)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})

	t.Run("fail when threshold is zero", func(t *testing.T) {
		_, err := manager.Generate("org-invalid", 5, 0)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})

	t.Run("fail when total shares is less than 2", func(t *testing.T) {
		_, err := manager.Generate("org-invalid", 1, 1)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})

	t.Run("fail when org ID is empty", func(t *testing.T) {
		_, err := manager.Generate("", 5, 3)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})

	t.Run("generated CRKs are unique", func(t *testing.T) {
		crk1, err1 := manager.Generate("org-1", 5, 3)
		crk2, err2 := manager.Generate("org-2", 5, 3)

		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.NotEqual(t, crk1.PublicKey, crk2.PublicKey)
	})
}

// TestCRKReconstruct tests CRK reconstruction from shares.
func TestCRKReconstruct(t *testing.T) {
	manager := NewManager()

	t.Run("reconstruct CRK with exact threshold shares", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		// Use exactly 3 shares
		shares := crk.Shares[:3]
		privateKey, err := manager.Reconstruct(shares, crk.PublicKey)

		require.NoError(t, err)
		assert.NotNil(t, privateKey)
		assert.Len(t, privateKey, ed25519.PrivateKeySize)

		// Verify the reconstructed key matches the public key
		derivedPublicKey := privateKey.Public().(ed25519.PublicKey)
		assert.Equal(t, crk.PublicKey, []byte(derivedPublicKey))
	})

	t.Run("reconstruct CRK with more than threshold shares", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		// Use all 5 shares
		privateKey, err := manager.Reconstruct(crk.Shares, crk.PublicKey)

		require.NoError(t, err)
		assert.NotNil(t, privateKey)

		derivedPublicKey := privateKey.Public().(ed25519.PublicKey)
		assert.Equal(t, crk.PublicKey, []byte(derivedPublicKey))
	})

	t.Run("reconstruct with non-consecutive shares", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		// Use shares 1, 3, 5 (non-consecutive)
		shares := []models.CRKShare{crk.Shares[0], crk.Shares[2], crk.Shares[4]}
		privateKey, err := manager.Reconstruct(shares, crk.PublicKey)

		require.NoError(t, err)
		assert.NotNil(t, privateKey)

		derivedPublicKey := privateKey.Public().(ed25519.PublicKey)
		assert.Equal(t, crk.PublicKey, []byte(derivedPublicKey))
	})

	t.Run("fail with fewer shares than threshold", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		// Use only 2 shares (threshold is 3)
		shares := crk.Shares[:2]
		_, err = manager.Reconstruct(shares, crk.PublicKey)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCRKThresholdNotMet)
	})

	t.Run("fail with duplicate shares", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		// Use duplicate shares
		shares := []models.CRKShare{crk.Shares[0], crk.Shares[0], crk.Shares[1]}
		_, err = manager.Reconstruct(shares, crk.PublicKey)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrShareDuplicate)
	})

	t.Run("fail with shares from different CRKs", func(t *testing.T) {
		crk1, err1 := manager.Generate("org-1", 5, 3)
		crk2, err2 := manager.Generate("org-2", 5, 3)
		require.NoError(t, err1)
		require.NoError(t, err2)

		// Mix shares from different CRKs
		shares := []models.CRKShare{crk1.Shares[0], crk1.Shares[1], crk2.Shares[2]}
		_, err := manager.Reconstruct(shares, crk1.PublicKey)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCRKInvalid)
	})

	t.Run("fail with corrupted share data", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		// Corrupt one share
		shares := make([]models.CRKShare, 3)
		copy(shares, crk.Shares[:3])
		shares[0].ShareData = []byte("corrupted")

		_, err = manager.Reconstruct(shares, crk.PublicKey)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrShareInvalid)
	})

	t.Run("fail with empty shares", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		_, err = manager.Reconstruct([]models.CRKShare{}, crk.PublicKey)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCRKThresholdNotMet)
	})
}

// TestCRKSign tests CRK signing operations.
func TestCRKSign(t *testing.T) {
	manager := NewManager()

	t.Run("sign and verify data successfully", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		data := []byte("important operation data")
		signature, err := manager.Sign(crk.Shares[:3], crk.PublicKey, data)

		require.NoError(t, err)
		assert.NotEmpty(t, signature)
		assert.Len(t, signature, ed25519.SignatureSize)

		// Verify the signature
		valid, err := manager.Verify(crk.PublicKey, data, signature)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("verify fails with modified data", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		data := []byte("important operation data")
		signature, err := manager.Sign(crk.Shares[:3], crk.PublicKey, data)
		require.NoError(t, err)

		// Modify the data
		modifiedData := []byte("modified operation data")
		valid, err := manager.Verify(crk.PublicKey, modifiedData, signature)
		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("verify fails with wrong public key", func(t *testing.T) {
		crk1, err1 := manager.Generate("org-1", 5, 3)
		crk2, err2 := manager.Generate("org-2", 5, 3)
		require.NoError(t, err1)
		require.NoError(t, err2)

		data := []byte("important operation data")
		signature, err := manager.Sign(crk1.Shares[:3], crk1.PublicKey, data)
		require.NoError(t, err)

		// Verify with wrong public key
		valid, err := manager.Verify(crk2.PublicKey, data, signature)
		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("sign fails with insufficient shares", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		data := []byte("important operation data")
		_, err = manager.Sign(crk.Shares[:2], crk.PublicKey, data)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCRKThresholdNotMet)
	})

	t.Run("sign empty data", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		signature, err := manager.Sign(crk.Shares[:3], crk.PublicKey, []byte{})

		require.NoError(t, err)
		assert.NotEmpty(t, signature)

		valid, err := manager.Verify(crk.PublicKey, []byte{}, signature)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("sign large data", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		// 1MB of data
		largeData := make([]byte, 1024*1024)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		signature, err := manager.Sign(crk.Shares[:3], crk.PublicKey, largeData)
		require.NoError(t, err)

		valid, err := manager.Verify(crk.PublicKey, largeData, signature)
		require.NoError(t, err)
		assert.True(t, valid)
	})
}

// TestCRKShareValidation tests share validation.
func TestCRKShareValidation(t *testing.T) {
	manager := NewManager()

	t.Run("validate valid share", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		err = manager.ValidateShare(crk.Shares[0], crk.PublicKey)
		assert.NoError(t, err)
	})

	t.Run("validate share with wrong public key", func(t *testing.T) {
		crk1, err1 := manager.Generate("org-1", 5, 3)
		crk2, err2 := manager.Generate("org-2", 5, 3)
		require.NoError(t, err1)
		require.NoError(t, err2)

		err := manager.ValidateShare(crk1.Shares[0], crk2.PublicKey)
		assert.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrShareInvalid)
	})

	t.Run("validate shares can reconstruct", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		err = manager.ValidateShares(crk.Shares[:3], 3, crk.PublicKey)
		assert.NoError(t, err)
	})

	t.Run("validate shares fails with insufficient count", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		err = manager.ValidateShares(crk.Shares[:2], 3, crk.PublicKey)
		assert.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCRKThresholdNotMet)
	})

	t.Run("validate corrupted share", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		corruptedShare := models.CRKShare{
			ShareNumber: 1,
			ShareData:   []byte("invalid data"),
		}

		err = manager.ValidateShare(corruptedShare, crk.PublicKey)
		assert.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrShareInvalid)
	})
}

// TestCRKRegenerateShares tests share regeneration.
func TestCRKRegenerateShares(t *testing.T) {
	manager := NewManager()

	t.Run("regenerate shares maintains key", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		// Reconstruct to get private key
		privateKey, err := manager.Reconstruct(crk.Shares[:3], crk.PublicKey)
		require.NoError(t, err)

		// Regenerate with new share count
		newShares, err := manager.RegenerateShares(privateKey, 7, 4)
		require.NoError(t, err)
		assert.Len(t, newShares, 7)

		// Verify new shares can reconstruct the same key
		newPrivateKey, err := manager.Reconstruct(newShares[:4], crk.PublicKey)
		require.NoError(t, err)

		assert.Equal(t, privateKey, newPrivateKey)
	})

	t.Run("old shares cannot mix with new shares", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		privateKey, err := manager.Reconstruct(crk.Shares[:3], crk.PublicKey)
		require.NoError(t, err)

		newShares, err := manager.RegenerateShares(privateKey, 5, 3)
		require.NoError(t, err)

		// Mix old and new shares
		mixedShares := []models.CRKShare{crk.Shares[0], crk.Shares[1], newShares[2]}
		_, err = manager.Reconstruct(mixedShares, crk.PublicKey)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCRKInvalid)
	})
}

// TestCRKCeremony tests key ceremony operations.
func TestCRKCeremony(t *testing.T) {
	ceremonyMgr := NewCeremonyManager()
	manager := NewManager()

	t.Run("complete ceremony successfully", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		ceremony, err := ceremonyMgr.StartCeremony("org-test", "workspace.create", 3)
		require.NoError(t, err)
		assert.NotEmpty(t, ceremony.ID)
		assert.Equal(t, "org-test", ceremony.OrgID)
		assert.Equal(t, "workspace.create", ceremony.Operation)
		assert.False(t, ceremony.Completed)

		// Add shares from different custodians
		err = ceremonyMgr.AddShare(ceremony.ID, crk.Shares[0])
		require.NoError(t, err)

		err = ceremonyMgr.AddShare(ceremony.ID, crk.Shares[2])
		require.NoError(t, err)

		err = ceremonyMgr.AddShare(ceremony.ID, crk.Shares[4])
		require.NoError(t, err)

		// Complete ceremony
		result, err := ceremonyMgr.CompleteCeremony(ceremony.ID, "auditor@example.com")
		require.NoError(t, err)
		assert.NotEmpty(t, result)
	})

	t.Run("ceremony fails with insufficient shares", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		ceremony, err := ceremonyMgr.StartCeremony("org-test", "workspace.create", 3)
		require.NoError(t, err)

		// Add only 2 shares
		err = ceremonyMgr.AddShare(ceremony.ID, crk.Shares[0])
		require.NoError(t, err)

		err = ceremonyMgr.AddShare(ceremony.ID, crk.Shares[1])
		require.NoError(t, err)

		// Try to complete
		_, err = ceremonyMgr.CompleteCeremony(ceremony.ID, "auditor@example.com")
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCRKThresholdNotMet)
	})

	t.Run("cancel ceremony", func(t *testing.T) {
		ceremony, err := ceremonyMgr.StartCeremony("org-test", "workspace.create", 3)
		require.NoError(t, err)

		err = ceremonyMgr.CancelCeremony(ceremony.ID)
		require.NoError(t, err)

		// Try to add share to cancelled ceremony
		crk, _ := manager.Generate("org-test", 5, 3)
		err = ceremonyMgr.AddShare(ceremony.ID, crk.Shares[0])
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})

	t.Run("duplicate share rejected in ceremony", func(t *testing.T) {
		crk, err := manager.Generate("org-test", 5, 3)
		require.NoError(t, err)

		ceremony, err := ceremonyMgr.StartCeremony("org-test", "workspace.create", 3)
		require.NoError(t, err)

		err = ceremonyMgr.AddShare(ceremony.ID, crk.Shares[0])
		require.NoError(t, err)

		// Try to add same share again
		err = ceremonyMgr.AddShare(ceremony.ID, crk.Shares[0])
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrShareDuplicate)
	})
}

// BenchmarkCRKOperations benchmarks CRK operations.
func BenchmarkCRKOperations(b *testing.B) {
	manager := NewManager()

	b.Run("Generate 5-of-3", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = manager.Generate("org-bench", 5, 3)
		}
	})

	b.Run("Reconstruct 3 shares", func(b *testing.B) {
		crk, _ := manager.Generate("org-bench", 5, 3)
		shares := crk.Shares[:3]
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = manager.Reconstruct(shares, crk.PublicKey)
		}
	})

	b.Run("Sign 1KB data", func(b *testing.B) {
		crk, _ := manager.Generate("org-bench", 5, 3)
		shares := crk.Shares[:3]
		data := make([]byte, 1024)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = manager.Sign(shares, crk.PublicKey, data)
		}
	})

	b.Run("Verify signature", func(b *testing.B) {
		crk, _ := manager.Generate("org-bench", 5, 3)
		data := make([]byte, 1024)
		sig, _ := manager.Sign(crk.Shares[:3], crk.PublicKey, data)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = manager.Verify(crk.PublicKey, data, sig)
		}
	})
}
