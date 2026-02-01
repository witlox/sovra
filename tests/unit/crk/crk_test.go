// Package crk contains unit tests for CRK management.
package crk

import (
	"context"
	"testing"

	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/tests/mocks"
	"github.com/sovra-project/sovra/tests/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCRKGeneration(t *testing.T) {
	ctx := testutil.TestContext(t)
	generator := mocks.NewCRKGenerator()

	t.Run("generates CRK with specified threshold and shares", func(t *testing.T) {
		crk, shares, err := generator.Generate(ctx, "org-eth", 3, 5)

		require.NoError(t, err)
		assert.NotEmpty(t, crk.ID)
		assert.Equal(t, "org-eth", crk.OrgID)
		assert.Equal(t, 3, crk.Threshold)
		assert.Len(t, shares, 5)
	})

	t.Run("each share has unique index", func(t *testing.T) {
		_, shares, err := generator.Generate(ctx, "org-eth", 3, 5)

		require.NoError(t, err)
		indices := make(map[int]bool)
		for _, share := range shares {
			assert.False(t, indices[share.Index], "duplicate index found")
			indices[share.Index] = true
		}
	})

	t.Run("shares reference parent CRK", func(t *testing.T) {
		crk, shares, err := generator.Generate(ctx, "org-eth", 3, 5)

		require.NoError(t, err)
		for _, share := range shares {
			assert.Equal(t, crk.ID, share.CRKID)
		}
	})

	t.Run("handles generation failure", func(t *testing.T) {
		generator.FailNext = true

		_, _, err := generator.Generate(ctx, "org-eth", 3, 5)

		require.Error(t, err)
	})
}

func TestCRKReconstruction(t *testing.T) {
	ctx := testutil.TestContext(t)
	generator := mocks.NewCRKGenerator()
	reconstructor := mocks.NewCRKReconstructor()

	t.Run("reconstructs with threshold shares", func(t *testing.T) {
		_, shares, _ := generator.Generate(ctx, "org-eth", 3, 5)

		key, err := reconstructor.Reconstruct(ctx, shares[:3], 3)

		require.NoError(t, err)
		assert.NotEmpty(t, key)
	})

	t.Run("fails with insufficient shares", func(t *testing.T) {
		_, shares, _ := generator.Generate(ctx, "org-eth", 3, 5)

		_, err := reconstructor.Reconstruct(ctx, shares[:2], 3)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCRKThresholdNotMet)
	})

	t.Run("fails with duplicate shares", func(t *testing.T) {
		_, shares, _ := generator.Generate(ctx, "org-eth", 3, 5)
		duplicateShares := []*mocks.CRKGenerateResult{
			generator.Generated[len(generator.Generated)-1],
		}
		_ = duplicateShares

		// Create duplicate by using same share twice
		dupShares := make([]*mocks.CRKGenerateResult, 0)
		_ = dupShares
		sharesCopy := []*mocks.CRKGenerateResult{}
		_ = sharesCopy

		// Use same share multiple times
		testShares := shares[:1]
		testShares = append(testShares, shares[0]) // duplicate
		testShares = append(testShares, shares[2])

		_, err := reconstructor.Reconstruct(ctx, testShares, 3)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrShareDuplicate)
	})

	t.Run("fails with mixed CRK shares", func(t *testing.T) {
		_, shares1, _ := generator.Generate(ctx, "org-a", 3, 5)
		_, shares2, _ := generator.Generate(ctx, "org-b", 3, 5)

		// Mix shares from different CRKs
		mixedShares := []*mocks.CRKGenerateResult{}
		_ = mixedShares

		testShares := append(shares1[:2], shares2[0])

		_, err := reconstructor.Reconstruct(ctx, testShares, 3)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCRKInvalid)
	})
}

func TestCRKShareValidation(t *testing.T) {
	ctx := testutil.TestContext(t)
	generator := mocks.NewCRKGenerator()

	t.Run("share data is not empty", func(t *testing.T) {
		_, shares, err := generator.Generate(ctx, "org-eth", 3, 5)

		require.NoError(t, err)
		for _, share := range shares {
			assert.NotEmpty(t, share.Data)
		}
	})

	t.Run("shares are cryptographically distinct", func(t *testing.T) {
		_, shares, err := generator.Generate(ctx, "org-eth", 3, 5)

		require.NoError(t, err)
		seen := make(map[string]bool)
		for _, share := range shares {
			dataStr := string(share.Data)
			assert.False(t, seen[dataStr], "duplicate share data found")
			seen[dataStr] = true
		}
	})
}

func BenchmarkCRKOperations(b *testing.B) {
	ctx := context.Background()
	generator := mocks.NewCRKGenerator()
	reconstructor := mocks.NewCRKReconstructor()

	b.Run("Generate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _ = generator.Generate(ctx, "org-bench", 3, 5)
		}
	})

	b.Run("Reconstruct", func(b *testing.B) {
		_, shares, _ := generator.Generate(ctx, "org-bench", 3, 5)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = reconstructor.Reconstruct(ctx, shares[:3], 3)
		}
	})
}
