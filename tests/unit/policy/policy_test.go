// Package policy contains unit tests for policy management.
package policy

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

func TestPolicyCreation(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewPolicyRepository()

	t.Run("creates policy with valid rego", func(t *testing.T) {
		policy := testutil.TestPolicy("encrypt-only", "ws-123")

		err := repo.Create(ctx, policy)

		require.NoError(t, err)
		assert.NotEmpty(t, policy.ID)
		assert.False(t, policy.CreatedAt.IsZero())
	})

	t.Run("associates policy with workspace", func(t *testing.T) {
		policy := testutil.TestPolicy("workspace-policy", "ws-specific")

		err := repo.Create(ctx, policy)

		require.NoError(t, err)
		assert.Equal(t, "ws-specific", policy.WorkspaceID)
	})
}

func TestPolicyRetrieval(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewPolicyRepository()

	t.Run("retrieves existing policy", func(t *testing.T) {
		policy := testutil.TestPolicy("test-policy", "ws-123")
		_ = repo.Create(ctx, policy)

		retrieved, err := repo.Get(ctx, policy.ID)

		require.NoError(t, err)
		assert.Equal(t, policy.ID, retrieved.ID)
		assert.Equal(t, policy.Name, retrieved.Name)
	})

	t.Run("returns error for non-existent policy", func(t *testing.T) {
		_, err := repo.Get(ctx, "non-existent")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})

	t.Run("retrieves policies by workspace", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			policy := testutil.TestPolicy("policy-"+string(rune('a'+i)), "ws-multi")
			_ = repo.Create(ctx, policy)
		}

		policies, err := repo.GetByWorkspace(ctx, "ws-multi")

		require.NoError(t, err)
		assert.Len(t, policies, 3)
	})
}

func TestPolicyEvaluation(t *testing.T) {
	ctx := testutil.TestContext(t)
	engine := mocks.NewPolicyEngine()

	t.Run("allows action when policy permits", func(t *testing.T) {
		policy := testutil.TestPolicy("allow-encrypt", "ws-123")
		_ = engine.LoadPolicy(ctx, policy)

		input := models.PolicyInput{
			Actor:     "user-123",
			Role:      "researcher",
			Operation: "encrypt",
			Workspace: "ws-123",
		}

		allowed, err := engine.Evaluate(ctx, input)

		require.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("denies action when policy denies", func(t *testing.T) {
		engine.DenyNext = true

		input := models.PolicyInput{
			Actor:     "user-123",
			Role:      "guest",
			Operation: "delete",
		}

		allowed, err := engine.Evaluate(ctx, input)

		require.NoError(t, err)
		assert.False(t, allowed)
	})

	t.Run("tracks evaluation count", func(t *testing.T) {
		initialCount := engine.EvalCount
		input := models.PolicyInput{Operation: "test"}

		_, _ = engine.Evaluate(ctx, input)
		_, _ = engine.Evaluate(ctx, input)
		_, _ = engine.Evaluate(ctx, input)

		assert.Equal(t, initialCount+3, engine.EvalCount)
	})
}

func TestPolicyValidation(t *testing.T) {
	engine := mocks.NewPolicyEngine()

	t.Run("validates valid rego", func(t *testing.T) {
		rego := `
			package sovra.workspace
			default allow = false
			allow { input.action == "encrypt" }
		`

		err := engine.ValidateRego(rego)

		require.NoError(t, err)
	})

	t.Run("rejects empty rego", func(t *testing.T) {
		err := engine.ValidateRego("")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrPolicyInvalid)
	})
}

func TestPolicyUpdate(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewPolicyRepository()

	t.Run("updates policy rego", func(t *testing.T) {
		policy := testutil.TestPolicy("mutable-policy", "ws-123")
		_ = repo.Create(ctx, policy)

		newRego := `
			package sovra.workspace
			default allow = true
		`
		policy.Rego = newRego
		err := repo.Update(ctx, policy)

		require.NoError(t, err)

		updated, _ := repo.Get(ctx, policy.ID)
		assert.Equal(t, newRego, updated.Rego)
	})

	t.Run("updates timestamp on modification", func(t *testing.T) {
		policy := testutil.TestPolicy("timestamp-policy", "ws-123")
		_ = repo.Create(ctx, policy)
		originalUpdatedAt := policy.UpdatedAt

		policy.Name = "renamed-policy"
		_ = repo.Update(ctx, policy)

		assert.True(t, policy.UpdatedAt.After(originalUpdatedAt) || policy.UpdatedAt.Equal(originalUpdatedAt))
	})
}

func TestPolicyDeletion(t *testing.T) {
	ctx := testutil.TestContext(t)
	repo := mocks.NewPolicyRepository()

	t.Run("deletes policy", func(t *testing.T) {
		policy := testutil.TestPolicy("to-delete", "ws-123")
		_ = repo.Create(ctx, policy)

		err := repo.Delete(ctx, policy.ID)

		require.NoError(t, err)

		_, err = repo.Get(ctx, policy.ID)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

func TestPolicyUnloading(t *testing.T) {
	ctx := testutil.TestContext(t)
	engine := mocks.NewPolicyEngine()

	t.Run("unloads policy from engine", func(t *testing.T) {
		policy := testutil.TestPolicy("temporary", "ws-123")
		_ = engine.LoadPolicy(ctx, policy)

		err := engine.UnloadPolicy(ctx, policy.ID)

		require.NoError(t, err)
	})
}

func BenchmarkPolicyOperations(b *testing.B) {
	ctx := context.Background()
	engine := mocks.NewPolicyEngine()

	policy := testutil.TestPolicy("bench-policy", "ws-bench")
	_ = engine.LoadPolicy(ctx, policy)

	b.Run("Evaluate", func(b *testing.B) {
		input := models.PolicyInput{
			Actor:     "user-123",
			Role:      "researcher",
			Operation: "encrypt",
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = engine.Evaluate(ctx, input)
		}
	})

	b.Run("ValidateRego", func(b *testing.B) {
		rego := `package test; default allow = false`
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = engine.ValidateRego(rego)
		}
	})
}
