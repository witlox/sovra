// Package policy contains unit tests for policy management.
package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/policy"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/tests/testutil"
	"github.com/witlox/sovra/tests/testutil/inmemory"
)

// createTestService creates a policy service with inmemory dependencies.
func createTestService() (policy.Service, *inmemory.PolicyRepository, *inmemory.OPAClient) {
	repo := inmemory.NewPolicyRepository()
	opaClient := inmemory.NewOPAClient()
	svc := policy.NewPolicyService(repo, opaClient, nil)
	return svc, repo, opaClient
}

func TestPolicyCreation(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc, _, opaClient := createTestService()

	t.Run("creates policy with valid rego", func(t *testing.T) {
		req := policy.CreateRequest{
			Name:      "encrypt-only",
			Workspace: "ws-123",
			Rego: `package sovra.workspace
default allow = false
allow { input.operation == "encrypt" }`,
		}

		p, err := svc.Create(ctx, req)

		require.NoError(t, err)
		assert.NotEmpty(t, p.ID)
		assert.Equal(t, "encrypt-only", p.Name)
		assert.Equal(t, "ws-123", p.WorkspaceID)
		assert.Equal(t, 1, p.Version)
		assert.False(t, p.CreatedAt.IsZero())

		// Verify policy was uploaded to OPA
		_, exists := opaClient.GetPolicy("sovra-policy-" + p.ID)
		assert.True(t, exists)
	})

	t.Run("rejects invalid rego syntax", func(t *testing.T) {
		req := policy.CreateRequest{
			Name:      "invalid-policy",
			Workspace: "ws-123",
			Rego:      "this is not valid rego {{{",
		}

		_, err := svc.Create(ctx, req)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrPolicyInvalid)
	})

	t.Run("rejects empty rego", func(t *testing.T) {
		req := policy.CreateRequest{
			Name:      "empty-policy",
			Workspace: "ws-123",
			Rego:      "",
		}

		_, err := svc.Create(ctx, req)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrPolicyInvalid)
	})
}

func TestPolicyRetrieval(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc, _, _ := createTestService()

	t.Run("retrieves existing policy", func(t *testing.T) {
		req := policy.CreateRequest{
			Name:      "test-policy",
			Workspace: "ws-123",
			Rego: `package test
default allow = true`,
		}
		created, err := svc.Create(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, created)

		retrieved, err := svc.Get(ctx, created.ID)

		require.NoError(t, err)
		assert.Equal(t, created.ID, retrieved.ID)
		assert.Equal(t, created.Name, retrieved.Name)
	})

	t.Run("returns error for non-existent policy", func(t *testing.T) {
		_, err := svc.Get(ctx, "non-existent")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})

	t.Run("retrieves policies by workspace", func(t *testing.T) {
		// Create policies for specific workspace
		for i := 0; i < 3; i++ {
			req := policy.CreateRequest{
				Name:      "policy-" + string(rune('a'+i)),
				Workspace: "ws-multi",
				Rego: `package test
default allow = true`,
			}
			_, err := svc.Create(ctx, req)
			require.NoError(t, err)
		}

		policies, err := svc.GetForWorkspace(ctx, "ws-multi")

		require.NoError(t, err)
		assert.Len(t, policies, 3)
	})
}

func TestPolicyEvaluation(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc, _, opaClient := createTestService()

	t.Run("allows action when policy permits", func(t *testing.T) {
		input := models.PolicyInput{
			Actor:     "user-123",
			Role:      "researcher",
			Operation: "encrypt",
			Workspace: "ws-123",
		}

		result, err := svc.Evaluate(ctx, input)

		require.NoError(t, err)
		assert.True(t, result.Allowed)
	})

	t.Run("denies action when policy denies", func(t *testing.T) {
		opaClient.SetDenyNext(true)

		input := models.PolicyInput{
			Actor:     "user-123",
			Role:      "guest",
			Operation: "delete",
		}

		result, err := svc.Evaluate(ctx, input)

		require.NoError(t, err)
		assert.False(t, result.Allowed)
		assert.NotEmpty(t, result.DenyReason)
	})

	t.Run("evaluates with all input fields", func(t *testing.T) {
		input := models.PolicyInput{
			Actor:     "admin-user",
			Role:      "admin",
			Operation: "manage",
			Workspace: "ws-critical",
			Purpose:   "administrative task",
		}

		result, err := svc.Evaluate(ctx, input)

		require.NoError(t, err)
		assert.True(t, result.Allowed)
	})

	t.Run("evaluates different operations", func(t *testing.T) {
		operations := []string{"create", "read", "update", "delete", "encrypt", "decrypt"}

		for _, op := range operations {
			input := models.PolicyInput{
				Actor:     "user-123",
				Role:      "researcher",
				Operation: op,
				Workspace: "ws-ops-test",
			}

			result, err := svc.Evaluate(ctx, input)

			require.NoError(t, err, "operation %s should evaluate", op)
			assert.True(t, result.Allowed, "operation %s should be allowed", op)
		}
	})
}

func TestPolicyValidation(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc, _, _ := createTestService()

	t.Run("validates valid rego", func(t *testing.T) {
		rego := `
			package sovra.workspace
			default allow = false
			allow { input.action == "encrypt" }
		`

		err := svc.Validate(ctx, rego)

		require.NoError(t, err)
	})

	t.Run("rejects empty rego", func(t *testing.T) {
		err := svc.Validate(ctx, "")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrPolicyInvalid)
	})

	t.Run("rejects invalid rego syntax", func(t *testing.T) {
		err := svc.Validate(ctx, "invalid rego {{{}}")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrPolicyInvalid)
	})
}

func TestPolicyUpdate(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc, _, opaClient := createTestService()

	t.Run("updates policy rego", func(t *testing.T) {
		req := policy.CreateRequest{
			Name:      "mutable-policy",
			Workspace: "ws-123",
			Rego: `package test
default allow = false`,
		}
		created, err := svc.Create(ctx, req)
		require.NoError(t, err)

		newRego := `
			package sovra.workspace
			default allow = true
		`
		updated, err := svc.Update(ctx, created.ID, newRego, nil)

		require.NoError(t, err)
		assert.Equal(t, 2, updated.Version)
		assert.Contains(t, updated.Rego, "default allow = true")

		// Verify OPA was updated
		_, exists := opaClient.GetPolicy("sovra-policy-" + created.ID)
		assert.True(t, exists)
	})

	t.Run("rejects update with invalid rego", func(t *testing.T) {
		req := policy.CreateRequest{
			Name:      "update-test",
			Workspace: "ws-123",
			Rego: `package test
default allow = false`,
		}
		created, err := svc.Create(ctx, req)
		require.NoError(t, err)

		_, err = svc.Update(ctx, created.ID, "invalid rego {{{", nil)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrPolicyInvalid)
	})

	t.Run("returns error for non-existent policy", func(t *testing.T) {
		_, err := svc.Update(ctx, "non-existent", `package test`, nil)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

func TestPolicyDeletion(t *testing.T) {
	ctx := testutil.TestContext(t)
	svc, _, opaClient := createTestService()

	t.Run("deletes policy", func(t *testing.T) {
		req := policy.CreateRequest{
			Name:      "to-delete",
			Workspace: "ws-123",
			Rego: `package test
default allow = false`,
		}
		created, err := svc.Create(ctx, req)
		require.NoError(t, err)
		policyOPAID := "sovra-policy-" + created.ID

		// Verify policy exists in OPA
		_, exists := opaClient.GetPolicy(policyOPAID)
		assert.True(t, exists)

		err = svc.Delete(ctx, created.ID, nil)

		require.NoError(t, err)

		// Verify policy was removed from OPA
		_, exists = opaClient.GetPolicy(policyOPAID)
		assert.False(t, exists)

		// Verify policy cannot be retrieved
		_, err = svc.Get(ctx, created.ID)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})

	t.Run("returns error for non-existent policy", func(t *testing.T) {
		err := svc.Delete(ctx, "non-existent", nil)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})
}

func BenchmarkPolicyOperations(b *testing.B) {
	ctx := context.Background()
	svc, _, _ := createTestService()

	// Create a policy for benchmarking
	req := policy.CreateRequest{
		Name:      "bench-policy",
		Workspace: "ws-bench",
		Rego: `package bench
default allow = true`,
	}
	_, _ = svc.Create(ctx, req)

	b.Run("Evaluate", func(b *testing.B) {
		input := models.PolicyInput{
			Actor:     "user-123",
			Role:      "researcher",
			Operation: "encrypt",
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = svc.Evaluate(ctx, input)
		}
	})

	b.Run("Validate", func(b *testing.B) {
		rego := `package test; default allow = false`
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = svc.Validate(ctx, rego)
		}
	})
}
