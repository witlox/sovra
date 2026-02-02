// Package integration contains integration tests with real infrastructure.
package integration

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/pkg/opa"
)

// TestOPAClientIntegration tests the OPA client with a real OPA instance.
func TestOPAClientIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	WithOPA(t, func(t *testing.T, oc *OPAContainer) {
		client := opa.NewClient(oc.Address)
		ctx := context.Background()

		t.Run("health check", func(t *testing.T) {
			err := client.Health(ctx)
			require.NoError(t, err)
		})

		t.Run("upload and get policy", func(t *testing.T) {
			policyID := "test/allow"
			policyContent := `
package test

default allow = false

allow {
	input.role == "admin"
}
`
			err := client.UploadPolicy(ctx, policyID, policyContent)
			require.NoError(t, err)

			// Get the policy
			policy, err := client.GetPolicy(ctx, policyID)
			require.NoError(t, err)
			assert.Equal(t, policyID, policy.ID)
			assert.Contains(t, policy.Raw, "default allow = false")
		})

		t.Run("list policies", func(t *testing.T) {
			// Upload a policy first
			policyID := "test/list"
			policyContent := `package test.list
default allow = true`
			err := client.UploadPolicy(ctx, policyID, policyContent)
			require.NoError(t, err)

			// List policies
			policies, err := client.ListPolicies(ctx)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, len(policies), 1)
		})

		t.Run("delete policy", func(t *testing.T) {
			policyID := "test/delete"
			policyContent := `package test.delete
default allow = true`

			// Upload
			err := client.UploadPolicy(ctx, policyID, policyContent)
			require.NoError(t, err)

			// Verify exists
			_, err = client.GetPolicy(ctx, policyID)
			require.NoError(t, err)

			// Delete
			err = client.DeletePolicy(ctx, policyID)
			require.NoError(t, err)

			// Verify deleted
			_, err = client.GetPolicy(ctx, policyID)
			require.Error(t, err)
		})

		t.Run("evaluate policy allows admin", func(t *testing.T) {
			policyID := "test/rbac"
			policyContent := `
package test.rbac

default allow = false

allow {
	input.role == "admin"
}

allow {
	input.role == "researcher"
	input.operation == "read"
}
`
			err := client.UploadPolicy(ctx, policyID, policyContent)
			require.NoError(t, err)

			// Test admin access
			input := models.PolicyInput{
				Role:      "admin",
				Operation: "delete",
			}
			result, err := client.EvaluateDecision(ctx, "test/rbac/allow", input)
			require.NoError(t, err)
			assert.True(t, result.Allow)
		})

		t.Run("evaluate policy denies guest", func(t *testing.T) {
			// Reuse the rbac policy from above
			input := models.PolicyInput{
				Role:      "guest",
				Operation: "delete",
			}
			result, err := client.EvaluateDecision(ctx, "test/rbac/allow", input)
			require.NoError(t, err)
			assert.False(t, result.Allow)
		})

		t.Run("evaluate policy allows researcher read", func(t *testing.T) {
			input := models.PolicyInput{
				Role:      "researcher",
				Operation: "read",
			}
			result, err := client.EvaluateDecision(ctx, "test/rbac/allow", input)
			require.NoError(t, err)
			assert.True(t, result.Allow)
		})

		t.Run("evaluate policy denies researcher write", func(t *testing.T) {
			input := models.PolicyInput{
				Role:      "researcher",
				Operation: "write",
			}
			result, err := client.EvaluateDecision(ctx, "test/rbac/allow", input)
			require.NoError(t, err)
			assert.False(t, result.Allow)
		})

		t.Run("evaluate raw input", func(t *testing.T) {
			policyID := "test/raw"
			policyContent := `
package test.raw

result := {"count": count(input.items)}
`
			err := client.UploadPolicy(ctx, policyID, policyContent)
			require.NoError(t, err)

			rawInput := map[string]any{
				"items": []string{"a", "b", "c"},
			}
			result, err := client.EvaluateRaw(ctx, "test/raw/result", rawInput)
			require.NoError(t, err)
			assert.NotNil(t, result.Result)
		})

		t.Run("workspace access policy", func(t *testing.T) {
			// Upload a workspace access policy matching Sovra docs
			policyID := "sovra/workspace"
			policyContent := `
package sovra.workspace

default allow = false

# Allow org members to access their workspaces
allow {
	input.operation == "encrypt"
	input.workspace != ""
}

allow {
	input.operation == "decrypt"
	input.workspace != ""
	input.role == "researcher"
}

# Deny if classification is too high for role
deny {
	input.classification == "SECRET"
	input.role != "admin"
}
`
			err := client.UploadPolicy(ctx, policyID, policyContent)
			require.NoError(t, err)

			// Test encrypt allowed
			input := models.PolicyInput{
				Operation: "encrypt",
				Workspace: "ws-123",
				Role:      "researcher",
			}
			result, err := client.EvaluateDecision(ctx, "sovra/workspace/allow", input)
			require.NoError(t, err)
			assert.True(t, result.Allow)

			// Test decrypt allowed for researcher
			input.Operation = "decrypt"
			result, err = client.EvaluateDecision(ctx, "sovra/workspace/allow", input)
			require.NoError(t, err)
			assert.True(t, result.Allow)
		})
	})
}
