package policy

import (
	"context"
	"testing"
	"time"

	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPolicyCreate tests policy creation.
func TestPolicyCreate(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockEngine())

	t.Run("create valid policy", func(t *testing.T) {
		req := CreateRequest{
			Name:      "workspace-access",
			Workspace: "cancer-research",
			Rego: `
package workspace.cancer_research

default allow = false

allow {
    input.role == "researcher"
    input.purpose == "analysis"
}
`,
			CRKSignature: []byte("valid-signature"),
		}

		policy, err := service.Create(ctx, req)

		require.NoError(t, err)
		assert.NotEmpty(t, policy.ID)
		assert.Equal(t, "workspace-access", policy.Name)
		assert.Equal(t, "cancer-research", policy.Workspace)
		assert.NotEmpty(t, policy.Rego)
	})

	t.Run("create organization-wide policy", func(t *testing.T) {
		req := CreateRequest{
			Name:      "org-default",
			Workspace: "", // Empty = organization-wide
			Rego: `
package org.default

default allow = false

allow {
    input.role == "admin"
}
`,
			CRKSignature: []byte("valid-signature"),
		}

		policy, err := service.Create(ctx, req)

		require.NoError(t, err)
		assert.Empty(t, policy.Workspace)
	})

	t.Run("fail with invalid Rego syntax", func(t *testing.T) {
		req := CreateRequest{
			Name:      "invalid-policy",
			Workspace: "test",
			Rego: `
package invalid
this is not valid rego syntax
`,
			CRKSignature: []byte("valid-signature"),
		}

		_, err := service.Create(ctx, req)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})

	t.Run("fail without CRK signature", func(t *testing.T) {
		req := CreateRequest{
			Name:      "unsigned-policy",
			Workspace: "test",
			Rego:      "package test\ndefault allow = false",
			CRKSignature: nil,
		}

		_, err := service.Create(ctx, req)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrUnauthorized)
	})

	t.Run("fail with empty name", func(t *testing.T) {
		req := CreateRequest{
			Name:      "",
			Workspace: "test",
			Rego:      "package test\ndefault allow = false",
			CRKSignature: []byte("valid-signature"),
		}

		_, err := service.Create(ctx, req)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})

	t.Run("fail with empty Rego", func(t *testing.T) {
		req := CreateRequest{
			Name:      "empty-rego",
			Workspace: "test",
			Rego:      "",
			CRKSignature: []byte("valid-signature"),
		}

		_, err := service.Create(ctx, req)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})
}

// TestPolicyEvaluate tests policy evaluation.
func TestPolicyEvaluate(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockEngine())

	// Create a policy first
	req := CreateRequest{
		Name:      "research-access",
		Workspace: "cancer-research",
		Rego: `
package workspace.cancer_research

default allow = false

allow {
    input.role == "researcher"
    input.purpose == "analysis"
}

allow {
    input.role == "admin"
}

deny_reason = "unauthorized role" {
    not input.role in ["researcher", "admin"]
}

deny_reason = "invalid purpose" {
    input.role == "researcher"
    input.purpose != "analysis"
}
`,
		CRKSignature: []byte("valid-signature"),
	}
	_, _ = service.Create(ctx, req)

	t.Run("allow researcher with valid purpose", func(t *testing.T) {
		input := models.PolicyInput{
			Actor:     "researcher@eth.ch",
			Role:      "researcher",
			Operation: "decrypt",
			Workspace: "cancer-research",
			Purpose:   "analysis",
			Time:      time.Now(),
		}

		result, err := service.Evaluate(ctx, input)

		require.NoError(t, err)
		assert.True(t, result.Allowed)
	})

	t.Run("allow admin regardless of purpose", func(t *testing.T) {
		input := models.PolicyInput{
			Actor:     "admin@eth.ch",
			Role:      "admin",
			Operation: "decrypt",
			Workspace: "cancer-research",
			Purpose:   "maintenance",
			Time:      time.Now(),
		}

		result, err := service.Evaluate(ctx, input)

		require.NoError(t, err)
		assert.True(t, result.Allowed)
	})

	t.Run("deny researcher with invalid purpose", func(t *testing.T) {
		input := models.PolicyInput{
			Actor:     "researcher@eth.ch",
			Role:      "researcher",
			Operation: "decrypt",
			Workspace: "cancer-research",
			Purpose:   "wrong-purpose",
			Time:      time.Now(),
		}

		result, err := service.Evaluate(ctx, input)

		require.NoError(t, err)
		assert.False(t, result.Allowed)
		assert.NotEmpty(t, result.DenyReason)
	})

	t.Run("deny unauthorized role", func(t *testing.T) {
		input := models.PolicyInput{
			Actor:     "guest@eth.ch",
			Role:      "guest",
			Operation: "decrypt",
			Workspace: "cancer-research",
			Purpose:   "analysis",
			Time:      time.Now(),
		}

		result, err := service.Evaluate(ctx, input)

		require.NoError(t, err)
		assert.False(t, result.Allowed)
		assert.Equal(t, "unauthorized role", result.DenyReason)
	})

	t.Run("evaluate with missing workspace policy uses default deny", func(t *testing.T) {
		input := models.PolicyInput{
			Actor:     "researcher@eth.ch",
			Role:      "researcher",
			Operation: "decrypt",
			Workspace: "no-policy-workspace",
			Purpose:   "analysis",
			Time:      time.Now(),
		}

		result, err := service.Evaluate(ctx, input)

		require.NoError(t, err)
		assert.False(t, result.Allowed)
	})
}

// TestPolicyTimeBased tests time-based policy evaluation.
func TestPolicyTimeBased(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockEngine())

	// Create time-based policy
	req := CreateRequest{
		Name:      "business-hours",
		Workspace: "work-data",
		Rego: `
package workspace.work_data

default allow = false

allow {
    input.role == "employee"
    is_business_hours
}

is_business_hours {
    hour := time.clock(time.parse_rfc3339_ns(input.time))[0]
    hour >= 8
    hour < 18
}
`,
		CRKSignature: []byte("valid-signature"),
	}
	_, _ = service.Create(ctx, req)

	t.Run("allow during business hours", func(t *testing.T) {
		businessHours := time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC) // 10 AM

		input := models.PolicyInput{
			Actor:     "employee@company.com",
			Role:      "employee",
			Operation: "decrypt",
			Workspace: "work-data",
			Purpose:   "work",
			Time:      businessHours,
		}

		result, err := service.Evaluate(ctx, input)

		require.NoError(t, err)
		assert.True(t, result.Allowed)
	})

	t.Run("deny outside business hours", func(t *testing.T) {
		afterHours := time.Date(2026, 1, 30, 22, 0, 0, 0, time.UTC) // 10 PM

		input := models.PolicyInput{
			Actor:     "employee@company.com",
			Role:      "employee",
			Operation: "decrypt",
			Workspace: "work-data",
			Purpose:   "work",
			Time:      afterHours,
		}

		result, err := service.Evaluate(ctx, input)

		require.NoError(t, err)
		assert.False(t, result.Allowed)
	})
}

// TestPolicyUpdate tests policy updates.
func TestPolicyUpdate(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockEngine())

	t.Run("update policy Rego", func(t *testing.T) {
		// Create policy
		req := CreateRequest{
			Name:      "updateable",
			Workspace: "test",
			Rego:      "package test\ndefault allow = false",
			CRKSignature: []byte("valid-signature"),
		}
		policy, err := service.Create(ctx, req)
		require.NoError(t, err)

		// Update policy
		newRego := `
package test

default allow = false

allow {
    input.role == "admin"
}
`
		updated, err := service.Update(ctx, policy.ID, newRego, []byte("valid-signature"))

		require.NoError(t, err)
		assert.Equal(t, policy.ID, updated.ID)
		assert.Contains(t, updated.Rego, "admin")
		assert.True(t, updated.UpdatedAt.After(policy.CreatedAt))
	})

	t.Run("update non-existent policy fails", func(t *testing.T) {
		_, err := service.Update(ctx, "non-existent", "package test", []byte("valid-signature"))

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})

	t.Run("update with invalid Rego fails", func(t *testing.T) {
		req := CreateRequest{
			Name:      "updateable-invalid",
			Workspace: "test",
			Rego:      "package test\ndefault allow = false",
			CRKSignature: []byte("valid-signature"),
		}
		policy, _ := service.Create(ctx, req)

		_, err := service.Update(ctx, policy.ID, "invalid rego syntax!", []byte("valid-signature"))

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrInvalidInput)
	})
}

// TestPolicyDelete tests policy deletion.
func TestPolicyDelete(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockEngine())

	t.Run("delete policy successfully", func(t *testing.T) {
		req := CreateRequest{
			Name:      "deleteable",
			Workspace: "test",
			Rego:      "package test\ndefault allow = false",
			CRKSignature: []byte("valid-signature"),
		}
		policy, _ := service.Create(ctx, req)

		err := service.Delete(ctx, policy.ID, []byte("valid-signature"))

		require.NoError(t, err)

		_, err = service.Get(ctx, policy.ID)
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrNotFound)
	})

	t.Run("delete without signature fails", func(t *testing.T) {
		req := CreateRequest{
			Name:      "protected",
			Workspace: "test",
			Rego:      "package test\ndefault allow = false",
			CRKSignature: []byte("valid-signature"),
		}
		policy, _ := service.Create(ctx, req)

		err := service.Delete(ctx, policy.ID, nil)

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrUnauthorized)
	})
}

// TestPolicyValidation tests Rego validation.
func TestPolicyValidation(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockEngine())

	t.Run("validate correct Rego", func(t *testing.T) {
		rego := `
package valid

default allow = false

allow {
    input.role == "admin"
}
`
		err := service.Validate(ctx, rego)
		assert.NoError(t, err)
	})

	t.Run("validate Rego with syntax error", func(t *testing.T) {
		rego := `
package invalid
this is not valid rego
`
		err := service.Validate(ctx, rego)
		assert.Error(t, err)
	})

	t.Run("validate Rego with missing package", func(t *testing.T) {
		rego := `
default allow = false

allow {
    input.role == "admin"
}
`
		err := service.Validate(ctx, rego)
		assert.Error(t, err)
	})

	t.Run("validate complex Rego policy", func(t *testing.T) {
		rego := `
package complex

import future.keywords.if
import future.keywords.in

default allow = false

allow if {
    input.role in allowed_roles
    valid_time
}

allowed_roles := {"admin", "researcher", "analyst"}

valid_time if {
    now := time.now_ns()
    day := time.weekday(now)
    day != "Saturday"
    day != "Sunday"
}
`
		err := service.Validate(ctx, rego)
		assert.NoError(t, err)
	})
}

// TestPolicyGetForWorkspace tests retrieving policies for a workspace.
func TestPolicyGetForWorkspace(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockEngine())

	t.Run("get policies for workspace", func(t *testing.T) {
		// Create multiple policies for same workspace
		for i := 0; i < 3; i++ {
			req := CreateRequest{
				Name:      "policy-" + string(rune('a'+i)),
				Workspace: "multi-policy-workspace",
				Rego:      "package test\ndefault allow = false",
				CRKSignature: []byte("valid-signature"),
			}
			_, _ = service.Create(ctx, req)
		}

		policies, err := service.GetForWorkspace(ctx, "multi-policy-workspace")

		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(policies), 3)
	})

	t.Run("get empty policies for workspace without policies", func(t *testing.T) {
		policies, err := service.GetForWorkspace(ctx, "no-policies")

		require.NoError(t, err)
		assert.Empty(t, policies)
	})
}

// TestPolicyEvaluationCaching tests that policy evaluation is cached.
func TestPolicyEvaluationCaching(t *testing.T) {
	ctx := context.Background()
	engine := NewMockEngine()
	service := NewService(NewMockRepository(), engine)

	req := CreateRequest{
		Name:      "cached-policy",
		Workspace: "cache-test",
		Rego:      "package cache_test\ndefault allow = true",
		CRKSignature: []byte("valid-signature"),
	}
	_, _ = service.Create(ctx, req)

	input := models.PolicyInput{
		Actor:     "user@test.com",
		Role:      "user",
		Operation: "read",
		Workspace: "cache-test",
		Time:      time.Now(),
	}

	// First evaluation
	result1, _ := service.Evaluate(ctx, input)
	evalCount1 := engine.EvalCount()

	// Second evaluation (should hit cache)
	result2, _ := service.Evaluate(ctx, input)
	evalCount2 := engine.EvalCount()

	assert.Equal(t, result1.Allowed, result2.Allowed)
	assert.Equal(t, evalCount1, evalCount2, "cached evaluation should not increment eval count")
}

// BenchmarkPolicyOperations benchmarks policy operations.
func BenchmarkPolicyOperations(b *testing.B) {
	ctx := context.Background()
	service := NewService(NewMockRepository(), NewMockEngine())

	b.Run("Create policy", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			req := CreateRequest{
				Name:      "bench-" + string(rune('a'+i%26)),
				Workspace: "bench",
				Rego:      "package bench\ndefault allow = false",
				CRKSignature: []byte("valid-signature"),
			}
			_, _ = service.Create(ctx, req)
		}
	})

	b.Run("Evaluate simple policy", func(b *testing.B) {
		req := CreateRequest{
			Name:      "bench-eval",
			Workspace: "bench-eval",
			Rego:      "package bench_eval\ndefault allow = true",
			CRKSignature: []byte("valid-signature"),
		}
		_, _ = service.Create(ctx, req)

		input := models.PolicyInput{
			Actor:     "user@test.com",
			Role:      "user",
			Operation: "read",
			Workspace: "bench-eval",
			Time:      time.Now(),
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = service.Evaluate(ctx, input)
		}
	})

	b.Run("Validate Rego", func(b *testing.B) {
		rego := "package bench\ndefault allow = false\nallow { input.role == \"admin\" }"
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = service.Validate(ctx, rego)
		}
	})
}
