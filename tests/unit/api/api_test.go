// Package api contains unit tests for API gateway.
package api

import (
	"context"
	"testing"

	"github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/tests/mocks"
	"github.com/sovra-project/sovra/tests/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthentication(t *testing.T) {
	ctx := testutil.TestContext(t)
	auth := mocks.NewAPIAuthenticator()

	t.Run("authenticates valid token", func(t *testing.T) {
		userID, orgID, roles, err := auth.Authenticate(ctx, "valid-token")

		require.NoError(t, err)
		assert.Equal(t, "user-123", userID)
		assert.Equal(t, "org-eth", orgID)
		assert.Contains(t, roles, "researcher")
	})

	t.Run("authenticates valid certificate", func(t *testing.T) {
		cert := []byte("valid-certificate")

		userID, orgID, roles, err := auth.AuthenticateCert(ctx, cert)

		require.NoError(t, err)
		assert.NotEmpty(t, userID)
		assert.NotEmpty(t, orgID)
		assert.NotEmpty(t, roles)
	})

	t.Run("rejects expired token", func(t *testing.T) {
		auth.TokenExpired = true

		_, _, _, err := auth.Authenticate(ctx, "expired-token")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCertificateExpired)
	})

	t.Run("rejects invalid token", func(t *testing.T) {
		auth.TokenInvalid = true

		_, _, _, err := auth.Authenticate(ctx, "invalid-token")

		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrCertificateInvalid)
	})
}

func TestAuthorization(t *testing.T) {
	ctx := testutil.TestContext(t)
	authz := mocks.NewAPIAuthorizer()

	t.Run("allows permitted action", func(t *testing.T) {
		allowed, err := authz.Authorize(ctx, "user-123", "encrypt", "workspace", "ws-123")

		require.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("denies forbidden action", func(t *testing.T) {
		authz.Deny = true

		allowed, err := authz.Authorize(ctx, "user-123", "delete", "workspace", "ws-123")

		require.NoError(t, err)
		assert.False(t, allowed)
	})
}

func TestRateLimiting(t *testing.T) {
	ctx := testutil.TestContext(t)
	limiter := mocks.NewAPIRateLimiter()

	t.Run("allows request within limit", func(t *testing.T) {
		allowed, err := limiter.Allow(ctx, "user-123")

		require.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("denies request over limit", func(t *testing.T) {
		limiter.Limit = 5

		// Exhaust limit
		for i := 0; i < 5; i++ {
			_, _ = limiter.Allow(ctx, "user-exhaust")
		}

		allowed, err := limiter.Allow(ctx, "user-exhaust")

		require.NoError(t, err)
		assert.False(t, allowed)
	})

	t.Run("resets limit", func(t *testing.T) {
		limiter.Limit = 1
		_, _ = limiter.Allow(ctx, "user-reset")
		allowed, _ := limiter.Allow(ctx, "user-reset")
		assert.False(t, allowed)

		err := limiter.Reset(ctx, "user-reset")
		require.NoError(t, err)

		allowed, _ = limiter.Allow(ctx, "user-reset")
		assert.True(t, allowed)
	})

	t.Run("returns remaining requests", func(t *testing.T) {
		limiter.Limit = 10
		for i := 0; i < 3; i++ {
			_, _ = limiter.Allow(ctx, "user-remaining")
		}

		remaining, err := limiter.GetRemaining(ctx, "user-remaining")

		require.NoError(t, err)
		assert.Equal(t, 7, remaining)
	})
}

func BenchmarkAPIOperations(b *testing.B) {
	ctx := context.Background()

	b.Run("Authentication", func(b *testing.B) {
		auth := mocks.NewAPIAuthenticator()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, _, _ = auth.Authenticate(ctx, "token")
		}
	})

	b.Run("Authorization", func(b *testing.B) {
		authz := mocks.NewAPIAuthorizer()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = authz.Authorize(ctx, "user", "action", "resource", "id")
		}
	})

	b.Run("RateLimiting", func(b *testing.B) {
		limiter := mocks.NewAPIRateLimiter()
		limiter.Limit = 1000000
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = limiter.Allow(ctx, "user-bench")
		}
	})
}
