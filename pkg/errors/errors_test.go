// Package errors_test contains tests for error types.
package errors_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pkgErrors "github.com/witlox/sovra/pkg/errors"
)

func TestValidationError(t *testing.T) {
	t.Run("creates validation error", func(t *testing.T) {
		err := pkgErrors.NewValidationError("email", "invalid format")

		assert.Equal(t, "email", err.Field)
		assert.Equal(t, "invalid format", err.Message)
		assert.Contains(t, err.Error(), "email")
		assert.Contains(t, err.Error(), "invalid format")
	})
}

func TestCRKError(t *testing.T) {
	t.Run("creates CRK error with cause", func(t *testing.T) {
		cause := errors.New("network timeout")
		err := pkgErrors.NewCRKError("reconstruct", cause)

		assert.Equal(t, "reconstruct", err.Operation)
		assert.Equal(t, cause, err.Cause)
		assert.Contains(t, err.Error(), "reconstruct")
		assert.Contains(t, err.Error(), "network timeout")
	})

	t.Run("unwraps to cause", func(t *testing.T) {
		cause := errors.New("threshold not met")
		err := pkgErrors.NewCRKError("verify", cause)

		assert.ErrorIs(t, err, cause)
	})
}

func TestFederationError(t *testing.T) {
	t.Run("creates federation error", func(t *testing.T) {
		cause := errors.New("connection refused")
		err := pkgErrors.NewFederationError("partner-org", "handshake", cause)

		assert.Equal(t, "partner-org", err.PartnerID)
		assert.Equal(t, "handshake", err.Operation)
		assert.Contains(t, err.Error(), "partner-org")
		assert.Contains(t, err.Error(), "handshake")
	})

	t.Run("unwraps to cause", func(t *testing.T) {
		cause := errors.New("certificate invalid")
		err := pkgErrors.NewFederationError("org-1", "verify", cause)

		assert.ErrorIs(t, err, cause)
	})
}

func TestPolicyError(t *testing.T) {
	t.Run("creates policy error", func(t *testing.T) {
		err := pkgErrors.NewPolicyError("policy-123", "user:read", "insufficient permissions")

		assert.Equal(t, "policy-123", err.PolicyID)
		assert.Equal(t, "user:read", err.Input)
		assert.Equal(t, "insufficient permissions", err.Reason)
		assert.Contains(t, err.Error(), "policy-123")
		assert.Contains(t, err.Error(), "insufficient permissions")
	})
}

func TestSentinelErrors(t *testing.T) {
	t.Run("sentinel errors are defined", func(t *testing.T) {
		require.Error(t, pkgErrors.ErrNotFound)
		require.Error(t, pkgErrors.ErrUnauthorized)
		require.Error(t, pkgErrors.ErrForbidden)
		require.Error(t, pkgErrors.ErrInvalidInput)
		require.Error(t, pkgErrors.ErrConflict)
		require.Error(t, pkgErrors.ErrInternalError)
		require.Error(t, pkgErrors.ErrCRKInvalid)
		require.Error(t, pkgErrors.ErrCRKThresholdNotMet)
		require.Error(t, pkgErrors.ErrShareInvalid)
		require.Error(t, pkgErrors.ErrShareDuplicate)
		require.Error(t, pkgErrors.ErrFederationFailed)
		require.Error(t, pkgErrors.ErrFederationNotEstablished)
		require.Error(t, pkgErrors.ErrWorkspaceNotFound)
		require.Error(t, pkgErrors.ErrPolicyViolation)
		require.Error(t, pkgErrors.ErrPolicyInvalid)
		require.Error(t, pkgErrors.ErrVaultSealed)
		require.Error(t, pkgErrors.ErrEdgeNodeOffline)
		require.Error(t, pkgErrors.ErrEdgeNodeUnreachable)
		require.Error(t, pkgErrors.ErrKeyNotFound)
		require.Error(t, pkgErrors.ErrCertificateExpired)
		require.Error(t, pkgErrors.ErrCertificateInvalid)
	})

	t.Run("errors can be wrapped", func(t *testing.T) {
		wrapped := errors.Join(pkgErrors.ErrNotFound, errors.New("additional context"))

		assert.ErrorIs(t, wrapped, pkgErrors.ErrNotFound)
	})
}
