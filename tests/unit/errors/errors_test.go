// Package errors_test contains tests for error types.
package errors_test

import (
	"errors"
	"testing"

	pkgErrors "github.com/sovra-project/sovra/pkg/errors"
	"github.com/stretchr/testify/assert"
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

		assert.True(t, errors.Is(err, cause))
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

		assert.True(t, errors.Is(err, cause))
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
		assert.NotNil(t, pkgErrors.ErrNotFound)
		assert.NotNil(t, pkgErrors.ErrUnauthorized)
		assert.NotNil(t, pkgErrors.ErrForbidden)
		assert.NotNil(t, pkgErrors.ErrInvalidInput)
		assert.NotNil(t, pkgErrors.ErrConflict)
		assert.NotNil(t, pkgErrors.ErrInternalError)
		assert.NotNil(t, pkgErrors.ErrCRKInvalid)
		assert.NotNil(t, pkgErrors.ErrCRKThresholdNotMet)
		assert.NotNil(t, pkgErrors.ErrShareInvalid)
		assert.NotNil(t, pkgErrors.ErrShareDuplicate)
		assert.NotNil(t, pkgErrors.ErrFederationFailed)
		assert.NotNil(t, pkgErrors.ErrFederationNotEstablished)
		assert.NotNil(t, pkgErrors.ErrWorkspaceNotFound)
		assert.NotNil(t, pkgErrors.ErrPolicyViolation)
		assert.NotNil(t, pkgErrors.ErrPolicyInvalid)
		assert.NotNil(t, pkgErrors.ErrVaultSealed)
		assert.NotNil(t, pkgErrors.ErrEdgeNodeOffline)
		assert.NotNil(t, pkgErrors.ErrEdgeNodeUnreachable)
		assert.NotNil(t, pkgErrors.ErrKeyNotFound)
		assert.NotNil(t, pkgErrors.ErrCertificateExpired)
		assert.NotNil(t, pkgErrors.ErrCertificateInvalid)
	})

	t.Run("errors can be wrapped", func(t *testing.T) {
		wrapped := errors.Join(pkgErrors.ErrNotFound, errors.New("additional context"))

		assert.True(t, errors.Is(wrapped, pkgErrors.ErrNotFound))
	})
}
