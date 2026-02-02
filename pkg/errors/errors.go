// Package errors defines custom error types for Sovra.
package errors

import (
	"errors"
	"fmt"
)

// Sentinel errors for common error cases.
var (
	ErrNotFound                 = errors.New("resource not found")
	ErrUnauthorized             = errors.New("unauthorized")
	ErrForbidden                = errors.New("access forbidden")
	ErrInvalidInput             = errors.New("invalid input")
	ErrConflict                 = errors.New("resource conflict")
	ErrInternalError            = errors.New("internal error")
	ErrCRKInvalid               = errors.New("invalid CRK")
	ErrCRKThresholdNotMet       = errors.New("CRK threshold not met")
	ErrShareInvalid             = errors.New("invalid share")
	ErrShareDuplicate           = errors.New("duplicate share")
	ErrFederationFailed         = errors.New("federation failed")
	ErrFederationNotEstablished = errors.New("federation not established")
	ErrWorkspaceNotFound        = errors.New("workspace not found")
	ErrPolicyViolation          = errors.New("policy violation")
	ErrPolicyInvalid            = errors.New("invalid policy")
	ErrVaultSealed              = errors.New("vault is sealed")
	ErrEdgeNodeOffline          = errors.New("edge node offline")
	ErrEdgeNodeUnreachable      = errors.New("edge node unreachable")
	ErrKeyNotFound              = errors.New("key not found")
	ErrCertificateExpired       = errors.New("certificate expired")
	ErrCertificateInvalid       = errors.New("certificate invalid")
)

// ValidationError represents a validation error with field-specific details.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error: %s - %s", e.Field, e.Message)
}

// NewValidationError creates a new validation error.
func NewValidationError(field, message string) *ValidationError {
	return &ValidationError{Field: field, Message: message}
}

// CRKError represents an error related to CRK operations.
type CRKError struct {
	Operation string
	Cause     error
}

func (e *CRKError) Error() string {
	return fmt.Sprintf("CRK operation '%s' failed: %v", e.Operation, e.Cause)
}

func (e *CRKError) Unwrap() error {
	return e.Cause
}

// NewCRKError creates a new CRK error.
func NewCRKError(operation string, cause error) *CRKError {
	return &CRKError{Operation: operation, Cause: cause}
}

// FederationError represents an error related to federation operations.
type FederationError struct {
	PartnerID string
	Operation string
	Cause     error
}

func (e *FederationError) Error() string {
	return fmt.Sprintf("federation with '%s' failed during '%s': %v", e.PartnerID, e.Operation, e.Cause)
}

func (e *FederationError) Unwrap() error {
	return e.Cause
}

// NewFederationError creates a new federation error.
func NewFederationError(partnerID, operation string, cause error) *FederationError {
	return &FederationError{PartnerID: partnerID, Operation: operation, Cause: cause}
}

// PolicyError represents an error related to policy evaluation.
type PolicyError struct {
	PolicyID string
	Input    string
	Reason   string
}

func (e *PolicyError) Error() string {
	return fmt.Sprintf("policy '%s' denied access: %s", e.PolicyID, e.Reason)
}

// NewPolicyError creates a new policy error.
func NewPolicyError(policyID, input, reason string) *PolicyError {
	return &PolicyError{PolicyID: policyID, Input: input, Reason: reason}
}
