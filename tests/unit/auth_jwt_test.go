package unit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/witlox/sovra/internal/auth/jwt"
)

func TestClaims(t *testing.T) {
	t.Run("valid claims", func(t *testing.T) {
		claims := &jwt.Claims{
			Subject:      "user123",
			Issuer:       "test-issuer",
			ExpiresAt:    time.Now().Add(time.Hour).Unix(),
			IssuedAt:     time.Now().Unix(),
			Organization: "test-org",
			Roles:        []string{"admin", "user"},
		}

		if err := claims.Valid(); err != nil {
			t.Errorf("expected valid claims, got error: %v", err)
		}
	})

	t.Run("expired claims", func(t *testing.T) {
		claims := &jwt.Claims{
			ExpiresAt: time.Now().Add(-time.Hour).Unix(),
		}

		if err := claims.Valid(); !errors.Is(err, jwt.ErrTokenExpired) {
			t.Errorf("expected ErrTokenExpired, got %v", err)
		}
	})

	t.Run("not yet valid claims", func(t *testing.T) {
		claims := &jwt.Claims{
			NotBefore: time.Now().Add(time.Hour).Unix(),
		}

		if err := claims.Valid(); !errors.Is(err, jwt.ErrTokenNotYetValid) {
			t.Errorf("expected ErrTokenNotYetValid, got %v", err)
		}
	})
}

func TestClaimsContext(t *testing.T) {
	claims := &jwt.Claims{
		Subject:      "test-subject",
		Organization: "test-org",
		Roles:        []string{"admin"},
	}

	ctx := jwt.ContextWithClaims(context.Background(), claims)

	retrieved, ok := jwt.ClaimsFromContext(ctx)
	if !ok {
		t.Error("expected to find claims in context")
	}
	if retrieved.Subject != "test-subject" {
		t.Errorf("expected subject 'test-subject', got %s", retrieved.Subject)
	}
	if retrieved.Organization != "test-org" {
		t.Errorf("expected org 'test-org', got %s", retrieved.Organization)
	}
	if len(retrieved.Roles) != 1 || retrieved.Roles[0] != "admin" {
		t.Errorf("expected roles [admin], got %v", retrieved.Roles)
	}
}

func TestNoClaimsInContext(t *testing.T) {
	ctx := context.Background()
	_, ok := jwt.ClaimsFromContext(ctx)
	if ok {
		t.Error("expected no claims in empty context")
	}
}

func TestValidatorErrors(t *testing.T) {
	// Test that proper errors are returned for invalid tokens

	// Invalid token format
	_, err := jwt.NewValidator(jwt.ValidatorConfig{
		PublicKeyPEM: []byte("not a valid key"),
	})
	if err == nil {
		t.Error("expected error for invalid public key")
	}
}

// Note: Full JWT validation tests would require generating actual signed tokens
// which requires private keys. In production, use a library like github.com/golang-jwt/jwt
