// Package jwt tests JWT validation.
package jwt_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/witlox/sovra/internal/auth/jwt"
)

// generateRSAKeyPair generates a new RSA key pair for testing.
func generateRSAKeyPair(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return privateKey, pubKeyPEM
}

func TestNewValidator(t *testing.T) {
	_, pubKeyPEM := generateRSAKeyPair(t)

	cfg := jwt.ValidatorConfig{
		PublicKeyPEM:   pubKeyPEM,
		ExpectedIssuer: "test-issuer",
		ExpectedAuds:   []string{"test-aud"},
	}

	validator, err := jwt.NewValidator(cfg)
	require.NoError(t, err)
	require.NotNil(t, validator)
}

func TestNewValidator_InvalidKey(t *testing.T) {
	cfg := jwt.ValidatorConfig{
		PublicKeyPEM: []byte("invalid key"),
	}

	_, err := jwt.NewValidator(cfg)
	require.Error(t, err)
}

func TestNewValidator_DefaultClockSkew(t *testing.T) {
	_, pubKeyPEM := generateRSAKeyPair(t)

	cfg := jwt.ValidatorConfig{
		PublicKeyPEM: pubKeyPEM,
		ClockSkew:    0, // Should default to 30 seconds
	}

	validator, err := jwt.NewValidator(cfg)
	require.NoError(t, err)
	require.NotNil(t, validator)
}

func TestClaimsValid(t *testing.T) {
	tests := []struct {
		name        string
		claims      jwt.Claims
		expectError error
	}{
		{
			name:        "valid claims",
			claims:      jwt.Claims{ExpiresAt: time.Now().Add(time.Hour).Unix()},
			expectError: nil,
		},
		{
			name:        "expired token",
			claims:      jwt.Claims{ExpiresAt: time.Now().Add(-time.Hour).Unix()},
			expectError: jwt.ErrTokenExpired,
		},
		{
			name:        "not yet valid",
			claims:      jwt.Claims{NotBefore: time.Now().Add(time.Hour).Unix()},
			expectError: jwt.ErrTokenNotYetValid,
		},
		{
			name:        "no expiry (valid)",
			claims:      jwt.Claims{},
			expectError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.claims.Valid()
			if tt.expectError != nil {
				assert.ErrorIs(t, err, tt.expectError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidate_InvalidToken(t *testing.T) {
	_, pubKeyPEM := generateRSAKeyPair(t)

	cfg := jwt.ValidatorConfig{
		PublicKeyPEM: pubKeyPEM,
	}
	validator, err := jwt.NewValidator(cfg)
	require.NoError(t, err)

	tests := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"single part", "single"},
		{"two parts", "part1.part2"},
		{"invalid base64 header", "!!!.!!.!!"},
		{"invalid base64 claims", base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + ".!!!.!!!"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validator.Validate(tt.token)
			assert.Error(t, err)
		})
	}
}

func TestContextWithClaims(t *testing.T) {
	claims := &jwt.Claims{
		Subject:      "user-123",
		Organization: "org-456",
		Roles:        []string{"admin"},
	}

	ctx := context.Background()
	ctx = jwt.ContextWithClaims(ctx, claims)

	retrieved, ok := jwt.ClaimsFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, claims.Subject, retrieved.Subject)
	assert.Equal(t, claims.Organization, retrieved.Organization)
	assert.Equal(t, claims.Roles, retrieved.Roles)
}

func TestClaimsFromContext_NotFound(t *testing.T) {
	ctx := context.Background()
	claims, ok := jwt.ClaimsFromContext(ctx)
	assert.False(t, ok)
	assert.Nil(t, claims)
}

func TestClaims_FullFields(t *testing.T) {
	now := time.Now()
	claims := jwt.Claims{
		Issuer:       "test-issuer",
		Subject:      "user-123",
		Audience:     []string{"aud1", "aud2"},
		ExpiresAt:    now.Add(time.Hour).Unix(),
		NotBefore:    now.Add(-time.Minute).Unix(),
		IssuedAt:     now.Unix(),
		JWTID:        "jti-abc",
		Organization: "org-456",
		Roles:        []string{"admin", "user"},
		Scopes:       []string{"read", "write"},
	}

	err := claims.Valid()
	require.NoError(t, err)

	// Test JSON marshaling
	data, err := json.Marshal(claims)
	require.NoError(t, err)
	assert.Contains(t, string(data), "test-issuer")
	assert.Contains(t, string(data), "user-123")
}

func TestHeader(t *testing.T) {
	header := jwt.Header{
		Algorithm: "RS256",
		Type:      "JWT",
		KeyID:     "key-123",
	}

	data, err := json.Marshal(header)
	require.NoError(t, err)
	assert.Contains(t, string(data), "RS256")
	assert.Contains(t, string(data), "JWT")
	assert.Contains(t, string(data), "key-123")
}

func TestValidatorConfig(t *testing.T) {
	cfg := jwt.ValidatorConfig{
		PublicKeyPEM:   []byte("key"),
		ExpectedIssuer: "issuer",
		ExpectedAuds:   []string{"aud1", "aud2"},
		ClockSkew:      time.Minute,
	}

	assert.Equal(t, "issuer", cfg.ExpectedIssuer)
	assert.Len(t, cfg.ExpectedAuds, 2)
	assert.Equal(t, time.Minute, cfg.ClockSkew)
}

func TestErrorTypes(t *testing.T) {
	// Verify error types are properly defined
	require.Error(t, jwt.ErrInvalidToken)
	require.Error(t, jwt.ErrTokenExpired)
	require.Error(t, jwt.ErrTokenNotYetValid)
	require.Error(t, jwt.ErrInvalidSignature)
	require.Error(t, jwt.ErrUnsupportedAlgorithm)
	require.Error(t, jwt.ErrInvalidIssuer)
	require.Error(t, jwt.ErrInvalidAudience)
}

func TestMiddleware_NoToken(t *testing.T) {
	_, pubKeyPEM := generateRSAKeyPair(t)
	validator, err := jwt.NewValidator(jwt.ValidatorConfig{PublicKeyPEM: pubKeyPEM})
	require.NoError(t, err)

	handler := jwt.Middleware(validator)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddleware_InvalidToken(t *testing.T) {
	_, pubKeyPEM := generateRSAKeyPair(t)
	validator, err := jwt.NewValidator(jwt.ValidatorConfig{PublicKeyPEM: pubKeyPEM})
	require.NoError(t, err)

	handler := jwt.Middleware(validator)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestOptionalMiddleware_NoToken(t *testing.T) {
	_, pubKeyPEM := generateRSAKeyPair(t)
	validator, err := jwt.NewValidator(jwt.ValidatorConfig{PublicKeyPEM: pubKeyPEM})
	require.NoError(t, err)

	handler := jwt.OptionalMiddleware(validator)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := jwt.ClaimsFromContext(r.Context())
		if ok {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code) // No claims in context
}

func TestOptionalMiddleware_InvalidToken(t *testing.T) {
	_, pubKeyPEM := generateRSAKeyPair(t)
	validator, err := jwt.NewValidator(jwt.ValidatorConfig{PublicKeyPEM: pubKeyPEM})
	require.NoError(t, err)

	handler := jwt.OptionalMiddleware(validator)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := jwt.ClaimsFromContext(r.Context())
		if ok {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code) // Invalid token ignored
}
