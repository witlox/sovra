package idp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/identity/idp"
)

func setupMockIDP(t *testing.T, userHandler http.HandlerFunc) (*httptest.Server, *idp.OIDCChecker) {
	t.Helper()

	mux := http.NewServeMux()

	// Token endpoint
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	// User lookup endpoint
	mux.HandleFunc("/users/", userHandler)

	// Discovery endpoint
	server := httptest.NewServer(mux)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token_endpoint":    server.URL + "/oauth2/token",
			"userinfo_endpoint": server.URL + "/userinfo",
		})
	})

	checker, err := idp.NewOIDCChecker(idp.OIDCCheckerConfig{
		IssuerURL:            server.URL,
		ClientID:             "test-client",
		OIDCSecret:           "test-secret",
		UserEndpointTemplate: server.URL + "/users/{{subject}}",
		HTTPClient:           server.Client(),
	})
	require.NoError(t, err)

	t.Cleanup(server.Close)
	return server, checker
}

func TestCheckSubject_Active(t *testing.T) {
	_, checker := setupMockIDP(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "user-123"})
	})

	status := checker.CheckSubject(context.Background(), "user-123")
	assert.True(t, status.Active)
	assert.NoError(t, status.Error)
}

func TestCheckSubject_NotFound(t *testing.T) {
	_, checker := setupMockIDP(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	status := checker.CheckSubject(context.Background(), "deleted-user")
	assert.False(t, status.Active)
	assert.NoError(t, status.Error)
}

func TestCheckSubject_ServerError(t *testing.T) {
	_, checker := setupMockIDP(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	status := checker.CheckSubject(context.Background(), "user-123")
	require.Error(t, status.Error)
	assert.ErrorIs(t, status.Error, idp.ErrIDPUnreachable)
}

func TestCheckSubject_AuthorizationHeader(t *testing.T) {
	var gotAuth string
	_, checker := setupMockIDP(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})

	checker.CheckSubject(context.Background(), "user-123")
	assert.Equal(t, "Bearer mock-access-token", gotAuth)
}

func TestNewOIDCChecker_DiscoveryFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := idp.NewOIDCChecker(idp.OIDCCheckerConfig{
		IssuerURL:  server.URL,
		ClientID:   "test",
		HTTPClient: server.Client(),
	})
	assert.Error(t, err)
}

func TestNewOIDCChecker_MissingTokenEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{})
	}))
	defer server.Close()

	_, err := idp.NewOIDCChecker(idp.OIDCCheckerConfig{
		IssuerURL:  server.URL,
		ClientID:   "test",
		HTTPClient: server.Client(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing token_endpoint")
}

func TestCheckSubject_TokenFailure(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token_endpoint": server.URL + "/oauth2/token",
		})
	})
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("invalid credentials"))
	})
	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	checker, err := idp.NewOIDCChecker(idp.OIDCCheckerConfig{
		IssuerURL:            server.URL,
		ClientID:             "bad-client",
		OIDCSecret:           "bad-secret",
		UserEndpointTemplate: server.URL + "/users/{{subject}}",
		HTTPClient:           server.Client(),
	})
	require.NoError(t, err)

	status := checker.CheckSubject(context.Background(), "user-123")
	require.ErrorIs(t, status.Error, idp.ErrIDPUnreachable)

	server.Close()
}

func TestCheckSubject_Unauthorized(t *testing.T) {
	_, checker := setupMockIDP(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	status := checker.CheckSubject(context.Background(), "user-123")
	require.Error(t, status.Error)
	assert.ErrorIs(t, status.Error, idp.ErrIDPUnreachable)
}
