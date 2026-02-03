package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_Empty(t *testing.T) {
	cfg := Config{}
	h, err := New(cfg)
	require.NoError(t, err)
	assert.NotNil(t, h)
	assert.Nil(t, h.GetMTLSVerifier())
	assert.Nil(t, h.GetJWTValidator())
	assert.Nil(t, h.GetAuthzEnforcer())
}

func TestNew_AuthzOnly(t *testing.T) {
	cfg := Config{AuthzEnabled: true}
	h, err := New(cfg)
	require.NoError(t, err)
	assert.NotNil(t, h.GetAuthzEnforcer())
}

func TestMiddleware_Passthrough(t *testing.T) {
	h, _ := New(Config{})
	handler := h.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAuthorize_NoEnforcer(t *testing.T) {
	h, _ := New(Config{})
	middleware := h.Authorize("workspace", "read")
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireRole_NoJWT(t *testing.T) {
	h, _ := New(Config{})
	handler := h.RequireRole("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRequireScope_NoJWT(t *testing.T) {
	h, _ := New(Config{})
	handler := h.RequireScope("read:workspace")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}
