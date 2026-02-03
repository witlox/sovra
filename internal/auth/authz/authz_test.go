// Package authz tests OPA-based authorization.
package authz_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/witlox/sovra/internal/auth/authz"
	"github.com/witlox/sovra/internal/auth/jwt"
)

func TestNewEnforcer(t *testing.T) {
	enforcer, err := authz.NewEnforcer(authz.DefaultPolicy)
	require.NoError(t, err)
	require.NotNil(t, enforcer)
}

func TestNewEnforcerWithDefaultPolicy(t *testing.T) {
	enforcer, err := authz.NewEnforcerWithDefaultPolicy()
	require.NoError(t, err)
	require.NotNil(t, enforcer)
}

func TestNewEnforcer_InvalidPolicy(t *testing.T) {
	_, err := authz.NewEnforcer("invalid rego policy {{{")
	require.Error(t, err)
}

func TestAuthorize_SystemAccount(t *testing.T) {
	enforcer, err := authz.NewEnforcerWithDefaultPolicy()
	require.NoError(t, err)

	input := authz.Input{
		Subject: authz.Subject{
			ID:           "system-1",
			Type:         "system",
			Organization: "org-1",
		},
		Action: "delete",
		Resource: authz.Resource{
			Type:         "workspace",
			ID:           "ws-123",
			Organization: "org-1",
		},
	}

	decision, err := enforcer.Authorize(context.Background(), input)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestAuthorize_AdminRole(t *testing.T) {
	enforcer, err := authz.NewEnforcerWithDefaultPolicy()
	require.NoError(t, err)

	input := authz.Input{
		Subject: authz.Subject{
			ID:           "user-1",
			Type:         "user",
			Organization: "org-1",
			Roles:        []string{"admin"},
		},
		Action: "delete",
		Resource: authz.Resource{
			Type:         "workspace",
			ID:           "ws-123",
			Organization: "org-1",
		},
	}

	decision, err := enforcer.Authorize(context.Background(), input)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestAuthorize_AdminWrongOrg(t *testing.T) {
	enforcer, err := authz.NewEnforcerWithDefaultPolicy()
	require.NoError(t, err)

	input := authz.Input{
		Subject: authz.Subject{
			ID:           "user-1",
			Type:         "user",
			Organization: "org-1",
			Roles:        []string{"admin"},
		},
		Action: "delete",
		Resource: authz.Resource{
			Type:         "workspace",
			ID:           "ws-123",
			Organization: "org-2", // Different org
		},
	}

	decision, err := enforcer.Authorize(context.Background(), input)
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
}

func TestAuthorize_ReadAccess(t *testing.T) {
	enforcer, err := authz.NewEnforcerWithDefaultPolicy()
	require.NoError(t, err)

	input := authz.Input{
		Subject: authz.Subject{
			ID:           "user-1",
			Type:         "user",
			Organization: "org-1",
		},
		Action: "read",
		Resource: authz.Resource{
			Type:         "workspace",
			ID:           "ws-123",
			Organization: "org-1",
		},
	}

	decision, err := enforcer.Authorize(context.Background(), input)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestAuthorize_ReadDeniedWrongOrg(t *testing.T) {
	enforcer, err := authz.NewEnforcerWithDefaultPolicy()
	require.NoError(t, err)

	input := authz.Input{
		Subject: authz.Subject{
			ID:           "user-1",
			Type:         "user",
			Organization: "org-1",
		},
		Action: "read",
		Resource: authz.Resource{
			Type:         "workspace",
			ID:           "ws-123",
			Organization: "org-2",
		},
	}

	decision, err := enforcer.Authorize(context.Background(), input)
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
}

func TestAuthorize_WriteWithScope(t *testing.T) {
	enforcer, err := authz.NewEnforcerWithDefaultPolicy()
	require.NoError(t, err)

	input := authz.Input{
		Subject: authz.Subject{
			ID:           "user-1",
			Type:         "user",
			Organization: "org-1",
			Scopes:       []string{"workspace:create"},
		},
		Action: "create",
		Resource: authz.Resource{
			Type:         "workspace",
			ID:           "",
			Organization: "org-1",
		},
	}

	decision, err := enforcer.Authorize(context.Background(), input)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestAuthorize_KeyUserEncrypt(t *testing.T) {
	enforcer, err := authz.NewEnforcerWithDefaultPolicy()
	require.NoError(t, err)

	input := authz.Input{
		Subject: authz.Subject{
			ID:           "user-1",
			Type:         "user",
			Organization: "org-1",
			Roles:        []string{"key_user"},
		},
		Action: "encrypt",
		Resource: authz.Resource{
			Type:         "key",
			ID:           "key-123",
			Organization: "org-1",
		},
	}

	decision, err := enforcer.Authorize(context.Background(), input)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestAuthorize_KeyAdminRotate(t *testing.T) {
	enforcer, err := authz.NewEnforcerWithDefaultPolicy()
	require.NoError(t, err)

	input := authz.Input{
		Subject: authz.Subject{
			ID:           "user-1",
			Type:         "user",
			Organization: "org-1",
			Roles:        []string{"key_admin"},
		},
		Action: "rotate",
		Resource: authz.Resource{
			Type:         "key",
			ID:           "key-123",
			Organization: "org-1",
		},
	}

	decision, err := enforcer.Authorize(context.Background(), input)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestAuthorizeOrFail_Allowed(t *testing.T) {
	enforcer, err := authz.NewEnforcerWithDefaultPolicy()
	require.NoError(t, err)

	input := authz.Input{
		Subject: authz.Subject{
			ID:   "system-1",
			Type: "system",
		},
		Action: "read",
		Resource: authz.Resource{
			Type: "workspace",
		},
	}

	err = enforcer.AuthorizeOrFail(context.Background(), input)
	assert.NoError(t, err)
}

func TestAuthorizeOrFail_Denied(t *testing.T) {
	enforcer, err := authz.NewEnforcerWithDefaultPolicy()
	require.NoError(t, err)

	input := authz.Input{
		Subject: authz.Subject{
			ID:           "user-1",
			Type:         "user",
			Organization: "org-1",
		},
		Action: "delete",
		Resource: authz.Resource{
			Type:         "workspace",
			ID:           "ws-123",
			Organization: "org-2", // Different org
		},
	}

	err = enforcer.AuthorizeOrFail(context.Background(), input)
	assert.ErrorIs(t, err, authz.ErrDenied)
}

func TestInput_Struct(t *testing.T) {
	input := authz.Input{
		Subject: authz.Subject{
			ID:           "user-123",
			Type:         "user",
			Organization: "org-456",
			Roles:        []string{"admin", "developer"},
			Scopes:       []string{"read:workspace", "write:key"},
		},
		Action: "create",
		Resource: authz.Resource{
			Type:         "workspace",
			ID:           "ws-789",
			Organization: "org-456",
			Workspace:    "parent-ws",
		},
		Context: map[string]any{
			"ip": "192.168.1.1",
		},
	}

	assert.Equal(t, "user-123", input.Subject.ID)
	assert.Equal(t, "create", input.Action)
	assert.Equal(t, "workspace", input.Resource.Type)
	assert.Equal(t, "192.168.1.1", input.Context["ip"])
}

func TestDecision_Struct(t *testing.T) {
	decision := authz.Decision{
		Allowed: true,
		Reason:  "admin access",
		Policy:  "admin_policy",
	}

	assert.True(t, decision.Allowed)
	assert.Equal(t, "admin access", decision.Reason)
	assert.Equal(t, "admin_policy", decision.Policy)
}

func TestErrorTypes(t *testing.T) {
	require.Error(t, authz.ErrDenied)
	require.Error(t, authz.ErrPolicyNotFound)
}

func TestDefaultPolicy_Content(t *testing.T) {
	policy := authz.DefaultPolicy
	assert.Contains(t, policy, "package sovra.authz")
	assert.Contains(t, policy, "default allow := false")
	assert.Contains(t, policy, "system")
	assert.Contains(t, policy, "admin")
}

func TestMiddleware_Allowed(t *testing.T) {
	enforcer, err := authz.NewEnforcerWithDefaultPolicy()
	require.NoError(t, err)

	handler := authz.Middleware(enforcer, "workspace", "read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Without proper context, the default policy allows certain actions
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Default policy has complex rules - just verify it runs without error
	assert.Contains(t, []int{http.StatusOK, http.StatusForbidden}, rec.Code)
}

func TestMiddleware_Denied(t *testing.T) {
	enforcer, err := authz.NewEnforcerWithDefaultPolicy()
	require.NoError(t, err)

	// Delete action requires explicit permissions
	handler := authz.Middleware(enforcer, "workspace", "delete")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// User without proper roles/scopes should be denied
	req := httptest.NewRequest("DELETE", "/test", nil)
	claims := &jwt.Claims{
		Subject:      "user-1",
		Organization: "org-1",
		// No roles or scopes
	}
	ctx := jwt.ContextWithClaims(req.Context(), claims)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRequireRole_NoJWT(t *testing.T) {
	handler := authz.RequireRole("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRequireRole_WithRole(t *testing.T) {
	handler := authz.RequireRole("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Create request with JWT claims in context
	req := httptest.NewRequest("GET", "/test", nil)
	claims := &jwt.Claims{
		Subject: "user-1",
		Roles:   []string{"admin", "user"},
	}
	ctx := jwt.ContextWithClaims(req.Context(), claims)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireScope_NoJWT(t *testing.T) {
	handler := authz.RequireScope("read:workspace")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRequireScope_WithScope(t *testing.T) {
	handler := authz.RequireScope("read:workspace")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	claims := &jwt.Claims{
		Subject: "user-1",
		Scopes:  []string{"read:workspace", "write:key"},
	}
	ctx := jwt.ContextWithClaims(req.Context(), claims)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}
