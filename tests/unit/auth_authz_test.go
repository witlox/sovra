package unit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/witlox/sovra/internal/auth/authz"
)

func TestEnforcerWithDefaultPolicy(t *testing.T) {
	enforcer, err := authz.NewEnforcerWithDefaultPolicy()
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	tests := []struct {
		name    string
		input   authz.Input
		allowed bool
	}{
		{
			name: "system account allowed",
			input: authz.Input{
				Subject: authz.Subject{
					ID:           "system",
					Type:         "system",
					Organization: "org1",
				},
				Action: "any",
				Resource: authz.Resource{
					Type:         "any",
					ID:           "any",
					Organization: "org2",
				},
			},
			allowed: true,
		},
		{
			name: "admin can access own org",
			input: authz.Input{
				Subject: authz.Subject{
					ID:           "admin-user",
					Type:         "user",
					Organization: "org1",
					Roles:        []string{"admin"},
				},
				Action: "delete",
				Resource: authz.Resource{
					Type:         "workspace",
					ID:           "ws1",
					Organization: "org1",
				},
			},
			allowed: true,
		},
		{
			name: "admin cannot access other org",
			input: authz.Input{
				Subject: authz.Subject{
					ID:           "admin-user",
					Type:         "user",
					Organization: "org1",
					Roles:        []string{"admin"},
				},
				Action: "delete",
				Resource: authz.Resource{
					Type:         "workspace",
					ID:           "ws1",
					Organization: "org2",
				},
			},
			allowed: false,
		},
		{
			name: "user can read own org",
			input: authz.Input{
				Subject: authz.Subject{
					ID:           "regular-user",
					Type:         "user",
					Organization: "org1",
					Roles:        []string{"user"},
				},
				Action: "read",
				Resource: authz.Resource{
					Type:         "workspace",
					ID:           "ws1",
					Organization: "org1",
				},
			},
			allowed: true,
		},
		{
			name: "user cannot read other org",
			input: authz.Input{
				Subject: authz.Subject{
					ID:           "regular-user",
					Type:         "user",
					Organization: "org1",
					Roles:        []string{"user"},
				},
				Action: "read",
				Resource: authz.Resource{
					Type:         "workspace",
					ID:           "ws1",
					Organization: "org2",
				},
			},
			allowed: false,
		},
		{
			name: "key_user can encrypt",
			input: authz.Input{
				Subject: authz.Subject{
					ID:           "key-user",
					Type:         "user",
					Organization: "org1",
					Roles:        []string{"key_user"},
				},
				Action: "encrypt",
				Resource: authz.Resource{
					Type:         "key",
					ID:           "key1",
					Organization: "org1",
				},
			},
			allowed: true,
		},
		{
			name: "key_user cannot rotate",
			input: authz.Input{
				Subject: authz.Subject{
					ID:           "key-user",
					Type:         "user",
					Organization: "org1",
					Roles:        []string{"key_user"},
				},
				Action: "rotate",
				Resource: authz.Resource{
					Type:         "key",
					ID:           "key1",
					Organization: "org1",
				},
			},
			allowed: false,
		},
		{
			name: "key_admin can rotate",
			input: authz.Input{
				Subject: authz.Subject{
					ID:           "key-admin",
					Type:         "user",
					Organization: "org1",
					Roles:        []string{"key_admin"},
				},
				Action: "rotate",
				Resource: authz.Resource{
					Type:         "key",
					ID:           "key1",
					Organization: "org1",
				},
			},
			allowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := enforcer.Authorize(context.Background(), tt.input)
			if err != nil {
				t.Fatalf("authorization error: %v", err)
			}
			if decision.Allowed != tt.allowed {
				t.Errorf("expected allowed=%v, got %v", tt.allowed, decision.Allowed)
			}
		})
	}
}

func TestAuthorizeOrFail(t *testing.T) {
	enforcer, err := authz.NewEnforcerWithDefaultPolicy()
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	// Test allowed case
	err = enforcer.AuthorizeOrFail(context.Background(), authz.Input{
		Subject: authz.Subject{
			Type: "system",
		},
		Action:   "anything",
		Resource: authz.Resource{Type: "any"},
	})
	if err != nil {
		t.Errorf("expected no error for allowed action, got %v", err)
	}

	// Test denied case
	err = enforcer.AuthorizeOrFail(context.Background(), authz.Input{
		Subject: authz.Subject{
			ID:           "user",
			Type:         "user",
			Organization: "org1",
		},
		Action: "delete",
		Resource: authz.Resource{
			Type:         "workspace",
			Organization: "org2",
		},
	})
	if !errors.Is(err, authz.ErrDenied) {
		t.Errorf("expected ErrDenied, got %v", err)
	}
}

func TestDecision(t *testing.T) {
	decision := &authz.Decision{
		Allowed: true,
		Reason:  "test reason",
		Policy:  "test.policy",
	}

	if !decision.Allowed {
		t.Error("expected allowed to be true")
	}
	if decision.Reason != "test reason" {
		t.Errorf("expected reason 'test reason', got %s", decision.Reason)
	}
}
