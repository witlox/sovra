package authz

import (
	"net/http"

	"github.com/witlox/sovra/internal/auth/jwt"
	"github.com/witlox/sovra/internal/auth/mtls"
)

// Middleware creates HTTP middleware that enforces authorization.
func Middleware(enforcer *Enforcer, resourceType string, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			input := buildInput(r, resourceType, action)

			decision, err := enforcer.Authorize(r.Context(), input)
			if err != nil {
				http.Error(w, "Authorization error", http.StatusInternalServerError)
				return
			}

			if !decision.Allowed {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole creates middleware that requires a specific role.
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check JWT claims
			if claims, ok := jwt.ClaimsFromContext(r.Context()); ok {
				for _, claimRole := range claims.Roles {
					if claimRole == role {
						next.ServeHTTP(w, r)
						return
					}
				}
			}

			http.Error(w, "Forbidden", http.StatusForbidden)
		})
	}
}

// RequireScope creates middleware that requires a specific scope.
func RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if claims, ok := jwt.ClaimsFromContext(r.Context()); ok {
				for _, s := range claims.Scopes {
					if s == scope {
						next.ServeHTTP(w, r)
						return
					}
				}
			}

			http.Error(w, "Forbidden", http.StatusForbidden)
		})
	}
}

func buildInput(r *http.Request, resourceType, action string) Input {
	input := Input{
		Action: action,
		Resource: Resource{
			Type: resourceType,
		},
		Context: make(map[string]any),
	}

	// Extract subject from JWT claims
	if claims, ok := jwt.ClaimsFromContext(r.Context()); ok {
		input.Subject = Subject{
			ID:           claims.Subject,
			Type:         "user",
			Organization: claims.Organization,
			Roles:        claims.Roles,
			Scopes:       claims.Scopes,
		}
	}

	// Override with mTLS identity if present
	if identity, ok := mtls.IdentityFromContext(r.Context()); ok {
		input.Subject.Organization = identity.Organization
		if input.Subject.ID == "" {
			input.Subject.ID = identity.CommonName
			input.Subject.Type = "service"
		}
	}

	// Extract resource ID from path parameters if available
	// This would typically use a router's path parameter extraction
	input.Context["method"] = r.Method
	input.Context["path"] = r.URL.Path

	return input
}
