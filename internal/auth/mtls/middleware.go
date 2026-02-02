package mtls

import (
	"net/http"
)

// Middleware creates HTTP middleware that enforces mTLS authentication.
func Middleware(verifier *Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, err := verifier.VerifyRequest(r)
			if err != nil {
				http.Error(w, "mTLS authentication required", http.StatusUnauthorized)
				return
			}

			// Store identity in context
			ctx := ContextWithIdentity(r.Context(), identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalMiddleware creates middleware that extracts mTLS identity if present,
// but doesn't require it.
func OptionalMiddleware(verifier *Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if identity, err := verifier.VerifyRequest(r); err == nil {
				ctx := ContextWithIdentity(r.Context(), identity)
				r = r.WithContext(ctx)
			}
			next.ServeHTTP(w, r)
		})
	}
}
