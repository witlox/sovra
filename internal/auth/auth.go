// Package auth provides unified authentication and authorization for Sovra.
package auth

import (
	"fmt"
	"net/http"

	"github.com/witlox/sovra/internal/auth/authz"
	"github.com/witlox/sovra/internal/auth/jwt"
	"github.com/witlox/sovra/internal/auth/mtls"
	"github.com/witlox/sovra/internal/auth/oidc"
)

// Config holds authentication configuration.
type Config struct {
	// mTLS settings
	MTLSEnabled  bool
	MTLSRequired bool
	TrustedCAPEM []byte

	// JWT settings
	JWTEnabled   bool
	JWTPublicKey []byte
	JWTIssuer    string
	JWTAudiences []string

	// OIDC settings (alternative to JWT)
	OIDCEnabled   bool
	OIDCIssuerURL string
	OIDCClientID  string

	// Authorization
	AuthzEnabled bool
	AuthzPolicy  string // Custom OPA policy, uses default if empty
}

// Handler wraps authentication/authorization around an HTTP handler.
type Handler struct {
	config        Config
	mtlsVerifier  *mtls.Verifier
	jwtValidator  *jwt.Validator
	oidcProvider  *oidc.Provider
	authzEnforcer *authz.Enforcer
}

// New creates a new auth handler.
func New(cfg Config) (*Handler, error) {
	h := &Handler{config: cfg}

	// Initialize mTLS verifier
	if cfg.MTLSEnabled && len(cfg.TrustedCAPEM) > 0 {
		verifier, err := mtls.NewVerifierFromPEM(cfg.TrustedCAPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to create mTLS verifier: %w", err)
		}
		h.mtlsVerifier = verifier
	}

	// Initialize JWT validator
	if cfg.JWTEnabled && len(cfg.JWTPublicKey) > 0 {
		validator, err := jwt.NewValidator(jwt.ValidatorConfig{
			PublicKeyPEM:   cfg.JWTPublicKey,
			ExpectedIssuer: cfg.JWTIssuer,
			ExpectedAuds:   cfg.JWTAudiences,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create JWT validator: %w", err)
		}
		h.jwtValidator = validator
	}

	// Initialize OIDC provider
	if cfg.OIDCEnabled && cfg.OIDCIssuerURL != "" {
		provider, err := oidc.NewProvider(oidc.Config{
			IssuerURL: cfg.OIDCIssuerURL,
			ClientID:  cfg.OIDCClientID,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
		}
		h.oidcProvider = provider
	}

	// Initialize authorization enforcer
	if cfg.AuthzEnabled {
		policy := cfg.AuthzPolicy
		if policy == "" {
			policy = authz.DefaultPolicy
		}
		enforcer, err := authz.NewEnforcer(policy)
		if err != nil {
			return nil, fmt.Errorf("failed to create authorization enforcer: %w", err)
		}
		h.authzEnforcer = enforcer
	}

	return h, nil
}

// Middleware returns the authentication middleware chain.
func (h *Handler) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := next

		// Apply mTLS middleware
		if h.mtlsVerifier != nil {
			if h.config.MTLSRequired {
				handler = mtls.Middleware(h.mtlsVerifier)(handler)
			} else {
				handler = mtls.OptionalMiddleware(h.mtlsVerifier)(handler)
			}
		}

		// Apply OIDC middleware if enabled (validates tokens from OIDC providers)
		if h.oidcProvider != nil {
			handler = oidc.OptionalMiddleware(h.oidcProvider)(handler)
		}

		// Apply JWT middleware (optional - mTLS or OIDC may be sufficient)
		if h.jwtValidator != nil {
			handler = jwt.OptionalMiddleware(h.jwtValidator)(handler)
		}

		return handler
	}
}

// Authorize returns authorization middleware for a specific resource/action.
func (h *Handler) Authorize(resourceType, action string) func(http.Handler) http.Handler {
	if h.authzEnforcer == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return authz.Middleware(h.authzEnforcer, resourceType, action)
}

// RequireRole returns middleware that requires a specific role.
func (h *Handler) RequireRole(role string) func(http.Handler) http.Handler {
	return authz.RequireRole(role)
}

// RequireScope returns middleware that requires a specific scope.
func (h *Handler) RequireScope(scope string) func(http.Handler) http.Handler {
	return authz.RequireScope(scope)
}

// GetMTLSVerifier returns the mTLS verifier for custom use.
func (h *Handler) GetMTLSVerifier() *mtls.Verifier {
	return h.mtlsVerifier
}

// GetJWTValidator returns the JWT validator for custom use.
func (h *Handler) GetJWTValidator() *jwt.Validator {
	return h.jwtValidator
}

// GetAuthzEnforcer returns the authorization enforcer for custom use.
func (h *Handler) GetAuthzEnforcer() *authz.Enforcer {
	return h.authzEnforcer
}
