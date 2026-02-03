// Package oidc provides OpenID Connect authentication.
// This integrates with standard OIDC providers like Azure AD, Okta, Keycloak, etc.
package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/witlox/sovra/internal/auth/jwt"
)

var (
	// ErrDiscoveryFailed indicates OIDC discovery failed.
	ErrDiscoveryFailed = errors.New("OIDC discovery failed")
	// ErrNoJWKS indicates no JWKS endpoint was found.
	ErrNoJWKS = errors.New("no JWKS endpoint found")
)

// Config holds OIDC configuration.
type Config struct {
	// IssuerURL is the OIDC issuer URL (e.g., https://login.microsoftonline.com/{tenant}/v2.0)
	IssuerURL string
	// ClientID is the expected audience (your application's client ID)
	ClientID string
	// RequiredScopes are scopes that must be present in the token
	RequiredScopes []string
	// HTTPClient is an optional HTTP client for discovery
	HTTPClient *http.Client
}

// Provider is an OIDC provider that can validate tokens.
type Provider struct {
	config      Config
	discovery   *DiscoveryDocument
	jwks        *JWKS
	mu          sync.RWMutex
	lastRefresh time.Time
}

// DiscoveryDocument contains OIDC discovery information.
type DiscoveryDocument struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSUri               string   `json:"jwks_uri"`
	ScopesSupported       []string `json:"scopes_supported"`
	ClaimsSupported       []string `json:"claims_supported"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`   // RSA modulus
	E   string `json:"e"`   // RSA exponent
	X   string `json:"x"`   // EC x coordinate
	Y   string `json:"y"`   // EC y coordinate
	Crv string `json:"crv"` // EC curve
}

// NewProvider creates a new OIDC provider.
func NewProvider(cfg Config) (*Provider, error) {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}

	p := &Provider{config: cfg}

	// Perform initial discovery
	if err := p.refresh(context.Background()); err != nil {
		return nil, err
	}

	return p, nil
}

// Validate validates an OIDC token and returns the claims.
func (p *Provider) Validate(ctx context.Context, token string) (*jwt.Claims, error) {
	// Refresh JWKS if stale (every 24 hours)
	p.mu.RLock()
	stale := time.Since(p.lastRefresh) > 24*time.Hour
	jwks := p.jwks
	discovery := p.discovery
	p.mu.RUnlock()

	if stale {
		if err := p.refresh(ctx); err != nil {
			// Log error but continue with cached keys
			_ = err
		}
		p.mu.RLock()
		jwks = p.jwks
		discovery = p.discovery
		p.mu.RUnlock()
	}

	// Parse token header to get kid
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, jwt.ErrInvalidToken
	}

	// Decode header to get kid
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, jwt.ErrInvalidToken
	}

	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, jwt.ErrInvalidToken
	}

	// Look up the signing key by kid from JWKS
	var signingKey *JWK
	if jwks != nil && header.Kid != "" {
		for i := range jwks.Keys {
			if jwks.Keys[i].Kid == header.Kid {
				signingKey = &jwks.Keys[i]
				break
			}
		}
	}

	// Build public key PEM from JWK if we found the key
	var publicKeyPEM []byte
	if signingKey != nil {
		publicKeyPEM, err = jwkToPublicKeyPEM(signingKey)
		if err != nil {
			return nil, fmt.Errorf("failed to convert JWK to public key: %w", err)
		}
	}

	// Validate using the JWT validator with the looked-up key
	validatorCfg := jwt.ValidatorConfig{
		ExpectedIssuer: discovery.Issuer,
		ExpectedAuds:   []string{p.config.ClientID},
	}
	if len(publicKeyPEM) > 0 {
		validatorCfg.PublicKeyPEM = publicKeyPEM
	}

	validator, err := jwt.NewValidator(validatorCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create validator: %w", err)
	}

	claims, err := validator.Validate(token)
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	// Check required scopes
	if len(p.config.RequiredScopes) > 0 {
		if !p.hasRequiredScopes(claims.Scopes) {
			return nil, errors.New("missing required scopes")
		}
	}

	return claims, nil
}

// jwkToPublicKeyPEM converts a JWK to PEM-encoded public key
func jwkToPublicKeyPEM(jwk *JWK) ([]byte, error) {
	switch jwk.Kty {
	case "RSA":
		// Decode RSA components
		nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			return nil, fmt.Errorf("failed to decode RSA modulus: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			return nil, fmt.Errorf("failed to decode RSA exponent: %w", err)
		}

		// Convert exponent bytes to int
		var e int
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}

		n := new(big.Int).SetBytes(nBytes)
		pubKey := &rsa.PublicKey{N: n, E: e}

		derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key: %w", err)
		}

		pemBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}
		return pem.EncodeToMemory(pemBlock), nil

	case "EC":
		// Decode EC components
		xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return nil, fmt.Errorf("failed to decode EC x: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
		if err != nil {
			return nil, fmt.Errorf("failed to decode EC y: %w", err)
		}

		var curve elliptic.Curve
		switch jwk.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve: %s", jwk.Crv)
		}

		pubKey := &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}

		derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key: %w", err)
		}

		pemBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}
		return pem.EncodeToMemory(pemBlock), nil

	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

func (p *Provider) refresh(ctx context.Context) error {
	// Fetch discovery document
	discoveryURL := strings.TrimSuffix(p.config.IssuerURL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := p.config.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDiscoveryFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", ErrDiscoveryFailed, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read discovery response: %w", err)
	}

	var discovery DiscoveryDocument
	if err := json.Unmarshal(body, &discovery); err != nil {
		return fmt.Errorf("failed to parse discovery document: %w", err)
	}

	if discovery.JWKSUri == "" {
		return ErrNoJWKS
	}

	// Fetch JWKS
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, discovery.JWKSUri, nil)
	if err != nil {
		return fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err = p.config.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	p.mu.Lock()
	p.discovery = &discovery
	p.jwks = &jwks
	p.lastRefresh = time.Now()
	p.mu.Unlock()

	return nil
}

func (p *Provider) hasRequiredScopes(tokenScopes []string) bool {
	scopeSet := make(map[string]bool)
	for _, s := range tokenScopes {
		scopeSet[s] = true
	}

	for _, required := range p.config.RequiredScopes {
		if !scopeSet[required] {
			return false
		}
	}
	return true
}

// Middleware creates HTTP middleware that validates OIDC tokens.
func Middleware(provider *Provider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearerToken(r)
			if token == "" {
				http.Error(w, "Authorization required", http.StatusUnauthorized)
				return
			}

			claims, err := provider.Validate(r.Context(), token)
			if err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			ctx := jwt.ContextWithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalMiddleware validates OIDC tokens if present but allows requests through without a token.
func OptionalMiddleware(provider *Provider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if already authenticated via mTLS or JWT
			if _, ok := jwt.ClaimsFromContext(r.Context()); ok {
				next.ServeHTTP(w, r)
				return
			}

			token := extractBearerToken(r)
			if token == "" {
				// No token - let request proceed without OIDC auth
				next.ServeHTTP(w, r)
				return
			}

			claims, err := provider.Validate(r.Context(), token)
			if err != nil {
				// Token present but invalid
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			ctx := jwt.ContextWithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}

	return parts[1]
}
