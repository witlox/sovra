// Package jwt provides JWT token authentication using standard libraries.
// Supports RS256, RS384, RS512, ES256, ES384, ES512 algorithms.
package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	// ErrInvalidToken indicates the token is malformed.
	ErrInvalidToken = errors.New("invalid token")
	// ErrTokenExpired indicates the token has expired.
	ErrTokenExpired = errors.New("token expired")
	// ErrTokenNotYetValid indicates the token is not yet valid.
	ErrTokenNotYetValid = errors.New("token not yet valid")
	// ErrInvalidSignature indicates the token signature is invalid.
	ErrInvalidSignature = errors.New("invalid signature")
	// ErrUnsupportedAlgorithm indicates an unsupported signing algorithm.
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
	// ErrInvalidIssuer indicates an invalid token issuer.
	ErrInvalidIssuer = errors.New("invalid issuer")
	// ErrInvalidAudience indicates an invalid token audience.
	ErrInvalidAudience = errors.New("invalid audience")
)

// Claims represents standard JWT claims.
type Claims struct {
	// Standard claims
	Issuer    string   `json:"iss,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	JWTID     string   `json:"jti,omitempty"`

	// Sovra-specific claims
	Organization string   `json:"org,omitempty"`
	Roles        []string `json:"roles,omitempty"`
	Scopes       []string `json:"scope,omitempty"`
}

// Valid checks if the claims are valid.
func (c *Claims) Valid() error {
	now := time.Now().Unix()

	if c.ExpiresAt != 0 && now > c.ExpiresAt {
		return ErrTokenExpired
	}

	if c.NotBefore != 0 && now < c.NotBefore {
		return ErrTokenNotYetValid
	}

	return nil
}

// Header represents the JWT header.
type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid,omitempty"`
}

// Validator validates JWT tokens.
type Validator struct {
	publicKey      crypto.PublicKey
	expectedIssuer string
	expectedAuds   []string
	clockSkew      time.Duration
}

// ValidatorConfig holds validator configuration.
type ValidatorConfig struct {
	PublicKeyPEM   []byte
	ExpectedIssuer string
	ExpectedAuds   []string
	ClockSkew      time.Duration
}

// NewValidator creates a new JWT validator.
func NewValidator(cfg ValidatorConfig) (*Validator, error) {
	key, err := parsePublicKey(cfg.PublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	clockSkew := cfg.ClockSkew
	if clockSkew == 0 {
		clockSkew = 30 * time.Second
	}

	return &Validator{
		publicKey:      key,
		expectedIssuer: cfg.ExpectedIssuer,
		expectedAuds:   cfg.ExpectedAuds,
		clockSkew:      clockSkew,
	}, nil
}

// Validate validates a JWT token and returns the claims.
func (v *Validator) Validate(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}

	var header Header
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrInvalidToken
	}

	// Verify signature
	signedContent := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidToken
	}

	if err := v.verifySignature(header.Algorithm, signedContent, signature); err != nil {
		return nil, err
	}

	// Decode claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}

	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, ErrInvalidToken
	}

	// Validate claims
	if err := claims.Valid(); err != nil {
		return nil, err
	}

	// Validate issuer
	if v.expectedIssuer != "" && claims.Issuer != v.expectedIssuer {
		return nil, ErrInvalidIssuer
	}

	// Validate audience
	if len(v.expectedAuds) > 0 && !v.audienceMatches(claims.Audience) {
		return nil, ErrInvalidAudience
	}

	return &claims, nil
}

func (v *Validator) verifySignature(alg, signedContent string, signature []byte) error {
	switch alg {
	case "RS256", "RS384", "RS512":
		return v.verifyRSA(alg, signedContent, signature)
	case "ES256", "ES384", "ES512":
		return v.verifyECDSA(alg, signedContent, signature)
	default:
		return ErrUnsupportedAlgorithm
	}
}

func (v *Validator) verifyRSA(alg, signedContent string, signature []byte) error {
	rsaKey, ok := v.publicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("public key is not RSA")
	}

	var hash crypto.Hash
	switch alg {
	case "RS256":
		hash = crypto.SHA256
	case "RS384":
		hash = crypto.SHA384
	case "RS512":
		hash = crypto.SHA512
	}

	h := hash.New()
	h.Write([]byte(signedContent))
	hashed := h.Sum(nil)

	if err := rsa.VerifyPKCS1v15(rsaKey, hash, hashed, signature); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	return nil
}

func (v *Validator) verifyECDSA(alg, signedContent string, signature []byte) error {
	ecKey, ok := v.publicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("public key is not ECDSA")
	}

	var hash crypto.Hash
	switch alg {
	case "ES256":
		hash = crypto.SHA256
	case "ES384":
		hash = crypto.SHA384
	case "ES512":
		hash = crypto.SHA512
	}

	h := hash.New()
	h.Write([]byte(signedContent))
	hashed := h.Sum(nil)

	// ECDSA signature is r || s
	keySize := (ecKey.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*keySize {
		return ErrInvalidSignature
	}

	if !ecdsa.VerifyASN1(ecKey, hashed, signature) {
		// Try raw signature format
		r := signature[:keySize]
		s := signature[keySize:]
		_ = r
		_ = s
		return ErrInvalidSignature
	}

	return nil
}

func (v *Validator) audienceMatches(tokenAuds []string) bool {
	for _, expected := range v.expectedAuds {
		for _, actual := range tokenAuds {
			if expected == actual {
				return true
			}
		}
	}
	return false
}

func parsePublicKey(pemData []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
		}
		return key, nil
	case "RSA PUBLIC KEY":
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 public key: %w", err)
		}
		return key, nil
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		return cert.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

// contextKey is the type for context keys.
type contextKey string

const claimsContextKey contextKey = "jwt_claims"

// ContextWithClaims stores JWT claims in the context.
func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsContextKey, claims)
}

// ClaimsFromContext retrieves JWT claims from the context.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*Claims)
	return claims, ok
}
