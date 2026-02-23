// Package idp provides identity provider subject checking.
package idp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrIDPUnreachable indicates the identity provider could not be reached.
var ErrIDPUnreachable = errors.New("identity provider unreachable")

// SubjectStatus represents the result of checking a subject in an IdP.
type SubjectStatus struct {
	Active bool  // true = found and active, false = definitively not found
	Error  error // non-nil if IdP was unreachable (Active is meaningless)
}

// SubjectChecker checks whether a subject is still active in an external IdP.
type SubjectChecker interface {
	CheckSubject(ctx context.Context, subject string) SubjectStatus
}

// OIDCCheckerConfig holds configuration for the OIDC subject checker.
type OIDCCheckerConfig struct {
	IssuerURL            string
	ClientID             string
	OIDCSecret           string // nolint:gosec // G117: OIDC client secret for token acquisition
	UserEndpointTemplate string // e.g. "https://graph.microsoft.com/v1.0/users/{{subject}}"
	HTTPClient           *http.Client
}

// OIDCChecker checks subject liveness against an OIDC-compatible IdP.
type OIDCChecker struct {
	tokenEndpoint        string
	userEndpointTemplate string
	clientID             string
	clientSecret         string
	httpClient           *http.Client
}

type oidcDiscovery struct {
	TokenEndpoint    string `json:"token_endpoint"`
	UserinfoEndpoint string `json:"userinfo_endpoint"`
}

// NewOIDCChecker creates a new OIDC subject checker by discovering endpoints.
func NewOIDCChecker(cfg OIDCCheckerConfig) (*OIDCChecker, error) {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	issuer := strings.TrimRight(cfg.IssuerURL, "/")

	// Discover OIDC endpoints
	discoveryURL := issuer + "/.well-known/openid-configuration"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create discovery request: %w", err)
	}

	resp, err := httpClient.Do(req) // nolint:gosec // G704: SSRF — URL is from admin-configured issuer
	if err != nil {
		return nil, fmt.Errorf("fetch OIDC discovery document: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read discovery response: %w", err)
	}

	var discovery oidcDiscovery
	if err := json.Unmarshal(body, &discovery); err != nil {
		return nil, fmt.Errorf("parse discovery document: %w", err)
	}

	if discovery.TokenEndpoint == "" {
		return nil, fmt.Errorf("discovery document missing token_endpoint")
	}

	userEndpoint := cfg.UserEndpointTemplate
	if userEndpoint == "" {
		userEndpoint = issuer + "/users/{{subject}}"
	}

	return &OIDCChecker{
		tokenEndpoint:        discovery.TokenEndpoint,
		userEndpointTemplate: userEndpoint,
		clientID:             cfg.ClientID,
		clientSecret:         cfg.OIDCSecret,
		httpClient:           httpClient,
	}, nil
}

// CheckSubject checks whether a subject is active in the IdP.
func (c *OIDCChecker) CheckSubject(ctx context.Context, subject string) SubjectStatus {
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return SubjectStatus{Error: fmt.Errorf("%w: %w", ErrIDPUnreachable, err)}
	}

	userURL := strings.ReplaceAll(c.userEndpointTemplate, "{{subject}}", url.PathEscape(subject))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userURL, nil)
	if err != nil {
		return SubjectStatus{Error: fmt.Errorf("%w: %w", ErrIDPUnreachable, err)}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req) // nolint:gosec // G704: SSRF — URL is from admin-configured user endpoint
	if err != nil {
		return SubjectStatus{Error: fmt.Errorf("%w: %w", ErrIDPUnreachable, err)}
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain body to allow connection reuse
	_, _ = io.Copy(io.Discard, resp.Body)

	switch {
	case resp.StatusCode == http.StatusOK:
		return SubjectStatus{Active: true}
	case resp.StatusCode == http.StatusNotFound:
		return SubjectStatus{Active: false}
	case resp.StatusCode >= 500:
		return SubjectStatus{Error: fmt.Errorf("%w: IdP returned %d", ErrIDPUnreachable, resp.StatusCode)}
	default:
		// 403, 401, etc. — treat as unreachable (misconfigured credentials)
		return SubjectStatus{Error: fmt.Errorf("%w: IdP returned %d", ErrIDPUnreachable, resp.StatusCode)}
	}
}

type tokenResponse struct {
	Token     string `json:"access_token"` // nolint:gosec // G117: parsed from token endpoint response
	TokenType string `json:"token_type"`
	ExpiresIn int    `json:"expires_in"`
}

func (c *OIDCChecker) getAccessToken(ctx context.Context) (string, error) {
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"scope":         {"openid"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req) // nolint:gosec // G704: SSRF — URL is from discovered token endpoint
	if err != nil {
		return "", fmt.Errorf("request token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}

	if tokenResp.Token == "" {
		return "", fmt.Errorf("empty access token in response")
	}

	return tokenResp.Token, nil
}
