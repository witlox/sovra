// Package idp provides identity provider subject and group checking.
package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GroupMemberChecker checks group membership against an external IdP.
type GroupMemberChecker interface {
	// GetGroupMembers returns the subject IDs of all members of an IdP group.
	GetGroupMembers(ctx context.Context, idpGroupID string) ([]string, error)
}

// OIDCGroupCheckerConfig holds configuration for the OIDC group checker.
type OIDCGroupCheckerConfig struct {
	IssuerURL             string
	ClientID              string
	OIDCSecret            string // nolint:gosec // G117: OIDC client secret for token acquisition
	GroupEndpointTemplate string // e.g. "https://graph.microsoft.com/v1.0/groups/{{groupId}}/members"
	HTTPClient            *http.Client
}

// OIDCGroupChecker checks group membership against an OIDC-compatible IdP.
type OIDCGroupChecker struct {
	tokenEndpoint         string
	groupEndpointTemplate string
	clientID              string
	clientSecret          string
	httpClient            *http.Client
}

// NewOIDCGroupChecker creates a new OIDC group membership checker.
func NewOIDCGroupChecker(cfg OIDCGroupCheckerConfig) (*OIDCGroupChecker, error) {
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

	var discovery struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.Unmarshal(body, &discovery); err != nil {
		return nil, fmt.Errorf("parse discovery document: %w", err)
	}
	if discovery.TokenEndpoint == "" {
		return nil, fmt.Errorf("discovery document missing token_endpoint")
	}

	groupEndpoint := cfg.GroupEndpointTemplate
	if groupEndpoint == "" {
		groupEndpoint = issuer + "/groups/{{groupId}}/members"
	}

	return &OIDCGroupChecker{
		tokenEndpoint:         discovery.TokenEndpoint,
		groupEndpointTemplate: groupEndpoint,
		clientID:              cfg.ClientID,
		clientSecret:          cfg.OIDCSecret,
		httpClient:            httpClient,
	}, nil
}

// GetGroupMembers queries the IdP for members of a group.
func (c *OIDCGroupChecker) GetGroupMembers(ctx context.Context, idpGroupID string) ([]string, error) {
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIDPUnreachable, err)
	}

	groupURL := strings.ReplaceAll(c.groupEndpointTemplate, "{{groupId}}", idpGroupID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, groupURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIDPUnreachable, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req) // nolint:gosec // G704: SSRF — URL is from admin-configured group endpoint
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIDPUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB limit
	if err != nil {
		return nil, fmt.Errorf("read group members response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: group endpoint returned %d", ErrIDPUnreachable, resp.StatusCode)
	}

	// Parse Microsoft Graph-style response: {"value": [{"id": "...", "userPrincipalName": "..."}]}
	var result struct {
		Value []struct {
			ID                string `json:"id"`
			UserPrincipalName string `json:"userPrincipalName"`
		} `json:"value"`
		// Also support flat array: ["subject1", "subject2"]
		Members []string `json:"members"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse group members response: %w", err)
	}

	// Build subject list from whichever format was returned
	var subjects []string
	if len(result.Value) > 0 {
		for _, member := range result.Value {
			subject := member.UserPrincipalName
			if subject == "" {
				subject = member.ID
			}
			subjects = append(subjects, subject)
		}
	} else if len(result.Members) > 0 {
		subjects = result.Members
	}

	return subjects, nil
}

func (c *OIDCGroupChecker) getAccessToken(ctx context.Context) (string, error) {
	data := strings.NewReader(fmt.Sprintf(
		"grant_type=client_credentials&client_id=%s&client_secret=%s&scope=openid",
		c.clientID, c.clientSecret,
	))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenEndpoint, data)
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
