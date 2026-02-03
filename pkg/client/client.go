// Package client provides an HTTP client for the Sovra API.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/witlox/sovra/pkg/models"
)

// Client is the Sovra API client.
type Client struct {
	baseURL    string
	httpClient *http.Client
	token      string
	orgID      string
}

// Config holds client configuration.
type Config struct {
	BaseURL string
	Token   string
	OrgID   string
	Timeout time.Duration
}

// New creates a new Sovra API client.
func New(cfg Config) *Client {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		baseURL: cfg.BaseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		token: cfg.Token,
		orgID: cfg.OrgID,
	}
}

// SetToken sets the authentication token.
func (c *Client) SetToken(token string) {
	c.token = token
}

// SetOrgID sets the organization ID.
func (c *Client) SetOrgID(orgID string) {
	c.orgID = orgID
}

// request makes an HTTP request to the API.
func (c *Client) request(ctx context.Context, method, path string, body, result any) error {
	u, err := url.JoinPath(c.baseURL, path)
	if err != nil {
		return fmt.Errorf("build URL: %w", err)
	}

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, reqBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.orgID != "" {
		req.Header.Set("X-Org-ID", c.orgID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp ErrorResponse
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("API error (%d): %s", resp.StatusCode, errResp.Error)
		}
		return fmt.Errorf("API error (%d): %s", resp.StatusCode, string(respBody))
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("unmarshal response: %w", err)
		}
	}

	return nil
}

// ErrorResponse represents an API error response.
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// Workspace API

// WorkspaceCreateRequest represents a workspace creation request.
type WorkspaceCreateRequest struct {
	Name           string                `json:"name"`
	Participants   []string              `json:"participants"`
	Classification models.Classification `json:"classification"`
	Mode           models.WorkspaceMode  `json:"mode,omitempty"`
	Purpose        string                `json:"purpose,omitempty"`
	CRKSignature   []byte                `json:"crk_signature,omitempty"`
}

// CreateWorkspace creates a new workspace.
func (c *Client) CreateWorkspace(ctx context.Context, req WorkspaceCreateRequest) (*models.Workspace, error) {
	var result models.Workspace
	if err := c.request(ctx, http.MethodPost, "/api/v1/workspaces", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetWorkspace retrieves a workspace by ID.
func (c *Client) GetWorkspace(ctx context.Context, id string) (*models.Workspace, error) {
	var result models.Workspace
	if err := c.request(ctx, http.MethodGet, "/api/v1/workspaces/"+id, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListWorkspaces lists workspaces.
func (c *Client) ListWorkspaces(ctx context.Context, limit, offset int) ([]*models.Workspace, error) {
	path := fmt.Sprintf("/api/v1/workspaces?limit=%d&offset=%d", limit, offset)
	var result []*models.Workspace
	if err := c.request(ctx, http.MethodGet, path, nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// EncryptRequest represents an encryption request.
type EncryptRequest struct {
	Data []byte `json:"data"`
}

// EncryptResponse represents an encryption response.
type EncryptResponse struct {
	Ciphertext []byte `json:"ciphertext"`
}

// Encrypt encrypts data in a workspace.
func (c *Client) Encrypt(ctx context.Context, workspaceID string, data []byte) ([]byte, error) {
	var result EncryptResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/workspaces/"+workspaceID+"/encrypt", EncryptRequest{Data: data}, &result); err != nil {
		return nil, err
	}
	return result.Ciphertext, nil
}

// DecryptRequest represents a decryption request.
type DecryptRequest struct {
	Ciphertext []byte `json:"ciphertext"`
}

// DecryptResponse represents a decryption response.
type DecryptResponse struct {
	Data []byte `json:"data"`
}

// Decrypt decrypts data from a workspace.
func (c *Client) Decrypt(ctx context.Context, workspaceID string, ciphertext []byte) ([]byte, error) {
	var result DecryptResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/workspaces/"+workspaceID+"/decrypt", DecryptRequest{Ciphertext: ciphertext}, &result); err != nil {
		return nil, err
	}
	return result.Data, nil
}

// Federation API

// ListFederations lists federation partners.
func (c *Client) ListFederations(ctx context.Context) ([]*models.Federation, error) {
	var result []*models.Federation
	if err := c.request(ctx, http.MethodGet, "/api/v1/federation", nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetFederationStatus gets federation status for a partner.
func (c *Client) GetFederationStatus(ctx context.Context, partnerOrgID string) (*models.Federation, error) {
	var result models.Federation
	if err := c.request(ctx, http.MethodGet, "/api/v1/federation/"+partnerOrgID, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Audit API

// AuditQueryParams represents audit query parameters.
type AuditQueryParams struct {
	Since     string `json:"since,omitempty"`
	Until     string `json:"until,omitempty"`
	EventType string `json:"event_type,omitempty"`
	Limit     int    `json:"limit,omitempty"`
}

// QueryAudit queries audit events.
func (c *Client) QueryAudit(ctx context.Context, params AuditQueryParams) ([]*models.AuditEvent, error) {
	path := "/api/v1/audit?"
	if params.Since != "" {
		path += "since=" + url.QueryEscape(params.Since) + "&"
	}
	if params.Until != "" {
		path += "until=" + url.QueryEscape(params.Until) + "&"
	}
	if params.EventType != "" {
		path += "event_type=" + url.QueryEscape(params.EventType) + "&"
	}
	if params.Limit > 0 {
		path += fmt.Sprintf("limit=%d&", params.Limit)
	}
	var result []*models.AuditEvent
	if err := c.request(ctx, http.MethodGet, path, nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Edge API

// ListEdgeNodes lists edge nodes.
func (c *Client) ListEdgeNodes(ctx context.Context) ([]*models.EdgeNode, error) {
	var result []*models.EdgeNode
	if err := c.request(ctx, http.MethodGet, "/api/v1/edges", nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetEdgeNode gets an edge node by ID.
func (c *Client) GetEdgeNode(ctx context.Context, id string) (*models.EdgeNode, error) {
	var result models.EdgeNode
	if err := c.request(ctx, http.MethodGet, "/api/v1/edges/"+id, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// EdgeNodeRegisterRequest represents an edge node registration request.
type EdgeNodeRegisterRequest struct {
	Name      string `json:"name"`
	VaultAddr string `json:"vault_addr"`
	Region    string `json:"region,omitempty"`
}

// RegisterEdgeNode registers a new edge node.
func (c *Client) RegisterEdgeNode(ctx context.Context, req EdgeNodeRegisterRequest) (*models.EdgeNode, error) {
	var result models.EdgeNode
	if err := c.request(ctx, http.MethodPost, "/api/v1/edges", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UnregisterEdgeNode unregisters an edge node.
func (c *Client) UnregisterEdgeNode(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/edges/"+id, nil, nil)
}

// Login API

// LoginRequest represents a login request.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse represents a login response.
type LoginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Login performs user login.
func (c *Client) Login(ctx context.Context, email, password string) (*LoginResponse, error) {
	var result LoginResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/auth/login", LoginRequest{Email: email, Password: password}, &result); err != nil {
		return nil, err
	}
	c.token = result.Token
	return &result, nil
}

// Logout performs user logout.
func (c *Client) Logout(ctx context.Context) error {
	return c.request(ctx, http.MethodPost, "/api/v1/auth/logout", nil, nil)
}

// CRK Ceremony API

// StartCeremonyRequest represents a ceremony start request.
type StartCeremonyRequest struct {
	OrgID     string `json:"org_id"`
	Shares    int    `json:"shares"`
	Threshold int    `json:"threshold"`
}

// CeremonyResponse represents a ceremony response.
type CeremonyResponse struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Threshold int    `json:"threshold"`
	Collected int    `json:"collected"`
}

// StartCRKCeremony starts a CRK ceremony.
func (c *Client) StartCRKCeremony(ctx context.Context, orgID string, shares, threshold int) (*CeremonyResponse, error) {
	var result CeremonyResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/crk/ceremony/start", StartCeremonyRequest{OrgID: orgID, Shares: shares, Threshold: threshold}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// AddCRKShare adds a share to a ceremony.
func (c *Client) AddCRKShare(ctx context.Context, ceremonyID string, share models.CRKShare) (*CeremonyResponse, error) {
	var result CeremonyResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/crk/ceremony/"+ceremonyID+"/share", share, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CompleteCRKCeremony completes a CRK ceremony.
func (c *Client) CompleteCRKCeremony(ctx context.Context, ceremonyID string) (*CeremonyResponse, error) {
	var result CeremonyResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/crk/ceremony/"+ceremonyID+"/complete", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Health checks

// HealthResponse represents a health check response.
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// Health checks API health.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var result HealthResponse
	if err := c.request(ctx, http.MethodGet, "/health", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
