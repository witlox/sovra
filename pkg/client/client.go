// Package client provides an HTTP client for the Sovra API.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
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
	BaseURL    string
	Token      string
	OrgID      string
	Timeout    time.Duration
	CertFile   string // Client certificate for mTLS
	KeyFile    string // Client private key for mTLS
	CACertFile string // CA certificate for server verification
}

// New creates a new Sovra API client.
func New(cfg Config) *Client {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()

	// Configure mTLS if cert/key are provided
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err == nil {
			if transport.TLSClientConfig == nil {
				transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			}
			transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
		}
	}
	if cfg.CACertFile != "" {
		caCert, err := os.ReadFile(cfg.CACertFile)
		if err == nil {
			caPool := x509.NewCertPool()
			if caPool.AppendCertsFromPEM(caCert) {
				if transport.TLSClientConfig == nil {
					transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
				}
				transport.TLSClientConfig.RootCAs = caPool
			}
		}
	}

	return &Client{
		baseURL: cfg.BaseURL,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
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
	Participants   []string              `json:"participants,omitempty"` // Deprecated: use GroupID
	GroupID        string                `json:"group_id,omitempty"`
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
	Data    []byte            `json:"data"`
	Context map[string]string `json:"context,omitempty"`
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

// EncryptWithContext encrypts data in a workspace with encryption context.
func (c *Client) EncryptWithContext(ctx context.Context, workspaceID string, data []byte, encCtx map[string]string) ([]byte, error) {
	var result EncryptResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/workspaces/"+workspaceID+"/encrypt", EncryptRequest{Data: data, Context: encCtx}, &result); err != nil {
		return nil, err
	}
	return result.Ciphertext, nil
}

// DecryptRequest represents a decryption request.
type DecryptRequest struct {
	Ciphertext []byte            `json:"ciphertext"`
	Context    map[string]string `json:"context,omitempty"`
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

// DecryptWithContext decrypts data from a workspace with encryption context.
func (c *Client) DecryptWithContext(ctx context.Context, workspaceID string, ciphertext []byte, encCtx map[string]string) ([]byte, error) {
	var result DecryptResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/workspaces/"+workspaceID+"/decrypt", DecryptRequest{Ciphertext: ciphertext, Context: encCtx}, &result); err != nil {
		return nil, err
	}
	return result.Data, nil
}

// UpdateWorkspaceRequest represents a workspace update request.
type UpdateWorkspaceRequest struct {
	Purpose        string                `json:"purpose,omitempty"`
	Classification models.Classification `json:"classification,omitempty"`
	Mode           models.WorkspaceMode  `json:"mode,omitempty"`
	Signature      []byte                `json:"signature,omitempty"`
}

// UpdateWorkspace updates a workspace.
func (c *Client) UpdateWorkspace(ctx context.Context, id string, req UpdateWorkspaceRequest) (*models.Workspace, error) {
	var result models.Workspace
	if err := c.request(ctx, http.MethodPut, "/api/v1/workspaces/"+id, req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RotateWorkspaceDEKRequest represents a DEK rotation request.
type RotateWorkspaceDEKRequest struct {
	Signature []byte `json:"signature,omitempty"`
}

// RotateWorkspaceDEK rotates the DEK for a workspace.
func (c *Client) RotateWorkspaceDEK(ctx context.Context, workspaceID string, signature []byte) error {
	return c.request(ctx, http.MethodPost, "/api/v1/workspaces/"+workspaceID+"/rotate-dek", RotateWorkspaceDEKRequest{Signature: signature}, nil)
}

// ExtendWorkspaceRequest represents a workspace expiration extension request.
type ExtendWorkspaceRequest struct {
	ExpiresAt time.Time `json:"expires_at"`
	Signature []byte    `json:"signature,omitempty"`
}

// ExtendWorkspace extends a workspace's expiration time.
func (c *Client) ExtendWorkspace(ctx context.Context, workspaceID string, expiresAt time.Time, signature []byte) error {
	return c.request(ctx, http.MethodPost, "/api/v1/workspaces/"+workspaceID+"/extend", ExtendWorkspaceRequest{ExpiresAt: expiresAt, Signature: signature}, nil)
}

// InviteParticipantRequest represents a participant invitation request.
type InviteParticipantRequest struct {
	OrgID     string `json:"org_id"`
	Signature []byte `json:"signature,omitempty"`
}

// InviteParticipant invites an organization to join a workspace.
func (c *Client) InviteParticipant(ctx context.Context, workspaceID string, req InviteParticipantRequest) (*models.WorkspaceInvitation, error) {
	var result models.WorkspaceInvitation
	if err := c.request(ctx, http.MethodPost, "/api/v1/workspaces/"+workspaceID+"/invite", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// AcceptInvitationRequest represents an invitation acceptance request.
type AcceptInvitationRequest struct {
	OrgID     string `json:"org_id"`
	GroupID   string `json:"group_id,omitempty"`
	Signature []byte `json:"signature,omitempty"`
}

// AcceptInvitation accepts a workspace invitation.
func (c *Client) AcceptInvitation(ctx context.Context, workspaceID string, req AcceptInvitationRequest) error {
	return c.request(ctx, http.MethodPost, "/api/v1/workspaces/"+workspaceID+"/accept-invitation", req, nil)
}

// DeclineInvitationRequest represents an invitation decline request.
type DeclineInvitationRequest struct {
	OrgID string `json:"org_id"`
}

// DeclineInvitation declines a workspace invitation.
func (c *Client) DeclineInvitation(ctx context.Context, workspaceID string, req DeclineInvitationRequest) error {
	return c.request(ctx, http.MethodPost, "/api/v1/workspaces/"+workspaceID+"/decline-invitation", req, nil)
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
// Deprecated: Admin authentication uses mTLS client certificates.
// Login/Logout are retained for SSO user flows only.

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
//
// Deprecated: Use mTLS client certificates for admin authentication.
func (c *Client) Login(ctx context.Context, email, password string) (*LoginResponse, error) {
	var result LoginResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/auth/login", LoginRequest{Email: email, Password: password}, &result); err != nil {
		return nil, err
	}
	c.token = result.Token
	return &result, nil
}

// Logout performs user logout.
//
// Deprecated: Use mTLS client certificates for admin authentication.
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

// CancelCRKCeremony cancels an ongoing CRK ceremony.
func (c *Client) CancelCRKCeremony(ctx context.Context, ceremonyID string) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/crk/ceremony/"+ceremonyID, nil, nil)
}

// Generation Ceremony API (password-protected shares)

// StartGenerationCeremonyRequest represents a generation ceremony start request.
type StartGenerationCeremonyRequest struct {
	OrgID       string `json:"org_id"`
	TotalShares int    `json:"total_shares"`
	Threshold   int    `json:"threshold"`
}

// GenerationCeremonyResponse represents a generation ceremony response.
type GenerationCeremonyResponse struct {
	ID              string                     `json:"id"`
	OrgID           string                     `json:"org_id"`
	TotalShares     int                        `json:"total_shares"`
	Threshold       int                        `json:"threshold"`
	Status          string                     `json:"status"`
	SeedEntries     json.RawMessage            `json:"seed_entries,omitempty"`
	EncryptedShares []models.EncryptedCRKShare `json:"encrypted_shares,omitempty"`
	CRK             *models.CRK                `json:"crk,omitempty"`
}

// StartGenerationCeremony starts a password-protected CRK generation ceremony.
func (c *Client) StartGenerationCeremony(ctx context.Context, orgID string, totalShares, threshold int) (*GenerationCeremonyResponse, error) {
	var result GenerationCeremonyResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/crk/generate-ceremony/start",
		StartGenerationCeremonyRequest{OrgID: orgID, TotalShares: totalShares, Threshold: threshold}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SeedGenerationShareRequest represents a seed share request.
type SeedGenerationShareRequest struct {
	Index         int    `json:"index"`
	EncryptionKey []byte `json:"encryption_key"`
	Salt          []byte `json:"salt"`
	KDFParams     struct {
		Time    uint32 `json:"time"`
		Memory  uint32 `json:"memory"`
		Threads uint8  `json:"threads"`
	} `json:"kdf_params"`
	CustodianName string `json:"custodian_name"`
}

// SeedGenerationShare seeds a shareholder's encryption key for a generation ceremony.
func (c *Client) SeedGenerationShare(ctx context.Context, ceremonyID string, req SeedGenerationShareRequest) error {
	return c.request(ctx, http.MethodPost, "/api/v1/crk/generate-ceremony/"+ceremonyID+"/seed", req, nil)
}

// CompleteGenerationCeremony completes a generation ceremony and returns the CRK with encrypted shares.
func (c *Client) CompleteGenerationCeremony(ctx context.Context, ceremonyID string) (*GenerationCeremonyResponse, error) {
	var result GenerationCeremonyResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/crk/generate-ceremony/"+ceremonyID+"/complete", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetGenerationCeremony retrieves the status of a generation ceremony.
func (c *Client) GetGenerationCeremony(ctx context.Context, ceremonyID string) (*GenerationCeremonyResponse, error) {
	var result GenerationCeremonyResponse
	if err := c.request(ctx, http.MethodGet, "/api/v1/crk/generate-ceremony/"+ceremonyID, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CancelGenerationCeremony cancels an in-progress generation ceremony.
func (c *Client) CancelGenerationCeremony(ctx context.Context, ceremonyID string) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/crk/generate-ceremony/"+ceremonyID, nil, nil)
}

// GetEncryptedShare retrieves a specific encrypted share.
func (c *Client) GetEncryptedShare(ctx context.Context, crkID string, index int) (*models.EncryptedCRKShare, error) {
	var result models.EncryptedCRKShare
	path := fmt.Sprintf("/api/v1/crk/shares/%s/%d", crkID, index)
	if err := c.request(ctx, http.MethodGet, path, nil, &result); err != nil {
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

// Admin Identity API

// CreateAdminRequest represents a request to create an admin identity.
// Requires CRK co-signature and authenticated admin caller (mTLS).
type CreateAdminRequest struct {
	Email        string             `json:"email"`
	Name         string             `json:"name"`
	Role         models.AdminRole   `json:"role"`
	CRKSignature []byte             `json:"crk_signature"`
	SSOProvider  models.SSOProvider `json:"sso_provider,omitempty"`
	SSOSubject   string             `json:"sso_subject,omitempty"`
}

// CreateAdminResponse includes the created admin and enrollment token.
type CreateAdminResponse struct {
	Admin           *models.AdminIdentity `json:"admin"`
	EnrollmentToken string                `json:"enrollment_token"`
}

// BootstrapAdminRequest represents a bootstrap admin creation request.
type BootstrapAdminRequest struct {
	OrgID        string           `json:"org_id"`
	Email        string           `json:"email"`
	Name         string           `json:"name"`
	Role         models.AdminRole `json:"role"`
	CRKSignature []byte           `json:"crk_signature"`
}

// EnrollAdminRequest represents an admin enrollment request.
type EnrollAdminRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	TOTPCode        string `json:"totp_code"`
}

// EnrollAdminResponse includes the enrolled admin and certificate.
type EnrollAdminResponse struct {
	Admin       *models.AdminIdentity `json:"admin"`
	Certificate string                `json:"certificate"`
	CertKey     string                `json:"private_key"` // nolint:gosec // G117: PEM key returned to caller
	Serial      string                `json:"serial"`
	Expiration  time.Time             `json:"expiration"`
}

// EnrollmentSetupResponse includes the TOTP provisioning URL.
type EnrollmentSetupResponse struct {
	ProvisioningURL string `json:"provisioning_url"`
}

// RenewAdminCertRequest represents a certificate renewal request.
type RenewAdminCertRequest struct {
	TOTPCode string `json:"totp_code"`
}

// RenewAdminCertResponse includes the new certificate.
type RenewAdminCertResponse struct {
	Certificate string    `json:"certificate"`
	CertKey     string    `json:"private_key"` // nolint:gosec // G117: PEM key returned to caller
	Serial      string    `json:"serial"`
	Expiration  time.Time `json:"expiration"`
}

// UpdateAdminRequest represents a request to update an admin identity.
type UpdateAdminRequest struct {
	Name   string           `json:"name,omitempty"`
	Role   models.AdminRole `json:"role,omitempty"`
	Active *bool            `json:"active,omitempty"`
}

// EnableMFAResponse represents the response from enabling MFA.
type EnableMFAResponse struct {
	Secret    string `json:"secret"`
	QRCodeURL string `json:"qr_code_url"`
}

// VerifyMFARequest represents a request to verify MFA setup.
type VerifyMFARequest struct {
	Code string `json:"code"`
}

// CreateAdmin creates a new admin identity (requires CRK co-signature and mTLS admin auth).
func (c *Client) CreateAdmin(ctx context.Context, req CreateAdminRequest) (*CreateAdminResponse, error) {
	var result CreateAdminResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/identities/admins", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// BootstrapAdmin creates the first admin for an org (only when no admins exist).
func (c *Client) BootstrapAdmin(ctx context.Context, req BootstrapAdminRequest) (*CreateAdminResponse, error) {
	var result CreateAdminResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/bootstrap/admin", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetEnrollmentSetup retrieves the TOTP provisioning URL for admin enrollment.
func (c *Client) GetEnrollmentSetup(ctx context.Context, adminID, token string) (*EnrollmentSetupResponse, error) {
	path := "/api/v1/enrollment/admins/" + adminID + "/setup?token=" + url.QueryEscape(token)
	var result EnrollmentSetupResponse
	if err := c.request(ctx, http.MethodGet, path, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// EnrollAdmin completes admin enrollment with TOTP verification and certificate issuance.
func (c *Client) EnrollAdmin(ctx context.Context, adminID string, req EnrollAdminRequest) (*EnrollAdminResponse, error) {
	var result EnrollAdminResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/enrollment/admins/"+adminID, req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RenewAdminCertificate renews an admin's mTLS certificate (requires TOTP and current mTLS auth).
func (c *Client) RenewAdminCertificate(ctx context.Context, adminID string, req RenewAdminCertRequest) (*RenewAdminCertResponse, error) {
	var result RenewAdminCertResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/identities/admins/"+adminID+"/certificate/renew", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// listAdminsResponse wraps the list of admin identities.
type listAdminsResponse struct {
	Admins []*models.AdminIdentity `json:"admins"`
}

// ListAdmins lists all admin identities.
func (c *Client) ListAdmins(ctx context.Context) ([]*models.AdminIdentity, error) {
	var result listAdminsResponse
	if err := c.request(ctx, http.MethodGet, "/api/v1/identities/admins", nil, &result); err != nil {
		return nil, err
	}
	return result.Admins, nil
}

// GetAdmin retrieves an admin identity by ID.
func (c *Client) GetAdmin(ctx context.Context, id string) (*models.AdminIdentity, error) {
	var result models.AdminIdentity
	if err := c.request(ctx, http.MethodGet, "/api/v1/identities/admins/"+id, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateAdmin updates an admin identity.
func (c *Client) UpdateAdmin(ctx context.Context, id string, req UpdateAdminRequest) (*models.AdminIdentity, error) {
	var result models.AdminIdentity
	if err := c.request(ctx, http.MethodPut, "/api/v1/identities/admins/"+id, req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteAdmin deletes an admin identity.
func (c *Client) DeleteAdmin(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/identities/admins/"+id, nil, nil)
}

// EnableMFA enables MFA for an admin identity.
func (c *Client) EnableMFA(ctx context.Context, id string) (*EnableMFAResponse, error) {
	var result EnableMFAResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/identities/admins/"+id+"/mfa/enable", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// VerifyMFA verifies MFA setup for an admin identity.
func (c *Client) VerifyMFA(ctx context.Context, id string, req VerifyMFARequest) error {
	return c.request(ctx, http.MethodPost, "/api/v1/identities/admins/"+id+"/mfa/verify", req, nil)
}

// User Identity API

// CreateUserSSORequest represents a request to create a user identity via SSO.
type CreateUserSSORequest struct {
	Email       string             `json:"email"`
	Name        string             `json:"name"`
	SSOProvider models.SSOProvider `json:"sso_provider"`
	SSOSubject  string             `json:"sso_subject"`
}

// CreateUserFromSSO creates a new user identity from SSO.
func (c *Client) CreateUserFromSSO(ctx context.Context, req CreateUserSSORequest) (*models.UserIdentity, error) {
	var result models.UserIdentity
	if err := c.request(ctx, http.MethodPost, "/api/v1/identities/users/sso", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// listUsersResponse wraps the list of user identities.
type listUsersResponse struct {
	Users []*models.UserIdentity `json:"users"`
}

// ListUsers lists all user identities.
func (c *Client) ListUsers(ctx context.Context) ([]*models.UserIdentity, error) {
	var result listUsersResponse
	if err := c.request(ctx, http.MethodGet, "/api/v1/identities/users", nil, &result); err != nil {
		return nil, err
	}
	return result.Users, nil
}

// GetUser retrieves a user identity by ID.
func (c *Client) GetUser(ctx context.Context, id string) (*models.UserIdentity, error) {
	var result models.UserIdentity
	if err := c.request(ctx, http.MethodGet, "/api/v1/identities/users/"+id, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteUser deletes a user identity.
func (c *Client) DeleteUser(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/identities/users/"+id, nil, nil)
}

// Service Identity API

// CreateServiceRequest represents a request to create a service identity.
type CreateServiceRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	AuthMethod  models.AuthMethod `json:"auth_method"`
	VaultRole   string            `json:"vault_role"`
	Namespace   string            `json:"namespace,omitempty"`
	ServiceAcct string            `json:"service_acct,omitempty"`
}

// CreateService creates a new service identity.
func (c *Client) CreateService(ctx context.Context, req CreateServiceRequest) (*models.ServiceIdentity, error) {
	var result models.ServiceIdentity
	if err := c.request(ctx, http.MethodPost, "/api/v1/identities/services", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// listServicesResponse wraps the list of service identities.
type listServicesResponse struct {
	Services []*models.ServiceIdentity `json:"services"`
}

// ListServices lists all service identities.
func (c *Client) ListServices(ctx context.Context) ([]*models.ServiceIdentity, error) {
	var result listServicesResponse
	if err := c.request(ctx, http.MethodGet, "/api/v1/identities/services", nil, &result); err != nil {
		return nil, err
	}
	return result.Services, nil
}

// GetService retrieves a service identity by ID.
func (c *Client) GetService(ctx context.Context, id string) (*models.ServiceIdentity, error) {
	var result models.ServiceIdentity
	if err := c.request(ctx, http.MethodGet, "/api/v1/identities/services/"+id, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteService deletes a service identity.
func (c *Client) DeleteService(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/identities/services/"+id, nil, nil)
}

// Device Identity API

// EnrollDeviceRequest represents a request to enroll a device.
type EnrollDeviceRequest struct {
	DeviceName string         `json:"device_name"`
	DeviceType string         `json:"device_type,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// EnrollDevice enrolls a new device identity.
func (c *Client) EnrollDevice(ctx context.Context, req EnrollDeviceRequest) (*models.DeviceIdentity, error) {
	var result models.DeviceIdentity
	if err := c.request(ctx, http.MethodPost, "/api/v1/identities/devices", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// listDevicesResponse wraps the list of device identities.
type listDevicesResponse struct {
	Devices []*models.DeviceIdentity `json:"devices"`
}

// ListDevices lists all device identities.
func (c *Client) ListDevices(ctx context.Context) ([]*models.DeviceIdentity, error) {
	var result listDevicesResponse
	if err := c.request(ctx, http.MethodGet, "/api/v1/identities/devices", nil, &result); err != nil {
		return nil, err
	}
	return result.Devices, nil
}

// GetDevice retrieves a device identity by ID.
func (c *Client) GetDevice(ctx context.Context, id string) (*models.DeviceIdentity, error) {
	var result models.DeviceIdentity
	if err := c.request(ctx, http.MethodGet, "/api/v1/identities/devices/"+id, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RevokeDevice revokes a device identity.
func (c *Client) RevokeDevice(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodPost, "/api/v1/identities/devices/"+id+"/revoke", nil, nil)
}

// Groups API

// CreateGroupRequest represents a request to create an identity group.
type CreateGroupRequest struct {
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	IDPGroupID    string   `json:"idp_group_id,omitempty"`
	VaultPolicies []string `json:"vault_policies,omitempty"`
}

// CreateGroup creates a new identity group.
func (c *Client) CreateGroup(ctx context.Context, req CreateGroupRequest) (*models.IdentityGroup, error) {
	var result models.IdentityGroup
	if err := c.request(ctx, http.MethodPost, "/api/v1/identities/groups", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateGroupRequest represents a request to update an identity group.
type UpdateGroupRequest struct {
	Name          string   `json:"name,omitempty"`
	Description   string   `json:"description,omitempty"`
	IDPGroupID    *string  `json:"idp_group_id,omitempty"`
	VaultPolicies []string `json:"vault_policies,omitempty"`
}

// UpdateGroup updates an identity group.
func (c *Client) UpdateGroup(ctx context.Context, id string, req UpdateGroupRequest) (*models.IdentityGroup, error) {
	var result models.IdentityGroup
	if err := c.request(ctx, http.MethodPut, "/api/v1/identities/groups/"+id, req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// listGroupsResponse wraps the list of identity groups.
type listGroupsResponse struct {
	Groups []*models.IdentityGroup `json:"groups"`
}

// ListGroups lists all identity groups.
func (c *Client) ListGroups(ctx context.Context) ([]*models.IdentityGroup, error) {
	var result listGroupsResponse
	if err := c.request(ctx, http.MethodGet, "/api/v1/identities/groups", nil, &result); err != nil {
		return nil, err
	}
	return result.Groups, nil
}

// GetGroup retrieves an identity group by ID.
func (c *Client) GetGroup(ctx context.Context, id string) (*models.IdentityGroup, error) {
	var result models.IdentityGroup
	if err := c.request(ctx, http.MethodGet, "/api/v1/identities/groups/"+id, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// AddGroupMemberRequest represents a request to add a member to a group.
type AddGroupMemberRequest struct {
	IdentityID   string              `json:"identity_id"`
	IdentityType models.IdentityType `json:"identity_type"`
}

// AddGroupMember adds a member to an identity group.
func (c *Client) AddGroupMember(ctx context.Context, groupID string, req AddGroupMemberRequest) error {
	return c.request(ctx, http.MethodPost, "/api/v1/identities/groups/"+groupID+"/members", req, nil)
}

// RemoveGroupMember removes a member from an identity group.
func (c *Client) RemoveGroupMember(ctx context.Context, groupID, identityID string) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/identities/groups/"+groupID+"/members/"+identityID, nil, nil)
}

// Group Join Requests API

// RequestGroupJoinRequest represents a request to join a group.
type RequestGroupJoinRequest struct {
	Justification string `json:"justification,omitempty"`
}

// RequestGroupJoin submits a request to join an identity group.
func (c *Client) RequestGroupJoin(ctx context.Context, groupID string, req RequestGroupJoinRequest) (*models.GroupJoinRequest, error) {
	var result models.GroupJoinRequest
	if err := c.request(ctx, http.MethodPost, "/api/v1/identities/groups/"+groupID+"/join-requests", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// listGroupJoinRequestsResponse wraps the list of group join requests.
type listGroupJoinRequestsResponse struct {
	Requests []*models.GroupJoinRequest `json:"requests"`
	Count    int                        `json:"count"`
}

// ListGroupJoinRequests lists pending join requests for a group.
func (c *Client) ListGroupJoinRequests(ctx context.Context, groupID string) ([]*models.GroupJoinRequest, error) {
	var result listGroupJoinRequestsResponse
	if err := c.request(ctx, http.MethodGet, "/api/v1/identities/groups/"+groupID+"/join-requests", nil, &result); err != nil {
		return nil, err
	}
	return result.Requests, nil
}

// ApproveGroupJoinRequest approves a pending group join request.
func (c *Client) ApproveGroupJoinRequest(ctx context.Context, groupID, requestID string) error {
	return c.request(ctx, http.MethodPost, "/api/v1/identities/groups/"+groupID+"/join-requests/"+requestID+"/approve", nil, nil)
}

// DenyGroupJoinRequest denies a pending group join request.
func (c *Client) DenyGroupJoinRequest(ctx context.Context, groupID, requestID string) error {
	return c.request(ctx, http.MethodPost, "/api/v1/identities/groups/"+groupID+"/join-requests/"+requestID+"/deny", nil, nil)
}

// RequestWorkspaceAccessRequest represents a request to access a workspace.
type RequestWorkspaceAccessRequest struct {
	Justification string `json:"justification,omitempty"`
}

// RequestWorkspaceAccess submits a request to access a workspace by joining its bound group.
func (c *Client) RequestWorkspaceAccess(ctx context.Context, workspaceID string, req RequestWorkspaceAccessRequest) (*models.GroupJoinRequest, error) {
	var result models.GroupJoinRequest
	if err := c.request(ctx, http.MethodPost, "/api/v1/workspaces/"+workspaceID+"/request-access", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Roles API

// CreateRoleRequest represents a request to create a role.
type CreateRoleRequest struct {
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	Permissions []models.Permission `json:"permissions"`
}

// CreateRole creates a new role.
func (c *Client) CreateRole(ctx context.Context, req CreateRoleRequest) (*models.Role, error) {
	var result models.Role
	if err := c.request(ctx, http.MethodPost, "/api/v1/identities/roles", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// listRolesResponse wraps the list of roles.
type listRolesResponse struct {
	Roles []*models.Role `json:"roles"`
}

// ListRoles lists all roles.
func (c *Client) ListRoles(ctx context.Context) ([]*models.Role, error) {
	var result listRolesResponse
	if err := c.request(ctx, http.MethodGet, "/api/v1/identities/roles", nil, &result); err != nil {
		return nil, err
	}
	return result.Roles, nil
}

// GetRole retrieves a role by ID.
func (c *Client) GetRole(ctx context.Context, id string) (*models.Role, error) {
	var result models.Role
	if err := c.request(ctx, http.MethodGet, "/api/v1/identities/roles/"+id, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// AssignRoleRequest represents a request to assign a role to an identity.
type AssignRoleRequest struct {
	IdentityID   string              `json:"identity_id"`
	IdentityType models.IdentityType `json:"identity_type"`
}

// AssignRole assigns a role to an identity.
func (c *Client) AssignRole(ctx context.Context, roleID string, req AssignRoleRequest) error {
	return c.request(ctx, http.MethodPost, "/api/v1/identities/roles/"+roleID+"/assign", req, nil)
}

// UnassignRole removes a role assignment from an identity.
func (c *Client) UnassignRole(ctx context.Context, roleID, identityID string) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/identities/roles/"+roleID+"/assignments/"+identityID, nil, nil)
}

// requestRaw makes an HTTP request and returns the raw response body.
func (c *Client) requestRaw(ctx context.Context, method, path string, body any) ([]byte, error) {
	u, err := url.JoinPath(c.baseURL, path)
	if err != nil {
		return nil, fmt.Errorf("build URL: %w", err)
	}

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, reqBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.orgID != "" {
		req.Header.Set("X-Org-ID", c.orgID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp ErrorResponse
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, errResp.Error)
		}
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// ============================================================================
// Workspace API — Additional Methods
// ============================================================================

// DeleteWorkspaceRequest represents a workspace deletion request.
type DeleteWorkspaceRequest struct {
	Signatures map[string][]byte `json:"signatures,omitempty"`
}

// DeleteWorkspace deletes a workspace.
func (c *Client) DeleteWorkspace(ctx context.Context, id string, req DeleteWorkspaceRequest) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/workspaces/"+id, req, nil)
}

// ArchiveWorkspaceRequest represents a workspace archive request.
type ArchiveWorkspaceRequest struct {
	Signature []byte `json:"signature,omitempty"`
}

// ArchiveWorkspace archives a workspace.
func (c *Client) ArchiveWorkspace(ctx context.Context, id string, req ArchiveWorkspaceRequest) error {
	return c.request(ctx, http.MethodPost, "/api/v1/workspaces/"+id+"/archive", req, nil)
}

// ============================================================================
// Federation API — Additional Methods
// ============================================================================

// InitFederationRequest represents a federation initialization request.
type InitFederationRequest struct {
	OrgID        string `json:"org_id"`
	CRKSignature []byte `json:"crk_signature,omitempty"`
}

// InitFederationResponse represents a federation initialization response.
type InitFederationResponse struct {
	OrgID       string `json:"org_id"`
	CSR         []byte `json:"csr"`
	Certificate []byte `json:"certificate"`
	PublicKey   []byte `json:"public_key"`
}

// InitFederation initializes federation for the organization.
func (c *Client) InitFederation(ctx context.Context, req InitFederationRequest) (*InitFederationResponse, error) {
	var result InitFederationResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/federation/init", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// EstablishFederationRequest represents a federation establishment request.
type EstablishFederationRequest struct {
	PartnerOrgID string `json:"partner_org_id"`
	PartnerURL   string `json:"partner_url"`
	PartnerCert  []byte `json:"partner_cert,omitempty"`
	PartnerCSR   []byte `json:"partner_csr,omitempty"`
	CRKSignature []byte `json:"crk_signature,omitempty"`
}

// EstablishFederation establishes a federation with a partner organization.
func (c *Client) EstablishFederation(ctx context.Context, req EstablishFederationRequest) (*models.Federation, error) {
	var result models.Federation
	if err := c.request(ctx, http.MethodPost, "/api/v1/federation/establish", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RevokeFederationRequest represents a federation revocation request.
type RevokeFederationRequest struct {
	Signature     []byte `json:"signature,omitempty"`
	NotifyPartner bool   `json:"notify_partner,omitempty"`
	RevokeCerts   bool   `json:"revoke_certs,omitempty"`
}

// RevokeFederation revokes a federation with a partner organization.
func (c *Client) RevokeFederation(ctx context.Context, partnerOrgID string, req RevokeFederationRequest) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/federation/"+partnerOrgID, req, nil)
}

// FederationHealthResult represents the health of a federation partner.
type FederationHealthResult struct {
	PartnerOrgID string    `json:"partner_org_id"`
	Healthy      bool      `json:"healthy"`
	LastCheck    time.Time `json:"last_check"`
	Error        string    `json:"error,omitempty"`
}

// FederationHealthResponse represents the federation health check response.
type FederationHealthResponse struct {
	Results []FederationHealthResult `json:"results"`
}

// FederationHealth checks the health of all federation partners.
func (c *Client) FederationHealth(ctx context.Context) (*FederationHealthResponse, error) {
	var result FederationHealthResponse
	if err := c.request(ctx, http.MethodGet, "/api/v1/federation/health", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ImportFederationCertificateRequest represents a certificate import request.
type ImportFederationCertificateRequest struct {
	PartnerOrgID string `json:"partner_org_id"`
	Certificate  []byte `json:"certificate"`
	Signature    []byte `json:"signature,omitempty"`
}

// ImportFederationCertificate imports a federation partner's certificate.
func (c *Client) ImportFederationCertificate(ctx context.Context, req ImportFederationCertificateRequest) error {
	return c.request(ctx, http.MethodPost, "/api/v1/federation/certificate/import", req, nil)
}

// RenewFederationCertRequest represents a federation certificate renewal request.
type RenewFederationCertRequest struct {
	Signature []byte `json:"signature,omitempty"`
}

// RenewFederationCertResponse represents the renewal response.
type RenewFederationCertResponse struct {
	Certificate []byte `json:"certificate"`
	PartnerID   string `json:"partner_id"`
}

// RenewFederationCert renews a federation certificate for a partner.
func (c *Client) RenewFederationCert(ctx context.Context, partnerOrgID string, req RenewFederationCertRequest) (*RenewFederationCertResponse, error) {
	var result RenewFederationCertResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/federation/"+partnerOrgID+"/renew-cert", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ============================================================================
// Policy API
// ============================================================================

// CreatePolicyRequest represents a policy creation request.
type CreatePolicyRequest struct {
	Name         string `json:"name"`
	Workspace    string `json:"workspace"`
	Rego         string `json:"rego"`
	CRKSignature []byte `json:"crk_signature,omitempty"`
}

// CreatePolicy creates a new policy.
func (c *Client) CreatePolicy(ctx context.Context, req CreatePolicyRequest) (*models.Policy, error) {
	var result models.Policy
	if err := c.request(ctx, http.MethodPost, "/api/v1/policies", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetPolicy retrieves a policy by ID.
func (c *Client) GetPolicy(ctx context.Context, id string) (*models.Policy, error) {
	var result models.Policy
	if err := c.request(ctx, http.MethodGet, "/api/v1/policies/"+id, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdatePolicyRequest represents a policy update request.
type UpdatePolicyRequest struct {
	Rego      string `json:"rego"`
	Signature []byte `json:"signature,omitempty"`
}

// UpdatePolicy updates a policy.
func (c *Client) UpdatePolicy(ctx context.Context, id string, req UpdatePolicyRequest) (*models.Policy, error) {
	var result models.Policy
	if err := c.request(ctx, http.MethodPut, "/api/v1/policies/"+id, req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeletePolicyRequest represents a policy deletion request.
type DeletePolicyRequest struct {
	Signature []byte `json:"signature,omitempty"`
}

// DeletePolicy deletes a policy.
func (c *Client) DeletePolicy(ctx context.Context, id string, req DeletePolicyRequest) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/policies/"+id, req, nil)
}

// PoliciesForWorkspaceResponse represents the response for workspace policies.
type PoliciesForWorkspaceResponse struct {
	Policies []*models.Policy `json:"policies"`
	Count    int              `json:"count"`
}

// GetPoliciesForWorkspace retrieves policies for a workspace.
func (c *Client) GetPoliciesForWorkspace(ctx context.Context, workspaceID string) (*PoliciesForWorkspaceResponse, error) {
	var result PoliciesForWorkspaceResponse
	if err := c.request(ctx, http.MethodGet, "/api/v1/policies/workspace/"+workspaceID, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// EvaluatePolicyRequest represents a policy evaluation request.
type EvaluatePolicyRequest struct {
	Actor     string         `json:"actor"`
	Role      string         `json:"role"`
	Operation string         `json:"operation"`
	Workspace string         `json:"workspace"`
	Purpose   string         `json:"purpose,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// EvaluatePolicyResponse represents a policy evaluation response.
type EvaluatePolicyResponse struct {
	Allowed    bool   `json:"Allowed"`
	DenyReason string `json:"DenyReason,omitempty"`
	PolicyID   string `json:"PolicyID,omitempty"`
	EvalTimeMs int64  `json:"EvalTimeMs,omitempty"`
}

// EvaluatePolicy evaluates a policy.
func (c *Client) EvaluatePolicy(ctx context.Context, req EvaluatePolicyRequest) (*EvaluatePolicyResponse, error) {
	var result EvaluatePolicyResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/policies/evaluate", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ValidatePolicyRequest represents a policy validation request.
type ValidatePolicyRequest struct {
	Rego string `json:"rego"`
}

// ValidatePolicyResponse represents a policy validation response.
type ValidatePolicyResponse struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

// ValidatePolicy validates a Rego policy on the server.
func (c *Client) ValidatePolicy(ctx context.Context, req ValidatePolicyRequest) (*ValidatePolicyResponse, error) {
	var result ValidatePolicyResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/policies/validate", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ============================================================================
// Audit API — Additional Methods
// ============================================================================

// GetAuditEvent retrieves an audit event by ID.
func (c *Client) GetAuditEvent(ctx context.Context, id string) (*models.AuditEvent, error) {
	var result models.AuditEvent
	if err := c.request(ctx, http.MethodGet, "/api/v1/audit/"+id, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ExportAuditRequest represents an audit export request.
type ExportAuditRequest struct {
	OrgID     string `json:"org_id,omitempty"`
	Workspace string `json:"workspace,omitempty"`
	EventType string `json:"event_type,omitempty"`
	Since     string `json:"since,omitempty"`
	Until     string `json:"until,omitempty"`
	Format    string `json:"format,omitempty"`
}

// ExportAudit exports audit logs, returning raw bytes (JSON or CSV).
func (c *Client) ExportAudit(ctx context.Context, req ExportAuditRequest) ([]byte, error) {
	return c.requestRaw(ctx, http.MethodPost, "/api/v1/audit/export", req)
}

// AuditStatsResponse represents audit statistics.
type AuditStatsResponse struct {
	TotalEvents  int64            `json:"TotalEvents"`
	SuccessCount int64            `json:"SuccessCount"`
	ErrorCount   int64            `json:"ErrorCount"`
	DeniedCount  int64            `json:"DeniedCount"`
	EventsByType map[string]int64 `json:"EventsByType,omitempty"`
	EventsByOrg  map[string]int64 `json:"EventsByOrg,omitempty"`
	UniqueActors int64            `json:"UniqueActors"`
	TimeRange    float64          `json:"TimeRange"`
}

// GetAuditStats retrieves audit statistics.
func (c *Client) GetAuditStats(ctx context.Context, since string) (*AuditStatsResponse, error) {
	path := "/api/v1/audit/stats"
	if since != "" {
		path += "?since=" + url.QueryEscape(since)
	}
	var result AuditStatsResponse
	if err := c.request(ctx, http.MethodGet, path, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// VerifyAuditIntegrityRequest represents an audit integrity verification request.
type VerifyAuditIntegrityRequest struct {
	Since string `json:"since,omitempty"`
	Until string `json:"until,omitempty"`
}

// VerifyAuditIntegrityResponse represents an audit integrity verification response.
type VerifyAuditIntegrityResponse struct {
	Valid bool   `json:"valid"`
	Since string `json:"since,omitempty"`
	Until string `json:"until,omitempty"`
}

// VerifyAuditIntegrity verifies the integrity of audit logs.
func (c *Client) VerifyAuditIntegrity(ctx context.Context, req VerifyAuditIntegrityRequest) (*VerifyAuditIntegrityResponse, error) {
	var result VerifyAuditIntegrityResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/audit/verify", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ============================================================================
// Edge API — Additional Methods
// ============================================================================

// EdgeHealthResponse represents edge node health status.
type EdgeHealthResponse struct {
	Healthy      bool    `json:"Healthy"`
	LastChecked  string  `json:"LastChecked,omitempty"`
	VaultSealed  bool    `json:"VaultSealed"`
	HAEnabled    bool    `json:"HAEnabled"`
	HAMode       string  `json:"HAMode,omitempty"`
	ClusterNodes int     `json:"ClusterNodes"`
	Version      string  `json:"Version,omitempty"`
	Latency      float64 `json:"Latency"`
	ErrorMessage string  `json:"ErrorMessage,omitempty"`
}

// GetEdgeHealth retrieves the health status of an edge node.
func (c *Client) GetEdgeHealth(ctx context.Context, id string) (*EdgeHealthResponse, error) {
	var result EdgeHealthResponse
	if err := c.request(ctx, http.MethodGet, "/api/v1/edges/"+id+"/health", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SyncEdgePolicies triggers policy synchronization for an edge node.
func (c *Client) SyncEdgePolicies(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodPost, "/api/v1/edges/"+id+"/sync/policies", nil, nil)
}

// SyncEdgeKeysRequest represents a key sync request for an edge node.
type SyncEdgeKeysRequest struct {
	WorkspaceID string `json:"workspace_id"`
	WrappedDEK  []byte `json:"wrapped_dek"`
}

// SyncEdgeKeys triggers key synchronization for an edge node.
func (c *Client) SyncEdgeKeys(ctx context.Context, id string, req SyncEdgeKeysRequest) error {
	return c.request(ctx, http.MethodPost, "/api/v1/edges/"+id+"/sync/keys", req, nil)
}

// EdgeSyncStatusResponse represents edge node sync status.
type EdgeSyncStatusResponse struct {
	LastSyncedAt   string `json:"LastSyncedAt,omitempty"`
	SyncInProgress bool   `json:"SyncInProgress"`
	PoliciesSynced int    `json:"PoliciesSynced"`
	KeysSynced     int    `json:"KeysSynced"`
	ErrorCount     int    `json:"ErrorCount"`
	LastError      string `json:"LastError,omitempty"`
}

// GetEdgeSyncStatus retrieves the sync status of an edge node.
func (c *Client) GetEdgeSyncStatus(ctx context.Context, id string) (*EdgeSyncStatusResponse, error) {
	var result EdgeSyncStatusResponse
	if err := c.request(ctx, http.MethodGet, "/api/v1/edges/"+id+"/sync/status", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ============================================================================
// Metrics API
// ============================================================================

// GetMetrics retrieves Prometheus metrics from the server.
func (c *Client) GetMetrics(ctx context.Context) (string, error) {
	data, err := c.requestRaw(ctx, http.MethodGet, "/metrics", nil)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ============================================================================
// Activity Log API
// ============================================================================

// GetActivityLog retrieves audit events for a specific actor.
func (c *Client) GetActivityLog(ctx context.Context, actorID string, params AuditQueryParams) ([]*models.AuditEvent, error) {
	path := "/api/v1/audit?actor=" + url.QueryEscape(actorID)
	if params.Since != "" {
		path += "&since=" + url.QueryEscape(params.Since)
	}
	if params.Until != "" {
		path += "&until=" + url.QueryEscape(params.Until)
	}
	if params.Limit > 0 {
		path += fmt.Sprintf("&limit=%d", params.Limit)
	}
	var result []*models.AuditEvent
	if err := c.request(ctx, http.MethodGet, path, nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// ============================================================================
// CRK API — Additional Methods
// ============================================================================

// RotateCRKRequest represents a CRK rotation request.
type RotateCRKRequest struct {
	OrgID     string `json:"org_id,omitempty"`
	Threshold int    `json:"threshold"`
}

// RotateCRK initiates a CRK rotation ceremony.
func (c *Client) RotateCRK(ctx context.Context, req RotateCRKRequest) (*CeremonyResponse, error) {
	var result CeremonyResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/crk/rotate", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ============================================================================
// Certificate API
// ============================================================================

// IssueCertificateRequest represents a certificate issuance request.
type IssueCertificateRequest struct {
	CommonName string   `json:"common_name"`
	AltNames   []string `json:"alt_names,omitempty"`
	TTL        string   `json:"ttl,omitempty"`
}

// CertificateResponse represents a certificate response.
type CertificateResponse struct {
	Certificate    string   `json:"certificate"`
	PrivateKey     string   `json:"private_key,omitempty"`
	PrivateKeyType string   `json:"private_key_type,omitempty"`
	SerialNumber   string   `json:"serial_number"`
	IssuingCA      string   `json:"issuing_ca,omitempty"`
	CAChain        []string `json:"ca_chain,omitempty"`
	Expiration     string   `json:"expiration,omitempty"`
}

// IssueCertificate issues a new certificate.
func (c *Client) IssueCertificate(ctx context.Context, role string, req IssueCertificateRequest) (*CertificateResponse, error) {
	path := "/api/v1/certificates/issue"
	if role != "" {
		path += "?role=" + url.QueryEscape(role)
	}
	var result CertificateResponse
	if err := c.request(ctx, http.MethodPost, path, req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RevokeCertificateRequest represents a certificate revocation request.
type RevokeCertificateRequest struct {
	SerialNumber string `json:"serial_number"`
}

// RevokeCertificate revokes a certificate.
func (c *Client) RevokeCertificate(ctx context.Context, serialNumber string) error {
	return c.request(ctx, http.MethodPost, "/api/v1/certificates/revoke", RevokeCertificateRequest{SerialNumber: serialNumber}, nil)
}

// ReadCertificate retrieves a certificate by serial number.
func (c *Client) ReadCertificate(ctx context.Context, serial string) (*CertificateResponse, error) {
	var result CertificateResponse
	if err := c.request(ctx, http.MethodGet, "/api/v1/certificates/"+url.PathEscape(serial), nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CertificateListResponse represents a certificate list response.
type CertificateListResponse struct {
	Certificates []string `json:"certificates"`
	Count        int      `json:"count"`
}

// ListCertificates lists all certificates.
func (c *Client) ListCertificates(ctx context.Context) (*CertificateListResponse, error) {
	var result CertificateListResponse
	if err := c.request(ctx, http.MethodGet, "/api/v1/certificates", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CAChainResponse represents a CA chain response.
type CAChainResponse struct {
	CAChain string `json:"ca_chain"`
}

// GetCAChain retrieves the CA certificate chain.
func (c *Client) GetCAChain(ctx context.Context) (*CAChainResponse, error) {
	var result CAChainResponse
	if err := c.request(ctx, http.MethodGet, "/api/v1/certificates/ca-chain", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// TidyCertificatesRequest represents a tidy certificates request.
type TidyCertificatesRequest struct {
	SafetyBuffer string `json:"safety_buffer,omitempty"`
}

// TidyCertificates triggers certificate store cleanup.
func (c *Client) TidyCertificates(ctx context.Context, safetyBuffer string) error {
	req := TidyCertificatesRequest{SafetyBuffer: safetyBuffer}
	return c.request(ctx, http.MethodPost, "/api/v1/certificates/tidy", req, nil)
}

// ============================================================================
// Workspace Export/Import API
// ============================================================================

// WorkspaceBundleResponse represents an exported workspace bundle.
type WorkspaceBundleResponse struct {
	Workspace  *models.Workspace `json:"workspace"`
	Policies   []byte            `json:"policies,omitempty"`
	ExportedAt string            `json:"exported_at"`
	ExportedBy string            `json:"exported_by"`
	Checksum   string            `json:"checksum"`
}

// ExportWorkspace exports a workspace as a bundle.
func (c *Client) ExportWorkspace(ctx context.Context, id string) (*WorkspaceBundleResponse, error) {
	var result WorkspaceBundleResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/workspaces/"+id+"/export", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ImportWorkspace imports a workspace from a bundle.
func (c *Client) ImportWorkspace(ctx context.Context, bundle *WorkspaceBundleResponse) (*models.Workspace, error) {
	var result models.Workspace
	if err := c.request(ctx, http.MethodPost, "/api/v1/workspaces/import", bundle, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ============================================================================
// Service Credential Rotation API
// ============================================================================

// RotateServiceCredentials rotates credentials for a service identity.
func (c *Client) RotateServiceCredentials(ctx context.Context, id string) (*models.ServiceIdentity, error) {
	var result models.ServiceIdentity
	if err := c.request(ctx, http.MethodPost, "/api/v1/identities/services/"+id+"/rotate", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ============================================================================
// Emergency Access API
// ============================================================================

// EmergencyAccessRequestPayload represents an emergency access request payload.
type EmergencyAccessRequestPayload struct {
	OrgID  string `json:"org_id,omitempty"`
	Reason string `json:"reason"`
}

// RequestEmergencyAccess initiates an emergency access request.
func (c *Client) RequestEmergencyAccess(ctx context.Context, req EmergencyAccessRequestPayload) (*models.EmergencyAccessRequest, error) {
	var result models.EmergencyAccessRequest
	if err := c.request(ctx, http.MethodPost, "/api/v1/emergency-access/request", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ApproveEmergencyAccess approves an emergency access request.
func (c *Client) ApproveEmergencyAccess(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodPost, "/api/v1/emergency-access/"+id+"/approve", nil, nil)
}

// DenyEmergencyAccess denies an emergency access request.
func (c *Client) DenyEmergencyAccess(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodPost, "/api/v1/emergency-access/"+id+"/deny", nil, nil)
}

// CompleteEmergencyAccess completes an emergency access request.
func (c *Client) CompleteEmergencyAccess(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodPost, "/api/v1/emergency-access/"+id+"/complete", nil, nil)
}

// VerifyEmergencyAccessPayload represents a CRK verification request.
type VerifyEmergencyAccessPayload struct {
	Signature []byte `json:"signature"`
}

// VerifyEmergencyAccess verifies an emergency access request with CRK.
func (c *Client) VerifyEmergencyAccess(ctx context.Context, id string, signature []byte) error {
	return c.request(ctx, http.MethodPost, "/api/v1/emergency-access/"+id+"/verify", VerifyEmergencyAccessPayload{Signature: signature}, nil)
}

// EmergencyAccessListResponse represents the list response.
type EmergencyAccessListResponse struct {
	Requests []*models.EmergencyAccessRequest `json:"requests"`
	Count    int                              `json:"count"`
}

// ListEmergencyAccess lists emergency access requests.
func (c *Client) ListEmergencyAccess(ctx context.Context, orgID string) (*EmergencyAccessListResponse, error) {
	path := "/api/v1/emergency-access"
	if orgID != "" {
		path += "?org_id=" + url.QueryEscape(orgID)
	}
	var result EmergencyAccessListResponse
	if err := c.request(ctx, http.MethodGet, path, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetEmergencyAccess retrieves an emergency access request by ID.
func (c *Client) GetEmergencyAccess(ctx context.Context, id string) (*models.EmergencyAccessRequest, error) {
	var result models.EmergencyAccessRequest
	if err := c.request(ctx, http.MethodGet, "/api/v1/emergency-access/"+id, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ============================================================================
// Account Recovery API
// ============================================================================

// InitiateRecoveryRequest represents an account recovery initiation request.
type InitiateRecoveryRequest struct {
	AdminID      string `json:"admin_id"`
	RecoveryType string `json:"recovery_type"`
	Reason       string `json:"reason"`
}

// InitiateRecovery initiates an account recovery.
func (c *Client) InitiateRecovery(ctx context.Context, req InitiateRecoveryRequest) (*models.AccountRecovery, error) {
	var result models.AccountRecovery
	if err := c.request(ctx, http.MethodPost, "/api/v1/account-recovery/initiate", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CollectRecoveryShare submits a share for account recovery.
func (c *Client) CollectRecoveryShare(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodPost, "/api/v1/account-recovery/"+id+"/share", nil, nil)
}

// CompleteRecovery completes an account recovery.
func (c *Client) CompleteRecovery(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodPost, "/api/v1/account-recovery/"+id+"/complete", nil, nil)
}

// ============================================================================
// Compliance API
// ============================================================================

// ComplianceReportRequest represents a compliance report request.
type ComplianceReportRequest struct {
	OrgID string `json:"org_id,omitempty"`
	Since string `json:"since,omitempty"`
	Until string `json:"until,omitempty"`
}

// ComplianceReport represents a generated compliance report.
type ComplianceReport struct {
	ID          string          `json:"id"`
	Type        string          `json:"type"`
	GeneratedAt string          `json:"generated_at"`
	GeneratedBy string          `json:"generated_by"`
	Period      json.RawMessage `json:"period"`
	Data        json.RawMessage `json:"data"`
}

// GenerateComplianceSummary generates a compliance summary report.
func (c *Client) GenerateComplianceSummary(ctx context.Context, req ComplianceReportRequest) (*ComplianceReport, error) {
	var result ComplianceReport
	if err := c.request(ctx, http.MethodPost, "/api/v1/compliance/reports/summary", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DSARRequest represents a GDPR DSAR request.
type DSARRequest struct {
	OrgID     string `json:"org_id,omitempty"`
	SubjectID string `json:"subject_id"`
}

// GenerateGDPRDSAR generates a GDPR Data Subject Access Request report.
func (c *Client) GenerateGDPRDSAR(ctx context.Context, req DSARRequest) (*ComplianceReport, error) {
	var result ComplianceReport
	if err := c.request(ctx, http.MethodPost, "/api/v1/compliance/reports/gdpr-dsar", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GenerateAccessReview generates an access review report.
func (c *Client) GenerateAccessReview(ctx context.Context, req ComplianceReportRequest) (*ComplianceReport, error) {
	var result ComplianceReport
	if err := c.request(ctx, http.MethodPost, "/api/v1/compliance/reports/access-review", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ============================================================================
// Rotation Policy API
// ============================================================================

// RotationPolicy represents a key rotation policy.
type RotationPolicy struct {
	WorkspaceID string `json:"workspace_id"`
	MaxAge      string `json:"max_age"`
	Enabled     bool   `json:"enabled"`
}

// SetRotationPolicyRequest represents a set rotation policy request.
type SetRotationPolicyRequest struct {
	MaxAge  string `json:"max_age"`
	Enabled bool   `json:"enabled"`
}

// SetRotationPolicy sets a rotation policy for a workspace.
func (c *Client) SetRotationPolicy(ctx context.Context, workspaceID string, req SetRotationPolicyRequest) (*RotationPolicy, error) {
	var result RotationPolicy
	if err := c.request(ctx, http.MethodPut, "/api/v1/workspaces/"+workspaceID+"/rotation-policy", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetRotationPolicy retrieves the rotation policy for a workspace.
func (c *Client) GetRotationPolicy(ctx context.Context, workspaceID string) (*RotationPolicy, error) {
	var result RotationPolicy
	if err := c.request(ctx, http.MethodGet, "/api/v1/workspaces/"+workspaceID+"/rotation-policy", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteRotationPolicy removes the rotation policy for a workspace.
func (c *Client) DeleteRotationPolicy(ctx context.Context, workspaceID string) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/workspaces/"+workspaceID+"/rotation-policy", nil, nil)
}

// RotationPolicyListResponse represents a rotation policy list response.
type RotationPolicyListResponse struct {
	Policies []*RotationPolicy `json:"policies"`
	Count    int               `json:"count"`
}

// ListRotationPolicies lists all rotation policies.
func (c *Client) ListRotationPolicies(ctx context.Context) (*RotationPolicyListResponse, error) {
	var result RotationPolicyListResponse
	if err := c.request(ctx, http.MethodGet, "/api/v1/rotation-policies", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ============================================================================
// Backup API
// ============================================================================

// CreateBackupRequest represents a backup creation request.
type CreateBackupRequest struct {
	Type         string `json:"type"`
	CRKSignature []byte `json:"crk_signature,omitempty"`
}

// CreateBackup creates a new backup.
func (c *Client) CreateBackup(ctx context.Context, req CreateBackupRequest) (*models.Backup, error) {
	var result models.Backup
	if err := c.request(ctx, http.MethodPost, "/api/v1/backups", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// BackupListResponse represents a backup list response.
type BackupListResponse struct {
	Backups []*models.Backup `json:"backups"`
	Count   int              `json:"count"`
}

// ListBackups lists all backups.
func (c *Client) ListBackups(ctx context.Context) (*BackupListResponse, error) {
	var result BackupListResponse
	if err := c.request(ctx, http.MethodGet, "/api/v1/backups", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetBackup retrieves a backup by ID.
func (c *Client) GetBackup(ctx context.Context, id string) (*models.Backup, error) {
	var result models.Backup
	if err := c.request(ctx, http.MethodGet, "/api/v1/backups/"+id, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RestoreBackupRequest represents a backup restore request.
type RestoreBackupRequest struct {
	CRKSignature []byte `json:"crk_signature,omitempty"`
}

// RestoreBackup restores from a backup.
func (c *Client) RestoreBackup(ctx context.Context, id string, req RestoreBackupRequest) error {
	return c.request(ctx, http.MethodPost, "/api/v1/backups/"+id+"/restore", req, nil)
}

// ============================================================================
// Activity API
// ============================================================================

// ActivityListResponse represents an activity list response.
type ActivityListResponse struct {
	Events []*models.AuditEvent `json:"events"`
	Count  int                  `json:"count"`
	Actor  string               `json:"actor"`
}

// ListActivity lists the caller's own activity.
func (c *Client) ListActivity(ctx context.Context, params AuditQueryParams) (*ActivityListResponse, error) {
	path := "/api/v1/activity?"
	if params.Since != "" {
		path += "since=" + url.QueryEscape(params.Since) + "&"
	}
	if params.Until != "" {
		path += "until=" + url.QueryEscape(params.Until) + "&"
	}
	if params.Limit > 0 {
		path += fmt.Sprintf("limit=%d&", params.Limit)
	}
	var result ActivityListResponse
	if err := c.request(ctx, http.MethodGet, path, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ExportActivityRequest represents an activity export request.
type ExportActivityRequest struct {
	Since  string `json:"since,omitempty"`
	Until  string `json:"until,omitempty"`
	Format string `json:"format,omitempty"`
}

// ExportActivity exports the caller's activity log.
func (c *Client) ExportActivity(ctx context.Context, req ExportActivityRequest) ([]byte, error) {
	return c.requestRaw(ctx, http.MethodPost, "/api/v1/activity/export", req)
}

// ============================================================================
// Direct Messaging API
// ============================================================================

// SendMessageRequest represents a message send request.
type SendMessageRequest struct {
	RecipientOrgID string `json:"recipient_org_id"`
	RecipientID    string `json:"recipient_id"`
	Subject        string `json:"subject"`
	Body           []byte `json:"body"`
	ConversationID string `json:"conversation_id,omitempty"`
}

// MessageListResponse represents a message list response.
type MessageListResponse struct {
	Messages []*models.DirectMessage `json:"messages"`
	Count    int                     `json:"count"`
}

// SendMessage sends a direct message.
func (c *Client) SendMessage(ctx context.Context, req SendMessageRequest) (*models.DirectMessage, error) {
	var result models.DirectMessage
	if err := c.request(ctx, http.MethodPost, "/api/v1/messages", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListMessages lists inbox messages (received).
func (c *Client) ListMessages(ctx context.Context, limit, offset int) (*MessageListResponse, error) {
	path := fmt.Sprintf("/api/v1/messages?limit=%d&offset=%d", limit, offset)
	var result MessageListResponse
	if err := c.request(ctx, http.MethodGet, path, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListSentMessages lists sent messages.
func (c *Client) ListSentMessages(ctx context.Context, limit, offset int) (*MessageListResponse, error) {
	path := fmt.Sprintf("/api/v1/messages/sent?limit=%d&offset=%d", limit, offset)
	var result MessageListResponse
	if err := c.request(ctx, http.MethodGet, path, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ReadMessage reads a message by ID (decrypts and marks as read).
func (c *Client) ReadMessage(ctx context.Context, id string) (*models.DirectMessage, error) {
	var result models.DirectMessage
	if err := c.request(ctx, http.MethodGet, "/api/v1/messages/"+id, nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteMessage deletes a message by ID.
func (c *Client) DeleteMessage(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/messages/"+id, nil, nil)
}

// SSOConfigResponse represents SSO configuration from the server.
type SSOConfigResponse struct {
	IssuerURL string `json:"issuer_url"`
	ClientID  string `json:"client_id"`
}

// GetSSOConfig retrieves SSO configuration from the server (unauthenticated).
func (c *Client) GetSSOConfig(ctx context.Context) (*SSOConfigResponse, error) {
	var result SSOConfigResponse
	if err := c.request(ctx, http.MethodGet, "/api/v1/sso-config", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
