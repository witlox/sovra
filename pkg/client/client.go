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

// UpdateWorkspaceRequest represents a workspace update request.
type UpdateWorkspaceRequest struct {
	Purpose        string                `json:"purpose,omitempty"`
	Classification models.Classification `json:"classification,omitempty"`
	Mode           models.WorkspaceMode  `json:"mode,omitempty"`
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

// CancelCRKCeremony cancels an ongoing CRK ceremony.
func (c *Client) CancelCRKCeremony(ctx context.Context, ceremonyID string) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/crk/ceremony/"+ceremonyID, nil, nil)
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
type CreateAdminRequest struct {
	Email    string           `json:"email"`
	Name     string           `json:"name"`
	Role     models.AdminRole `json:"role"`
	Password string           `json:"password"`
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

// CreateAdmin creates a new admin identity.
func (c *Client) CreateAdmin(ctx context.Context, req CreateAdminRequest) (*models.AdminIdentity, error) {
	var result models.AdminIdentity
	if err := c.request(ctx, http.MethodPost, "/api/v1/identities/admins", req, &result); err != nil {
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
