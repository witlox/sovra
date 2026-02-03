// Package vault provides authentication backend configuration for HashiCorp Vault.
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/go-version"
)

// SupportedVersionMin is the minimum supported Vault version.
const SupportedVersionMin = "1.12.0"

// SupportedVersionMax is the maximum supported Vault version.
const SupportedVersionMax = "1.18.99"

// AuthBackendType represents the type of authentication backend.
type AuthBackendType string

const (
	// AuthBackendJWT is the JWT/OIDC authentication backend.
	AuthBackendJWT AuthBackendType = "jwt"
	// AuthBackendOIDC is the OIDC authentication backend.
	AuthBackendOIDC AuthBackendType = "oidc"
	// AuthBackendKubernetes is the Kubernetes authentication backend.
	AuthBackendKubernetes AuthBackendType = "kubernetes"
	// AuthBackendAppRole is the AppRole authentication backend.
	AuthBackendAppRole AuthBackendType = "approle"
)

// JWTConfig holds configuration for JWT/OIDC authentication backend.
type JWTConfig struct {
	// Path is the mount path for the auth backend.
	Path string
	// Description of the auth backend.
	Description string
	// OIDCDiscoveryURL is the OIDC provider discovery URL.
	OIDCDiscoveryURL string
	// OIDCClientID is the OAuth 2.0 client ID.
	OIDCClientID string
	// OIDCClientSecret is the OAuth 2.0 client secret.
	OIDCClientSecret string
	// BoundIssuer is the issuer that must be in the JWT.
	BoundIssuer string
	// JWKSUrl is the URL for the JWKS endpoint (alternative to discovery URL).
	JWKSURL string
	// JWTValidationPubKeys are PEM-encoded public keys for JWT validation.
	JWTValidationPubKeys []string
	// DefaultRole is the default role to use.
	DefaultRole string
	// ProviderConfig holds provider-specific configuration.
	ProviderConfig map[string]interface{}
}

// JWTRoleConfig holds configuration for a JWT role.
type JWTRoleConfig struct {
	// Name is the role name.
	Name string
	// BoundAudiences are the allowed audiences.
	BoundAudiences []string
	// BoundClaims are claims that must be present.
	BoundClaims map[string]interface{}
	// BoundClaimsType is how to interpret bound_claims (string or glob).
	BoundClaimsType string
	// BoundSubject is the required subject claim.
	BoundSubject string
	// ClaimMappings maps JWT claims to token metadata.
	ClaimMappings map[string]string
	// GroupsClaim is the claim containing group membership.
	GroupsClaim string
	// UserClaim is the claim to use as the user identity.
	UserClaim string
	// TokenPolicies are the policies to attach to the token.
	TokenPolicies []string
	// TokenTTL is the TTL of the token.
	TokenTTL string
	// TokenMaxTTL is the maximum TTL of the token.
	TokenMaxTTL string
	// TokenType is the type of token (default, batch, service).
	TokenType string
}

// KubernetesConfig holds configuration for Kubernetes authentication backend.
type KubernetesConfig struct {
	// Path is the mount path for the auth backend.
	Path string
	// Description of the auth backend.
	Description string
	// KubernetesHost is the Kubernetes API server URL.
	KubernetesHost string
	// KubernetesCACert is the PEM-encoded CA certificate for the Kubernetes API.
	KubernetesCACert string
	// TokenReviewerJWT is the service account JWT for token review.
	TokenReviewerJWT string
	// Issuer is the JWT issuer for Kubernetes tokens.
	Issuer string
	// DisableLocalCAJWT disables the use of local CA and JWT.
	DisableLocalCAJWT bool
}

// KubernetesRoleConfig holds configuration for a Kubernetes role.
type KubernetesRoleConfig struct {
	// Name is the role name.
	Name string
	// BoundServiceAccountNames are the allowed service account names.
	BoundServiceAccountNames []string
	// BoundServiceAccountNamespaces are the allowed namespaces.
	BoundServiceAccountNamespaces []string
	// TokenPolicies are the policies to attach to the token.
	TokenPolicies []string
	// TokenTTL is the TTL of the token.
	TokenTTL string
	// TokenMaxTTL is the maximum TTL of the token.
	TokenMaxTTL string
	// Audience is the expected audience for the token.
	Audience string
}

// AppRoleConfig holds configuration for AppRole authentication backend.
type AppRoleConfig struct {
	// Path is the mount path for the auth backend.
	Path string
	// Description of the auth backend.
	Description string
}

// AppRoleRoleConfig holds configuration for an AppRole role.
type AppRoleRoleConfig struct {
	// Name is the role name.
	Name string
	// BindSecretID requires a secret ID for login.
	BindSecretID bool
	// SecretIDBoundCIDRs restricts secret ID usage to these CIDRs.
	SecretIDBoundCIDRs []string
	// SecretIDNumUses limits how many times a secret ID can be used.
	SecretIDNumUses int
	// SecretIDTTL is the TTL of the secret ID.
	SecretIDTTL string
	// TokenPolicies are the policies to attach to the token.
	TokenPolicies []string
	// TokenTTL is the TTL of the token.
	TokenTTL string
	// TokenMaxTTL is the maximum TTL of the token.
	TokenMaxTTL string
	// TokenBoundCIDRs restricts token usage to these CIDRs.
	TokenBoundCIDRs []string
	// TokenNumUses limits how many times a token can be used.
	TokenNumUses int
}

// VersionCompatibility holds version compatibility check results.
type VersionCompatibility struct {
	Version    string
	Compatible bool
	Message    string
	MinVersion string
	MaxVersion string
}

// CheckVersionCompatibility checks if the Vault version is compatible.
func (c *Client) CheckVersionCompatibility(ctx context.Context) (*VersionCompatibility, error) {
	health, err := c.Health(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Vault health: %w", err)
	}

	result := &VersionCompatibility{
		Version:    health.Version,
		MinVersion: SupportedVersionMin,
		MaxVersion: SupportedVersionMax,
	}

	// Parse version (strip any +ent or other suffixes)
	versionStr := health.Version
	if idx := strings.Index(versionStr, "+"); idx != -1 {
		versionStr = versionStr[:idx]
	}

	// Extract version using regex for cases like "1.18.3"
	re := regexp.MustCompile(`^(\d+\.\d+\.\d+)`)
	matches := re.FindStringSubmatch(versionStr)
	if len(matches) < 2 {
		result.Compatible = false
		result.Message = fmt.Sprintf("unable to parse Vault version: %s", health.Version)
		return result, nil
	}
	versionStr = matches[1]

	current, err := version.NewVersion(versionStr)
	if err != nil {
		result.Compatible = false
		result.Message = fmt.Sprintf("invalid version format: %s", versionStr)
		return result, nil //nolint:nilerr // intentional: return result with Compatible=false, not error
	}

	minVer, _ := version.NewVersion(SupportedVersionMin)
	maxVer, _ := version.NewVersion(SupportedVersionMax)

	if current.LessThan(minVer) {
		result.Compatible = false
		result.Message = fmt.Sprintf("Vault version %s is below minimum supported version %s", current, SupportedVersionMin)
		return result, nil
	}

	if current.GreaterThan(maxVer) {
		result.Compatible = false
		result.Message = fmt.Sprintf("Vault version %s is above maximum supported version %s", current, SupportedVersionMax)
		return result, nil
	}

	result.Compatible = true
	result.Message = fmt.Sprintf("Vault version %s is compatible", current)
	c.logger.InfoContext(ctx, "vault version compatible", "version", current.String())
	return result, nil
}

// EnableAuthBackend enables an authentication backend at the given path.
func (c *Client) EnableAuthBackend(ctx context.Context, path string, backendType AuthBackendType, description string) error {
	options := map[string]interface{}{
		"type":        string(backendType),
		"description": description,
	}

	_, err := c.client.Logical().WriteWithContext(ctx, fmt.Sprintf("sys/auth/%s", path), options)
	if err != nil {
		c.logger.ErrorContext(ctx, "failed to enable auth backend",
			"path", path,
			"type", backendType,
			"error", err,
		)
		return fmt.Errorf("vault: failed to enable auth backend at %s: %w", path, err)
	}

	c.logger.InfoContext(ctx, "auth backend enabled", "path", path, "type", backendType)
	return nil
}

// DisableAuthBackend disables an authentication backend at the given path.
func (c *Client) DisableAuthBackend(ctx context.Context, path string) error {
	_, err := c.client.Logical().DeleteWithContext(ctx, fmt.Sprintf("sys/auth/%s", path))
	if err != nil {
		c.logger.ErrorContext(ctx, "failed to disable auth backend", "path", path, "error", err)
		return fmt.Errorf("vault: failed to disable auth backend at %s: %w", path, err)
	}

	c.logger.InfoContext(ctx, "auth backend disabled", "path", path)
	return nil
}

// ListAuthBackends lists all enabled authentication backends.
func (c *Client) ListAuthBackends(ctx context.Context) (map[string]interface{}, error) {
	secret, err := c.client.Logical().ReadWithContext(ctx, "sys/auth")
	if err != nil {
		c.logger.ErrorContext(ctx, "failed to list auth backends", "error", err)
		return nil, fmt.Errorf("vault: failed to list auth backends: %w", err)
	}

	if secret == nil {
		return make(map[string]interface{}), nil
	}

	return secret.Data, nil
}

// ConfigureJWTAuth configures a JWT/OIDC authentication backend.
func (c *Client) ConfigureJWTAuth(ctx context.Context, cfg *JWTConfig) error {
	if cfg == nil {
		return fmt.Errorf("vault: JWT config is required")
	}
	if cfg.Path == "" {
		cfg.Path = "jwt"
	}

	// Enable the auth backend
	if err := c.EnableAuthBackend(ctx, cfg.Path, AuthBackendJWT, cfg.Description); err != nil {
		// Check if already enabled
		if !strings.Contains(err.Error(), "path is already in use") {
			return err
		}
		c.logger.DebugContext(ctx, "JWT auth backend already enabled", "path", cfg.Path)
	}

	// Configure the backend
	configPath := fmt.Sprintf("auth/%s/config", cfg.Path)
	configData := make(map[string]interface{})

	if cfg.OIDCDiscoveryURL != "" {
		configData["oidc_discovery_url"] = cfg.OIDCDiscoveryURL
	}
	if cfg.OIDCClientID != "" {
		configData["oidc_client_id"] = cfg.OIDCClientID
	}
	if cfg.OIDCClientSecret != "" {
		configData["oidc_client_secret"] = cfg.OIDCClientSecret
	}
	if cfg.BoundIssuer != "" {
		configData["bound_issuer"] = cfg.BoundIssuer
	}
	if cfg.JWKSURL != "" {
		configData["jwks_url"] = cfg.JWKSURL
	}
	if len(cfg.JWTValidationPubKeys) > 0 {
		configData["jwt_validation_pubkeys"] = cfg.JWTValidationPubKeys
	}
	if cfg.DefaultRole != "" {
		configData["default_role"] = cfg.DefaultRole
	}
	if cfg.ProviderConfig != nil {
		configData["provider_config"] = cfg.ProviderConfig
	}

	_, err := c.client.Logical().WriteWithContext(ctx, configPath, configData)
	if err != nil {
		c.logger.ErrorContext(ctx, "failed to configure JWT auth", "path", cfg.Path, "error", err)
		return fmt.Errorf("vault: failed to configure JWT auth: %w", err)
	}

	c.logger.InfoContext(ctx, "JWT auth backend configured", "path", cfg.Path)
	return nil
}

// CreateJWTRole creates a role for JWT authentication.
func (c *Client) CreateJWTRole(ctx context.Context, authPath string, cfg *JWTRoleConfig) error {
	if cfg == nil || cfg.Name == "" {
		return fmt.Errorf("vault: JWT role config with name is required")
	}
	if authPath == "" {
		authPath = "jwt"
	}

	rolePath := fmt.Sprintf("auth/%s/role/%s", authPath, cfg.Name)
	roleData := map[string]interface{}{
		"role_type": "jwt",
	}

	if len(cfg.BoundAudiences) > 0 {
		roleData["bound_audiences"] = cfg.BoundAudiences
	}
	if len(cfg.BoundClaims) > 0 {
		roleData["bound_claims"] = cfg.BoundClaims
	}
	if cfg.BoundClaimsType != "" {
		roleData["bound_claims_type"] = cfg.BoundClaimsType
	}
	if cfg.BoundSubject != "" {
		roleData["bound_subject"] = cfg.BoundSubject
	}
	if len(cfg.ClaimMappings) > 0 {
		roleData["claim_mappings"] = cfg.ClaimMappings
	}
	if cfg.GroupsClaim != "" {
		roleData["groups_claim"] = cfg.GroupsClaim
	}
	if cfg.UserClaim != "" {
		roleData["user_claim"] = cfg.UserClaim
	} else {
		roleData["user_claim"] = "sub" // Default to 'sub' claim
	}
	if len(cfg.TokenPolicies) > 0 {
		roleData["token_policies"] = cfg.TokenPolicies
	}
	if cfg.TokenTTL != "" {
		roleData["token_ttl"] = cfg.TokenTTL
	}
	if cfg.TokenMaxTTL != "" {
		roleData["token_max_ttl"] = cfg.TokenMaxTTL
	}
	if cfg.TokenType != "" {
		roleData["token_type"] = cfg.TokenType
	}

	_, err := c.client.Logical().WriteWithContext(ctx, rolePath, roleData)
	if err != nil {
		c.logger.ErrorContext(ctx, "failed to create JWT role",
			"path", authPath,
			"role", cfg.Name,
			"error", err,
		)
		return fmt.Errorf("vault: failed to create JWT role %s: %w", cfg.Name, err)
	}

	c.logger.InfoContext(ctx, "JWT role created", "path", authPath, "role", cfg.Name)
	return nil
}

// ConfigureKubernetesAuth configures a Kubernetes authentication backend.
func (c *Client) ConfigureKubernetesAuth(ctx context.Context, cfg *KubernetesConfig) error {
	if cfg == nil {
		return fmt.Errorf("vault: Kubernetes config is required")
	}
	if cfg.Path == "" {
		cfg.Path = "kubernetes"
	}

	// Enable the auth backend
	if err := c.EnableAuthBackend(ctx, cfg.Path, AuthBackendKubernetes, cfg.Description); err != nil {
		if !strings.Contains(err.Error(), "path is already in use") {
			return err
		}
		c.logger.DebugContext(ctx, "Kubernetes auth backend already enabled", "path", cfg.Path)
	}

	// Configure the backend
	configPath := fmt.Sprintf("auth/%s/config", cfg.Path)
	configData := map[string]interface{}{}

	if cfg.KubernetesHost != "" {
		configData["kubernetes_host"] = cfg.KubernetesHost
	}
	if cfg.KubernetesCACert != "" {
		configData["kubernetes_ca_cert"] = cfg.KubernetesCACert
	}
	if cfg.TokenReviewerJWT != "" {
		configData["token_reviewer_jwt"] = cfg.TokenReviewerJWT
	}
	if cfg.Issuer != "" {
		configData["issuer"] = cfg.Issuer
	}
	if cfg.DisableLocalCAJWT {
		configData["disable_local_ca_jwt"] = true
	}

	_, err := c.client.Logical().WriteWithContext(ctx, configPath, configData)
	if err != nil {
		c.logger.ErrorContext(ctx, "failed to configure Kubernetes auth", "path", cfg.Path, "error", err)
		return fmt.Errorf("vault: failed to configure Kubernetes auth: %w", err)
	}

	c.logger.InfoContext(ctx, "Kubernetes auth backend configured", "path", cfg.Path)
	return nil
}

// CreateKubernetesRole creates a role for Kubernetes authentication.
func (c *Client) CreateKubernetesRole(ctx context.Context, authPath string, cfg *KubernetesRoleConfig) error {
	if cfg == nil || cfg.Name == "" {
		return fmt.Errorf("vault: Kubernetes role config with name is required")
	}
	if authPath == "" {
		authPath = "kubernetes"
	}

	rolePath := fmt.Sprintf("auth/%s/role/%s", authPath, cfg.Name)
	roleData := map[string]interface{}{}

	if len(cfg.BoundServiceAccountNames) > 0 {
		roleData["bound_service_account_names"] = cfg.BoundServiceAccountNames
	}
	if len(cfg.BoundServiceAccountNamespaces) > 0 {
		roleData["bound_service_account_namespaces"] = cfg.BoundServiceAccountNamespaces
	}
	if len(cfg.TokenPolicies) > 0 {
		roleData["token_policies"] = cfg.TokenPolicies
	}
	if cfg.TokenTTL != "" {
		roleData["token_ttl"] = cfg.TokenTTL
	}
	if cfg.TokenMaxTTL != "" {
		roleData["token_max_ttl"] = cfg.TokenMaxTTL
	}
	if cfg.Audience != "" {
		roleData["audience"] = cfg.Audience
	}

	_, err := c.client.Logical().WriteWithContext(ctx, rolePath, roleData)
	if err != nil {
		c.logger.ErrorContext(ctx, "failed to create Kubernetes role",
			"path", authPath,
			"role", cfg.Name,
			"error", err,
		)
		return fmt.Errorf("vault: failed to create Kubernetes role %s: %w", cfg.Name, err)
	}

	c.logger.InfoContext(ctx, "Kubernetes role created", "path", authPath, "role", cfg.Name)
	return nil
}

// ConfigureAppRoleAuth configures an AppRole authentication backend.
func (c *Client) ConfigureAppRoleAuth(ctx context.Context, cfg *AppRoleConfig) error {
	if cfg == nil {
		return fmt.Errorf("vault: AppRole config is required")
	}
	if cfg.Path == "" {
		cfg.Path = "approle"
	}

	// Enable the auth backend
	if err := c.EnableAuthBackend(ctx, cfg.Path, AuthBackendAppRole, cfg.Description); err != nil {
		if !strings.Contains(err.Error(), "path is already in use") {
			return err
		}
		c.logger.DebugContext(ctx, "AppRole auth backend already enabled", "path", cfg.Path)
	}

	c.logger.InfoContext(ctx, "AppRole auth backend configured", "path", cfg.Path)
	return nil
}

// CreateAppRole creates an AppRole for authentication.
func (c *Client) CreateAppRole(ctx context.Context, authPath string, cfg *AppRoleRoleConfig) error {
	if cfg == nil || cfg.Name == "" {
		return fmt.Errorf("vault: AppRole role config with name is required")
	}
	if authPath == "" {
		authPath = "approle"
	}

	rolePath := fmt.Sprintf("auth/%s/role/%s", authPath, cfg.Name)
	roleData := map[string]interface{}{
		"bind_secret_id": cfg.BindSecretID,
	}

	if len(cfg.SecretIDBoundCIDRs) > 0 {
		roleData["secret_id_bound_cidrs"] = cfg.SecretIDBoundCIDRs
	}
	if cfg.SecretIDNumUses > 0 {
		roleData["secret_id_num_uses"] = cfg.SecretIDNumUses
	}
	if cfg.SecretIDTTL != "" {
		roleData["secret_id_ttl"] = cfg.SecretIDTTL
	}
	if len(cfg.TokenPolicies) > 0 {
		roleData["token_policies"] = cfg.TokenPolicies
	}
	if cfg.TokenTTL != "" {
		roleData["token_ttl"] = cfg.TokenTTL
	}
	if cfg.TokenMaxTTL != "" {
		roleData["token_max_ttl"] = cfg.TokenMaxTTL
	}
	if len(cfg.TokenBoundCIDRs) > 0 {
		roleData["token_bound_cidrs"] = cfg.TokenBoundCIDRs
	}
	if cfg.TokenNumUses > 0 {
		roleData["token_num_uses"] = cfg.TokenNumUses
	}

	_, err := c.client.Logical().WriteWithContext(ctx, rolePath, roleData)
	if err != nil {
		c.logger.ErrorContext(ctx, "failed to create AppRole",
			"path", authPath,
			"role", cfg.Name,
			"error", err,
		)
		return fmt.Errorf("vault: failed to create AppRole %s: %w", cfg.Name, err)
	}

	c.logger.InfoContext(ctx, "AppRole created", "path", authPath, "role", cfg.Name)
	return nil
}

// GetAppRoleRoleID retrieves the role ID for an AppRole.
func (c *Client) GetAppRoleRoleID(ctx context.Context, authPath, roleName string) (string, error) {
	if authPath == "" {
		authPath = "approle"
	}

	path := fmt.Sprintf("auth/%s/role/%s/role-id", authPath, roleName)
	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return "", fmt.Errorf("vault: failed to get role ID for %s: %w", roleName, err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("vault: role %s not found", roleName)
	}

	roleID, ok := secret.Data["role_id"].(string)
	if !ok {
		return "", fmt.Errorf("vault: invalid role_id format for role %s", roleName)
	}

	return roleID, nil
}

// GenerateAppRoleSecretID generates a secret ID for an AppRole.
func (c *Client) GenerateAppRoleSecretID(ctx context.Context, authPath, roleName string, metadata map[string]string) (string, string, error) {
	if authPath == "" {
		authPath = "approle"
	}

	path := fmt.Sprintf("auth/%s/role/%s/secret-id", authPath, roleName)
	data := map[string]interface{}{}
	if len(metadata) > 0 {
		// Vault expects metadata as a JSON string, not a map
		metadataJSON, err := json.Marshal(metadata)
		if err != nil {
			return "", "", fmt.Errorf("vault: failed to marshal metadata: %w", err)
		}
		data["metadata"] = string(metadataJSON)
	}

	secret, err := c.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return "", "", fmt.Errorf("vault: failed to generate secret ID for %s: %w", roleName, err)
	}

	if secret == nil || secret.Data == nil {
		return "", "", fmt.Errorf("vault: failed to generate secret ID for role %s", roleName)
	}

	secretID, ok := secret.Data["secret_id"].(string)
	if !ok {
		return "", "", fmt.Errorf("vault: invalid secret_id format for role %s", roleName)
	}

	secretIDAccessor, _ := secret.Data["secret_id_accessor"].(string)

	return secretID, secretIDAccessor, nil
}

// LoginWithAppRole authenticates using AppRole and returns a token.
func (c *Client) LoginWithAppRole(ctx context.Context, authPath, roleID, secretID string) (string, error) {
	if authPath == "" {
		authPath = "approle"
	}

	path := fmt.Sprintf("auth/%s/login", authPath)
	data := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}

	secret, err := c.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return "", fmt.Errorf("vault: AppRole login failed: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return "", fmt.Errorf("vault: AppRole login returned no auth info")
	}

	return secret.Auth.ClientToken, nil
}

// LoginWithJWT authenticates using a JWT and returns a token.
func (c *Client) LoginWithJWT(ctx context.Context, authPath, role, jwt string) (string, error) {
	if authPath == "" {
		authPath = "jwt"
	}

	path := fmt.Sprintf("auth/%s/login", authPath)
	data := map[string]interface{}{
		"jwt": jwt,
	}
	if role != "" {
		data["role"] = role
	}

	secret, err := c.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return "", fmt.Errorf("vault: JWT login failed: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return "", fmt.Errorf("vault: JWT login returned no auth info")
	}

	return secret.Auth.ClientToken, nil
}

// LoginWithKubernetes authenticates using a Kubernetes service account token.
func (c *Client) LoginWithKubernetes(ctx context.Context, authPath, role, jwt string) (string, error) {
	if authPath == "" {
		authPath = "kubernetes"
	}

	path := fmt.Sprintf("auth/%s/login", authPath)
	data := map[string]interface{}{
		"role": role,
		"jwt":  jwt,
	}

	secret, err := c.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return "", fmt.Errorf("vault: Kubernetes login failed: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return "", fmt.Errorf("vault: Kubernetes login returned no auth info")
	}

	return secret.Auth.ClientToken, nil
}

// CreatePolicy creates or updates a Vault policy.
func (c *Client) CreatePolicy(ctx context.Context, name, rules string) error {
	err := c.client.Sys().PutPolicyWithContext(ctx, name, rules)
	if err != nil {
		c.logger.ErrorContext(ctx, "failed to create policy", "name", name, "error", err)
		return fmt.Errorf("vault: failed to create policy %s: %w", name, err)
	}

	c.logger.InfoContext(ctx, "policy created", "name", name)
	return nil
}

// DeletePolicy deletes a Vault policy.
func (c *Client) DeletePolicy(ctx context.Context, name string) error {
	err := c.client.Sys().DeletePolicyWithContext(ctx, name)
	if err != nil {
		c.logger.ErrorContext(ctx, "failed to delete policy", "name", name, "error", err)
		return fmt.Errorf("vault: failed to delete policy %s: %w", name, err)
	}

	c.logger.InfoContext(ctx, "policy deleted", "name", name)
	return nil
}

// ListPolicies lists all Vault policies.
func (c *Client) ListPolicies(ctx context.Context) ([]string, error) {
	policies, err := c.client.Sys().ListPoliciesWithContext(ctx)
	if err != nil {
		c.logger.ErrorContext(ctx, "failed to list policies", "error", err)
		return nil, fmt.Errorf("vault: failed to list policies: %w", err)
	}

	return policies, nil
}

// parseVersion extracts major, minor, patch from a version string.
func parseVersion(v string) (int, int, int, error) {
	parts := strings.Split(v, ".")
	if len(parts) < 3 {
		return 0, 0, 0, fmt.Errorf("invalid version format: %s", v)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid major version: %w", err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid minor version: %w", err)
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid patch version: %w", err)
	}

	return major, minor, patch, nil
}
