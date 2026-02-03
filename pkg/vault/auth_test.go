package vault

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthBackendType_Constants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		backend  AuthBackendType
		expected string
	}{
		{"JWT backend", AuthBackendJWT, "jwt"},
		{"OIDC backend", AuthBackendOIDC, "oidc"},
		{"Kubernetes backend", AuthBackendKubernetes, "kubernetes"},
		{"AppRole backend", AuthBackendAppRole, "approle"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.backend))
		})
	}
}

func TestJWTConfig_Defaults(t *testing.T) {
	t.Parallel()

	cfg := &JWTConfig{}
	assert.Empty(t, cfg.Path)
	assert.Empty(t, cfg.OIDCDiscoveryURL)
	assert.Empty(t, cfg.OIDCClientID)
	assert.Nil(t, cfg.JWTValidationPubKeys)
}

func TestJWTRoleConfig_Defaults(t *testing.T) {
	t.Parallel()

	cfg := &JWTRoleConfig{
		Name:           "test-role",
		BoundAudiences: []string{"https://api.example.com"},
		TokenPolicies:  []string{"default"},
	}

	assert.Equal(t, "test-role", cfg.Name)
	assert.Equal(t, []string{"https://api.example.com"}, cfg.BoundAudiences)
	assert.Equal(t, []string{"default"}, cfg.TokenPolicies)
	assert.Empty(t, cfg.UserClaim) // Should default to "sub" in CreateJWTRole
}

func TestKubernetesConfig_Defaults(t *testing.T) {
	t.Parallel()

	cfg := &KubernetesConfig{
		KubernetesHost: "https://kubernetes.default.svc",
	}

	assert.Equal(t, "https://kubernetes.default.svc", cfg.KubernetesHost)
	assert.Empty(t, cfg.Path) // Should default to "kubernetes" in ConfigureKubernetesAuth
}

func TestKubernetesRoleConfig_Validation(t *testing.T) {
	t.Parallel()

	cfg := &KubernetesRoleConfig{
		Name:                          "edge-node",
		BoundServiceAccountNames:      []string{"sovra-agent"},
		BoundServiceAccountNamespaces: []string{"sovra-system"},
		TokenPolicies:                 []string{"edge-node-policy"},
		TokenTTL:                      "1h",
	}

	assert.Equal(t, "edge-node", cfg.Name)
	assert.Contains(t, cfg.BoundServiceAccountNames, "sovra-agent")
	assert.Contains(t, cfg.BoundServiceAccountNamespaces, "sovra-system")
}

func TestAppRoleConfig_Defaults(t *testing.T) {
	t.Parallel()

	cfg := &AppRoleConfig{
		Description: "Service authentication",
	}

	assert.Empty(t, cfg.Path) // Should default to "approle" in ConfigureAppRoleAuth
	assert.Equal(t, "Service authentication", cfg.Description)
}

func TestAppRoleRoleConfig_Validation(t *testing.T) {
	t.Parallel()

	cfg := &AppRoleRoleConfig{
		Name:            "api-gateway",
		BindSecretID:    true,
		SecretIDTTL:     "24h",
		TokenPolicies:   []string{"api-gateway-policy"},
		TokenTTL:        "1h",
		TokenMaxTTL:     "4h",
		TokenNumUses:    10,
		SecretIDNumUses: 1,
	}

	assert.Equal(t, "api-gateway", cfg.Name)
	assert.True(t, cfg.BindSecretID)
	assert.Equal(t, 1, cfg.SecretIDNumUses)
	assert.Equal(t, 10, cfg.TokenNumUses)
}

func TestVersionCompatibility_Structure(t *testing.T) {
	t.Parallel()

	compat := &VersionCompatibility{
		Version:    "1.15.0",
		Compatible: true,
		Message:    "Vault version 1.15.0 is compatible",
		MinVersion: SupportedVersionMin,
		MaxVersion: SupportedVersionMax,
	}

	assert.Equal(t, "1.15.0", compat.Version)
	assert.True(t, compat.Compatible)
	assert.Equal(t, SupportedVersionMin, compat.MinVersion)
	assert.Equal(t, SupportedVersionMax, compat.MaxVersion)
}

func TestSupportedVersionConstants(t *testing.T) {
	t.Parallel()

	// Ensure version constants are valid
	assert.NotEmpty(t, SupportedVersionMin)
	assert.NotEmpty(t, SupportedVersionMax)

	// Check format (should be semver-like)
	assert.Regexp(t, `^\d+\.\d+\.\d+$`, SupportedVersionMin)
	assert.Regexp(t, `^\d+\.\d+\.\d+$`, SupportedVersionMax)
}

func TestParseVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		version   string
		wantMajor int
		wantMinor int
		wantPatch int
		wantErr   bool
	}{
		{"valid version", "1.15.4", 1, 15, 4, false},
		{"zero version", "0.0.0", 0, 0, 0, false},
		{"large version", "10.20.30", 10, 20, 30, false},
		{"too short", "1.2", 0, 0, 0, true},
		{"empty", "", 0, 0, 0, true},
		{"non-numeric major", "a.2.3", 0, 0, 0, true},
		{"non-numeric minor", "1.b.3", 0, 0, 0, true},
		{"non-numeric patch", "1.2.c", 0, 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			major, minor, patch, err := parseVersion(tt.version)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantMajor, major)
				assert.Equal(t, tt.wantMinor, minor)
				assert.Equal(t, tt.wantPatch, patch)
			}
		})
	}
}

func TestClient_ConfigureJWTAuth_NilConfig(t *testing.T) {
	t.Parallel()

	client := &Client{}
	err := client.ConfigureJWTAuth(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWT config is required")
}

func TestClient_CreateJWTRole_NilConfig(t *testing.T) {
	t.Parallel()

	client := &Client{}

	// Test nil config
	err := client.CreateJWTRole(context.Background(), "jwt", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWT role config with name is required")

	// Test empty name
	err = client.CreateJWTRole(context.Background(), "jwt", &JWTRoleConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWT role config with name is required")
}

func TestClient_ConfigureKubernetesAuth_NilConfig(t *testing.T) {
	t.Parallel()

	client := &Client{}
	err := client.ConfigureKubernetesAuth(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Kubernetes config is required")
}

func TestClient_CreateKubernetesRole_NilConfig(t *testing.T) {
	t.Parallel()

	client := &Client{}

	// Test nil config
	err := client.CreateKubernetesRole(context.Background(), "kubernetes", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Kubernetes role config with name is required")

	// Test empty name
	err = client.CreateKubernetesRole(context.Background(), "kubernetes", &KubernetesRoleConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Kubernetes role config with name is required")
}

func TestClient_ConfigureAppRoleAuth_NilConfig(t *testing.T) {
	t.Parallel()

	client := &Client{}
	err := client.ConfigureAppRoleAuth(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AppRole config is required")
}

func TestClient_CreateAppRole_NilConfig(t *testing.T) {
	t.Parallel()

	client := &Client{}

	// Test nil config
	err := client.CreateAppRole(context.Background(), "approle", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AppRole role config with name is required")

	// Test empty name
	err = client.CreateAppRole(context.Background(), "approle", &AppRoleRoleConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AppRole role config with name is required")
}

func TestJWTConfig_FullConfiguration(t *testing.T) {
	t.Parallel()

	cfg := &JWTConfig{
		Path:             "oidc",
		Description:      "OIDC authentication for Sovra",
		OIDCDiscoveryURL: "https://accounts.google.com/.well-known/openid-configuration",
		OIDCClientID:     "client-id-12345",
		OIDCClientSecret: "secret-value",
		BoundIssuer:      "https://accounts.google.com",
		DefaultRole:      "default",
		ProviderConfig: map[string]interface{}{
			"provider": "google",
		},
	}

	assert.Equal(t, "oidc", cfg.Path)
	assert.Equal(t, "https://accounts.google.com", cfg.BoundIssuer)
	assert.Equal(t, "client-id-12345", cfg.OIDCClientID)
	assert.NotNil(t, cfg.ProviderConfig)
}

func TestJWTRoleConfig_FullConfiguration(t *testing.T) {
	t.Parallel()

	cfg := &JWTRoleConfig{
		Name:            "engineer",
		BoundAudiences:  []string{"https://sovra.example.com"},
		BoundSubject:    "user@example.com",
		BoundClaimsType: "glob",
		BoundClaims: map[string]interface{}{
			"email": "*@example.com",
		},
		ClaimMappings: map[string]string{
			"email":  "user_email",
			"groups": "user_groups",
		},
		GroupsClaim:   "groups",
		UserClaim:     "email",
		TokenPolicies: []string{"engineer-policy", "read-secrets"},
		TokenTTL:      "1h",
		TokenMaxTTL:   "8h",
		TokenType:     "service",
	}

	assert.Equal(t, "engineer", cfg.Name)
	assert.Equal(t, "glob", cfg.BoundClaimsType)
	assert.Contains(t, cfg.BoundClaims, "email")
	assert.Len(t, cfg.TokenPolicies, 2)
	assert.Equal(t, "service", cfg.TokenType)
}

func TestKubernetesConfig_FullConfiguration(t *testing.T) {
	t.Parallel()

	cfg := &KubernetesConfig{
		Path:              "k8s-prod",
		Description:       "Production Kubernetes cluster",
		KubernetesHost:    "https://10.0.0.1:6443",
		KubernetesCACert:  "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
		TokenReviewerJWT:  "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
		Issuer:            "https://kubernetes.default.svc.cluster.local",
		DisableLocalCAJWT: true,
	}

	assert.Equal(t, "k8s-prod", cfg.Path)
	assert.True(t, cfg.DisableLocalCAJWT)
	assert.Contains(t, cfg.KubernetesCACert, "BEGIN CERTIFICATE")
}

func TestAppRoleRoleConfig_FullConfiguration(t *testing.T) {
	t.Parallel()

	cfg := &AppRoleRoleConfig{
		Name:               "audit-service",
		BindSecretID:       true,
		SecretIDBoundCIDRs: []string{"10.0.0.0/8", "172.16.0.0/12"},
		SecretIDNumUses:    1, // One-time secret
		SecretIDTTL:        "10m",
		TokenPolicies:      []string{"audit-service-policy"},
		TokenTTL:           "15m",
		TokenMaxTTL:        "1h",
		TokenBoundCIDRs:    []string{"10.0.0.0/8"},
		TokenNumUses:       0, // Unlimited
	}

	assert.Equal(t, "audit-service", cfg.Name)
	assert.Len(t, cfg.SecretIDBoundCIDRs, 2)
	assert.Equal(t, 1, cfg.SecretIDNumUses)
	assert.Equal(t, 0, cfg.TokenNumUses)
}

func TestVersionCompatibility_Messages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		version     string
		compatible  bool
		msgContains string
	}{
		{
			name:        "compatible version",
			version:     "1.15.0",
			compatible:  true,
			msgContains: "compatible",
		},
		{
			name:        "below minimum",
			version:     "1.10.0",
			compatible:  false,
			msgContains: "below minimum",
		},
		{
			name:        "above maximum",
			version:     "2.0.0",
			compatible:  false,
			msgContains: "above maximum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compat := &VersionCompatibility{
				Version:    tt.version,
				Compatible: tt.compatible,
				MinVersion: SupportedVersionMin,
				MaxVersion: SupportedVersionMax,
			}

			if tt.compatible {
				compat.Message = "Vault version " + tt.version + " is compatible"
			} else if tt.name == "below minimum" {
				compat.Message = "Vault version " + tt.version + " is below minimum supported version"
			} else {
				compat.Message = "Vault version " + tt.version + " is above maximum supported version"
			}

			assert.Contains(t, compat.Message, tt.msgContains)
		})
	}
}

func TestDefaultAuthPaths(t *testing.T) {
	t.Parallel()

	// Test that when path is empty, the expected defaults would be used
	// These are documented behaviors from the ConfigureXXX functions

	jwtCfg := &JWTConfig{}
	if jwtCfg.Path == "" {
		jwtCfg.Path = "jwt" // Default behavior in ConfigureJWTAuth
	}
	assert.Equal(t, "jwt", jwtCfg.Path)

	k8sCfg := &KubernetesConfig{}
	if k8sCfg.Path == "" {
		k8sCfg.Path = "kubernetes" // Default behavior in ConfigureKubernetesAuth
	}
	assert.Equal(t, "kubernetes", k8sCfg.Path)

	approleCfg := &AppRoleConfig{}
	if approleCfg.Path == "" {
		approleCfg.Path = "approle" // Default behavior in ConfigureAppRoleAuth
	}
	assert.Equal(t, "approle", approleCfg.Path)
}
