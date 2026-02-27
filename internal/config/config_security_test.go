package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultDatabaseSSLMode(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Database.SSLMode != "require" {
		t.Fatalf("default database.ssl_mode = %q, want %q", cfg.Database.SSLMode, "require")
	}
}

func TestOIDCSecretRejectsConfigFile(t *testing.T) {
	// Create a temp config file with OIDC secret set
	dir := t.TempDir()
	configFile := filepath.Join(dir, "sovra.yaml")
	if err := os.WriteFile(configFile, []byte(`
admin:
  idp_client_secret: "secret-from-file"
  idp_issuer_url: "https://idp.example.com"
`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Unset the env var so validation fails
	t.Setenv("SOVRA_ADMIN_IDP_CLIENT_SECRET", "")
	os.Unsetenv("SOVRA_ADMIN_IDP_CLIENT_SECRET")

	_, err := Load(configFile)
	if err == nil {
		t.Fatal("Load should reject OIDC secret from config file when env var is not set")
	}
	if !contains(err.Error(), "environment variable") {
		t.Fatalf("error should mention environment variable, got: %v", err)
	}
}

func TestOIDCSecretAcceptsEnvVar(t *testing.T) {
	// Create a temp config file with OIDC secret set
	dir := t.TempDir()
	configFile := filepath.Join(dir, "sovra.yaml")
	if err := os.WriteFile(configFile, []byte(`
admin:
  idp_client_secret: "will-be-overridden"
  idp_issuer_url: "https://idp.example.com"
`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Set the env var
	t.Setenv("SOVRA_ADMIN_IDP_CLIENT_SECRET", "secret-from-env")

	cfg, err := Load(configFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Admin.IDPOIDCSecret != "secret-from-env" {
		t.Fatalf("IDPOIDCSecret = %q, want %q", cfg.Admin.IDPOIDCSecret, "secret-from-env")
	}
}

func TestDSNContainsSSLMode(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	dsn := cfg.Database.DSN()
	if !contains(dsn, "sslmode=require") {
		t.Fatalf("DSN should contain sslmode=require, got: %s", dsn)
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
