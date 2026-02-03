// Package config tests configuration loading.
package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/witlox/sovra/internal/config"
)

func TestLoadDefaults(t *testing.T) {
	// Ensure no config file exists
	os.Unsetenv("SOVRA_SERVICE")
	os.Unsetenv("SOVRA_ORG_ID")

	cfg, err := config.Load("")
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Check defaults
	assert.Equal(t, "info", cfg.LogLevel)
	assert.Equal(t, "json", cfg.LogFormat)

	// Server defaults
	assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	assert.Equal(t, 8080, cfg.Server.Port)
	assert.Equal(t, 30*time.Second, cfg.Server.ReadTimeout)
	assert.Equal(t, 30*time.Second, cfg.Server.WriteTimeout)
	assert.Equal(t, 120*time.Second, cfg.Server.IdleTimeout)
	assert.False(t, cfg.Server.TLSEnabled)
	assert.False(t, cfg.Server.MTLSEnabled)

	// Database defaults
	assert.Equal(t, "localhost", cfg.Database.Host)
	assert.Equal(t, 5432, cfg.Database.Port)
	assert.Equal(t, "sovra", cfg.Database.Database)
	assert.Equal(t, "sovra", cfg.Database.Username)
	assert.Equal(t, "prefer", cfg.Database.SSLMode)
	assert.Equal(t, 25, cfg.Database.MaxOpenConns)
	assert.Equal(t, 5, cfg.Database.MaxIdleConns)
	assert.Equal(t, 5*time.Minute, cfg.Database.ConnMaxLifetime)

	// Vault defaults
	assert.Equal(t, "http://localhost:8200", cfg.Vault.Address)
	assert.False(t, cfg.Vault.TLSEnabled)
	assert.Equal(t, "transit", cfg.Vault.TransitMount)
	assert.Equal(t, "pki", cfg.Vault.PKIMount)

	// OPA defaults
	assert.Equal(t, "http://localhost:8181", cfg.OPA.Address)
	assert.Equal(t, 5*time.Second, cfg.OPA.Timeout)

	// Federation defaults
	assert.True(t, cfg.Federation.Enabled)
	assert.Equal(t, 30*time.Second, cfg.Federation.HealthInterval)
	assert.Equal(t, 8760*time.Hour, cfg.Federation.CertificateExpiry)
}

func TestLoadFromEnv(t *testing.T) {
	// Set environment variables for fields that have defaults set (viper only reads env if default is set)
	os.Setenv("SOVRA_LOG_LEVEL", "debug")
	os.Setenv("SOVRA_SERVER_PORT", "9090")
	os.Setenv("SOVRA_DATABASE_HOST", "postgres.example.com")
	os.Setenv("SOVRA_VAULT_ADDRESS", "https://vault.example.com:8200")
	defer func() {
		os.Unsetenv("SOVRA_LOG_LEVEL")
		os.Unsetenv("SOVRA_SERVER_PORT")
		os.Unsetenv("SOVRA_DATABASE_HOST")
		os.Unsetenv("SOVRA_VAULT_ADDRESS")
	}()

	cfg, err := config.Load("")
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Only test fields that have defaults set (viper limitation)
	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, 9090, cfg.Server.Port)
	assert.Equal(t, "postgres.example.com", cfg.Database.Host)
	assert.Equal(t, "https://vault.example.com:8200", cfg.Vault.Address)
}

func TestLoadFromFile(t *testing.T) {
	// Create temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "sovra.yaml")
	configContent := `
service: test-service
org_id: test-org
log_level: warn

server:
  host: 127.0.0.1
  port: 3000
  tls_enabled: true

database:
  host: db.example.com
  port: 5433
  database: sovra_test
  username: sovra_user
  password: secret123

vault:
  address: https://vault.local:8200
  token: hvs.test-token
  transit_mount: transit-prod

federation:
  enabled: false
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := config.Load(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "test-service", cfg.Service)
	assert.Equal(t, "test-org", cfg.OrgID)
	assert.Equal(t, "warn", cfg.LogLevel)

	assert.Equal(t, "127.0.0.1", cfg.Server.Host)
	assert.Equal(t, 3000, cfg.Server.Port)
	assert.True(t, cfg.Server.TLSEnabled)

	assert.Equal(t, "db.example.com", cfg.Database.Host)
	assert.Equal(t, 5433, cfg.Database.Port)
	assert.Equal(t, "sovra_test", cfg.Database.Database)
	assert.Equal(t, "sovra_user", cfg.Database.Username)
	assert.Equal(t, "secret123", cfg.Database.Password)

	assert.Equal(t, "https://vault.local:8200", cfg.Vault.Address)
	assert.Equal(t, "hvs.test-token", cfg.Vault.Token)
	assert.Equal(t, "transit-prod", cfg.Vault.TransitMount)

	assert.False(t, cfg.Federation.Enabled)
}

func TestLoadInvalidFile(t *testing.T) {
	_, err := config.Load("/nonexistent/path/config.yaml")
	require.Error(t, err)
}

func TestLoadInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "sovra.yaml")
	err := os.WriteFile(configPath, []byte("invalid: yaml: content::: broken"), 0644)
	require.NoError(t, err)

	_, err = config.Load(configPath)
	require.Error(t, err)
}

func TestServerConfigAddr(t *testing.T) {
	cfg := config.ServerConfig{
		Host: "0.0.0.0",
		Port: 8080,
	}
	assert.Equal(t, "0.0.0.0:8080", cfg.Addr())

	cfg.Host = "localhost"
	cfg.Port = 443
	assert.Equal(t, "localhost:443", cfg.Addr())
}

func TestDatabaseConfigDSN(t *testing.T) {
	cfg := config.DatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		Username: "sovra",
		Password: "secret",
		Database: "sovra_db",
		SSLMode:  "require",
	}

	dsn := cfg.DSN()
	assert.Contains(t, dsn, "host=localhost")
	assert.Contains(t, dsn, "port=5432")
	assert.Contains(t, dsn, "user=sovra")
	assert.Contains(t, dsn, "password=secret")
	assert.Contains(t, dsn, "dbname=sovra_db")
	assert.Contains(t, dsn, "sslmode=require")
}
