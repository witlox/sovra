// Package vault provides a client for HashiCorp Vault operations.
package vault

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/hashicorp/vault/api"
)

// Client wraps the HashiCorp Vault API client.
type Client struct {
	client *api.Client
	logger *slog.Logger
}

// Config holds configuration for the Vault client.
type Config struct {
	Address   string
	Token     string
	Namespace string
	TLSConfig *TLSConfig
	Timeout   time.Duration
}

// TLSConfig holds TLS configuration for Vault connection.
type TLSConfig struct {
	CACert        string
	CAPath        string
	ClientCert    string
	ClientKey     string
	TLSServerName string
	Insecure      bool
}

// HealthStatus represents the health status of Vault.
type HealthStatus struct {
	Initialized bool
	Sealed      bool
	Standby     bool
	Version     string
	ClusterName string
	ClusterID   string
}

// New creates a new Vault client with the given configuration.
func New(cfg *Config, logger *slog.Logger) (*Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("vault: config is required")
	}
	if cfg.Address == "" {
		return nil, fmt.Errorf("vault: address is required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	vaultCfg := api.DefaultConfig()
	vaultCfg.Address = cfg.Address

	if cfg.Timeout > 0 {
		vaultCfg.Timeout = cfg.Timeout
	}

	if cfg.TLSConfig != nil {
		tlsCfg := &api.TLSConfig{
			CACert:        cfg.TLSConfig.CACert,
			CAPath:        cfg.TLSConfig.CAPath,
			ClientCert:    cfg.TLSConfig.ClientCert,
			ClientKey:     cfg.TLSConfig.ClientKey,
			TLSServerName: cfg.TLSConfig.TLSServerName,
			Insecure:      cfg.TLSConfig.Insecure,
		}
		if err := vaultCfg.ConfigureTLS(tlsCfg); err != nil {
			return nil, fmt.Errorf("vault: failed to configure TLS: %w", err)
		}
	}

	client, err := api.NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("vault: failed to create client: %w", err)
	}

	if cfg.Token != "" {
		client.SetToken(cfg.Token)
	}

	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}

	logger.InfoContext(context.Background(), "vault client created", "address", cfg.Address)

	return &Client{
		client: client,
		logger: logger,
	}, nil
}

// SetToken sets the authentication token for the client.
func (c *Client) SetToken(token string) {
	c.client.SetToken(token)
}

// SetNamespace sets the namespace for the client.
func (c *Client) SetNamespace(namespace string) {
	c.client.SetNamespace(namespace)
}

// Health checks the health status of the Vault server.
func (c *Client) Health(ctx context.Context) (*HealthStatus, error) {
	health, err := c.client.Sys().HealthWithContext(ctx)
	if err != nil {
		c.logger.ErrorContext(ctx, "failed to get vault health", "error", err)
		return nil, fmt.Errorf("vault: health check failed: %w", err)
	}

	status := &HealthStatus{
		Initialized: health.Initialized,
		Sealed:      health.Sealed,
		Standby:     health.Standby,
		Version:     health.Version,
		ClusterName: health.ClusterName,
		ClusterID:   health.ClusterID,
	}

	c.logger.DebugContext(ctx, "vault health check",
		"initialized", status.Initialized,
		"sealed", status.Sealed,
		"version", status.Version,
	)

	return status, nil
}

// IsSealed returns true if the Vault is sealed.
func (c *Client) IsSealed(ctx context.Context) (bool, error) {
	status, err := c.Health(ctx)
	if err != nil {
		return true, err
	}
	return status.Sealed, nil
}

// IsInitialized returns true if the Vault is initialized.
func (c *Client) IsInitialized(ctx context.Context) (bool, error) {
	status, err := c.Health(ctx)
	if err != nil {
		return false, err
	}
	return status.Initialized, nil
}

// EnableSecretsEngine enables a secrets engine at the given path.
func (c *Client) EnableSecretsEngine(ctx context.Context, path, engineType string, options map[string]interface{}) error {
	input := &api.MountInput{
		Type:    engineType,
		Options: make(map[string]string),
	}

	if options != nil {
		if desc, ok := options["description"].(string); ok {
			input.Description = desc
		}
		if config, ok := options["config"].(map[string]interface{}); ok {
			mountConfig := api.MountConfigInput{}
			if maxLease, ok := config["max_lease_ttl"].(string); ok {
				mountConfig.MaxLeaseTTL = maxLease
			}
			if defaultLease, ok := config["default_lease_ttl"].(string); ok {
				mountConfig.DefaultLeaseTTL = defaultLease
			}
			input.Config = mountConfig
		}
	}

	if err := c.client.Sys().MountWithContext(ctx, path, input); err != nil {
		c.logger.ErrorContext(ctx, "failed to enable secrets engine",
			"path", path,
			"type", engineType,
			"error", err,
		)
		return fmt.Errorf("vault: failed to enable secrets engine at %s: %w", path, err)
	}

	c.logger.InfoContext(ctx, "secrets engine enabled", "path", path, "type", engineType)
	return nil
}

// DisableSecretsEngine disables a secrets engine at the given path.
func (c *Client) DisableSecretsEngine(ctx context.Context, path string) error {
	if err := c.client.Sys().UnmountWithContext(ctx, path); err != nil {
		c.logger.ErrorContext(ctx, "failed to disable secrets engine", "path", path, "error", err)
		return fmt.Errorf("vault: failed to disable secrets engine at %s: %w", path, err)
	}

	c.logger.InfoContext(ctx, "secrets engine disabled", "path", path)
	return nil
}

// ListSecretsEngines lists all enabled secrets engines.
func (c *Client) ListSecretsEngines(ctx context.Context) (map[string]*api.MountOutput, error) {
	mounts, err := c.client.Sys().ListMountsWithContext(ctx)
	if err != nil {
		c.logger.ErrorContext(ctx, "failed to list secrets engines", "error", err)
		return nil, fmt.Errorf("vault: failed to list secrets engines: %w", err)
	}
	return mounts, nil
}

// Raw returns the underlying Vault API client for advanced operations.
func (c *Client) Raw() *api.Client {
	return c.client
}
