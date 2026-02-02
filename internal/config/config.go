// Package config handles configuration loading from environment and files.
package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for Sovra services.
type Config struct {
	// Service identification
	Service   string `mapstructure:"service"`
	OrgID     string `mapstructure:"org_id"`
	LogLevel  string `mapstructure:"log_level"`
	LogFormat string `mapstructure:"log_format"`

	// Server configuration
	Server ServerConfig `mapstructure:"server"`

	// Database configuration
	Database DatabaseConfig `mapstructure:"database"`

	// Vault configuration
	Vault VaultConfig `mapstructure:"vault"`

	// OPA configuration
	OPA OPAConfig `mapstructure:"opa"`

	// Federation configuration
	Federation FederationConfig `mapstructure:"federation"`
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`

	// TLS configuration
	TLSEnabled  bool   `mapstructure:"tls_enabled"`
	TLSCertFile string `mapstructure:"tls_cert_file"`
	TLSKeyFile  string `mapstructure:"tls_key_file"`
	MTLSEnabled bool   `mapstructure:"mtls_enabled"`
	TLSCAFile   string `mapstructure:"tls_ca_file"`
}

// DatabaseConfig holds PostgreSQL configuration.
type DatabaseConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	Database        string        `mapstructure:"database"`
	Username        string        `mapstructure:"username"`
	Password        string        `mapstructure:"password"`
	SSLMode         string        `mapstructure:"ssl_mode"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

// VaultConfig holds HashiCorp Vault configuration.
type VaultConfig struct {
	Address     string `mapstructure:"address"`
	Token       string `mapstructure:"token"`
	Namespace   string `mapstructure:"namespace"`
	TLSEnabled  bool   `mapstructure:"tls_enabled"`
	TLSCAFile   string `mapstructure:"tls_ca_file"`
	TLSCertFile string `mapstructure:"tls_cert_file"`
	TLSKeyFile  string `mapstructure:"tls_key_file"`

	// Engine mount paths
	TransitMount string `mapstructure:"transit_mount"`
	PKIMount     string `mapstructure:"pki_mount"`
}

// OPAConfig holds Open Policy Agent configuration.
type OPAConfig struct {
	Address string        `mapstructure:"address"`
	Timeout time.Duration `mapstructure:"timeout"`
}

// FederationConfig holds federation-related configuration.
type FederationConfig struct {
	Enabled           bool          `mapstructure:"enabled"`
	HealthInterval    time.Duration `mapstructure:"health_interval"`
	CertificateExpiry time.Duration `mapstructure:"certificate_expiry"`
}

// Load loads configuration from environment variables and config file.
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Environment variables
	v.SetEnvPrefix("SOVRA")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Config file
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("sovra")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("/etc/sovra")
		v.AddConfigPath("$HOME/.sovra")
	}

	// Read config file (optional)
	if err := v.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundError) {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
		// Config file not found is OK, use env vars and defaults
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// setDefaults sets default configuration values.
func setDefaults(v *viper.Viper) {
	// Service defaults
	v.SetDefault("log_level", "info")
	v.SetDefault("log_format", "json")

	// Server defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", 30*time.Second)
	v.SetDefault("server.write_timeout", 30*time.Second)
	v.SetDefault("server.idle_timeout", 120*time.Second)
	v.SetDefault("server.tls_enabled", false)
	v.SetDefault("server.mtls_enabled", false)

	// Database defaults
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.database", "sovra")
	v.SetDefault("database.username", "sovra")
	v.SetDefault("database.ssl_mode", "prefer")
	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 5)
	v.SetDefault("database.conn_max_lifetime", 5*time.Minute)

	// Vault defaults
	v.SetDefault("vault.address", "http://localhost:8200")
	v.SetDefault("vault.tls_enabled", false)
	v.SetDefault("vault.transit_mount", "transit")
	v.SetDefault("vault.pki_mount", "pki")

	// OPA defaults
	v.SetDefault("opa.address", "http://localhost:8181")
	v.SetDefault("opa.timeout", 5*time.Second)

	// Federation defaults
	v.SetDefault("federation.enabled", true)
	v.SetDefault("federation.health_interval", 30*time.Second)
	v.SetDefault("federation.certificate_expiry", 8760*time.Hour) // 1 year
}

// Addr returns the server address.
func (c *ServerConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// DSN returns the PostgreSQL connection string.
func (c *DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.Username, c.Password, c.Database, c.SSLMode,
	)
}
