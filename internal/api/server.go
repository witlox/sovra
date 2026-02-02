// Package api handles API gateway functionality.
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
)

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	Addr            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	Logger          *slog.Logger

	// TLS configuration
	TLSEnabled  bool
	TLSCertFile string
	TLSKeyFile  string
	TLSConfig   *tls.Config

	// mTLS configuration
	MTLSEnabled  bool
	ClientCAFile string
	ClientCAs    *x509.CertPool
}

// DefaultServerConfig returns a sensible default configuration.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Addr:            ":8443",
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		IdleTimeout:     120 * time.Second,
		ShutdownTimeout: 30 * time.Second,
		Logger:          slog.Default(),
		TLSEnabled:      true,
		MTLSEnabled:     false,
	}
}

// Server wraps http.Server with graceful shutdown and health checks.
type Server struct {
	server          *http.Server
	router          chi.Router
	config          *ServerConfig
	logger          *slog.Logger
	healthy         atomic.Bool
	ready           atomic.Bool
	started         atomic.Bool
	shutdownStarted atomic.Bool
}

// NewServer creates a new HTTP server.
func NewServer(router chi.Router, config *ServerConfig) (*Server, error) {
	if config == nil {
		config = DefaultServerConfig()
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	s := &Server{
		router: router,
		config: config,
		logger: config.Logger,
	}

	// Build TLS config if enabled
	tlsConfig, err := s.buildTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to build TLS config: %w", err)
	}

	s.server = &http.Server{
		Addr:         config.Addr,
		Handler:      router,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
		IdleTimeout:  config.IdleTimeout,
		TLSConfig:    tlsConfig,
		ErrorLog:     slog.NewLogLogger(config.Logger.Handler(), slog.LevelError),
	}

	// Set initial health status
	s.healthy.Store(true)
	s.ready.Store(false)

	return s, nil
}

// buildTLSConfig builds the TLS configuration.
func (s *Server) buildTLSConfig() (*tls.Config, error) {
	if !s.config.TLSEnabled {
		return nil, nil
	}

	// Use provided TLS config if available
	if s.config.TLSConfig != nil {
		return s.config.TLSConfig, nil
	}

	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
	}

	// Load server certificate if provided
	if s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(s.config.TLSCertFile, s.config.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load server certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Configure mTLS if enabled
	if s.config.MTLSEnabled {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

		// Load client CA pool
		if s.config.ClientCAs != nil {
			tlsConfig.ClientCAs = s.config.ClientCAs
		} else if s.config.ClientCAFile != "" {
			caCert, err := os.ReadFile(s.config.ClientCAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read client CA file: %w", err)
			}
			tlsConfig.ClientCAs = x509.NewCertPool()
			if !tlsConfig.ClientCAs.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse client CA certificate")
			}
		}
	}

	return tlsConfig, nil
}

// Start starts the HTTP server.
func (s *Server) Start(ctx context.Context) error {
	if s.started.Load() {
		return fmt.Errorf("server already started")
	}

	s.started.Store(true)
	s.ready.Store(true)

	s.logger.InfoContext(ctx, "starting HTTP server",
		"addr", s.config.Addr,
		"tls", s.config.TLSEnabled,
		"mtls", s.config.MTLSEnabled,
	)

	var err error
	switch {
	case s.config.TLSEnabled && s.config.TLSCertFile != "":
		err = s.server.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
	case s.config.TLSEnabled && s.server.TLSConfig != nil && len(s.server.TLSConfig.Certificates) > 0:
		lc := net.ListenConfig{}
		listener, listenErr := lc.Listen(ctx, "tcp", s.config.Addr)
		if listenErr != nil {
			return fmt.Errorf("failed to listen: %w", listenErr)
		}
		if serveErr := s.server.ServeTLS(listener, "", ""); serveErr != nil && serveErr != http.ErrServerClosed {
			return fmt.Errorf("failed to serve TLS: %w", serveErr)
		}
		return nil
	default:
		err = s.server.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		s.healthy.Store(false)
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

// StartAsync starts the server in a goroutine and returns immediately.
func (s *Server) StartAsync() error {
	if s.started.Load() {
		return fmt.Errorf("server already started")
	}

	go func() {
		if err := s.Start(context.Background()); err != nil {
			s.logger.ErrorContext(context.Background(), "server error", "error", err)
		}
	}()

	// Wait a brief moment for the server to start
	time.Sleep(10 * time.Millisecond)
	return nil
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if !s.started.Load() {
		return nil
	}

	if s.shutdownStarted.Swap(true) {
		return nil // Already shutting down
	}

	s.logger.InfoContext(ctx, "shutting down HTTP server")

	// Mark as not ready first
	s.ready.Store(false)

	// Create shutdown context with timeout
	if s.config.ShutdownTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.config.ShutdownTimeout)
		defer cancel()
	}

	// Gracefully shutdown
	if err := s.server.Shutdown(ctx); err != nil {
		s.logger.ErrorContext(ctx, "server shutdown error", "error", err)
		s.healthy.Store(false)
		return fmt.Errorf("server shutdown error: %w", err)
	}

	s.healthy.Store(false)
	s.logger.InfoContext(ctx, "HTTP server stopped")
	return nil
}

// IsHealthy returns whether the server is healthy.
func (s *Server) IsHealthy() bool {
	return s.healthy.Load()
}

// IsReady returns whether the server is ready to accept requests.
func (s *Server) IsReady() bool {
	return s.ready.Load()
}

// SetHealthy sets the server health status.
func (s *Server) SetHealthy(healthy bool) {
	s.healthy.Store(healthy)
}

// SetReady sets the server ready status.
func (s *Server) SetReady(ready bool) {
	s.ready.Store(ready)
}

// Addr returns the server address.
func (s *Server) Addr() string {
	return s.config.Addr
}

// Router returns the chi router.
func (s *Server) Router() chi.Router {
	return s.router
}

// HealthChecker provides health check functionality.
type HealthChecker struct {
	checks map[string]HealthCheckFunc
	logger *slog.Logger
}

// HealthCheckFunc is a function that performs a health check.
type HealthCheckFunc func(ctx context.Context) error

// NewHealthChecker creates a new health checker.
func NewHealthChecker(logger *slog.Logger) *HealthChecker {
	if logger == nil {
		logger = slog.Default()
	}
	return &HealthChecker{
		checks: make(map[string]HealthCheckFunc),
		logger: logger,
	}
}

// Register registers a health check.
func (h *HealthChecker) Register(name string, check HealthCheckFunc) {
	h.checks[name] = check
}

// Check runs all health checks and returns the results.
func (h *HealthChecker) Check(ctx context.Context) *HealthCheckResult {
	result := &HealthCheckResult{
		Status:     "healthy",
		Components: make(map[string]*ComponentHealthResult),
	}

	for name, check := range h.checks {
		componentResult := &ComponentHealthResult{Status: "healthy"}
		if err := check(ctx); err != nil {
			componentResult.Status = "unhealthy"
			componentResult.Error = err.Error()
			result.Status = "unhealthy"
			h.logger.WarnContext(ctx, "health check failed", "component", name, "error", err)
		}
		result.Components[name] = componentResult
	}

	return result
}

// HealthCheckResult represents the result of health checks.
type HealthCheckResult struct {
	Status     string                            `json:"status"`
	Components map[string]*ComponentHealthResult `json:"components,omitempty"`
}

// ComponentHealthResult represents the result of a component health check.
type ComponentHealthResult struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}
