// Package main implements the Sovra API Gateway service.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/witlox/sovra/internal/api"
	"github.com/witlox/sovra/internal/audit"
	"github.com/witlox/sovra/internal/config"
	"github.com/witlox/sovra/internal/crk"
	"github.com/witlox/sovra/internal/edge"
	"github.com/witlox/sovra/internal/federation"
	"github.com/witlox/sovra/internal/policy"
	"github.com/witlox/sovra/internal/workspace"
	"github.com/witlox/sovra/pkg/postgres"
	"github.com/witlox/sovra/pkg/telemetry"
	"github.com/witlox/sovra/pkg/vault"
)

var version = "dev"

func main() {
	logLevel := slog.LevelInfo
	if os.Getenv("SOVRA_LOG_LEVEL") == "debug" {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	logger.Info("starting sovra api-gateway", "version", version)

	cfg, err := config.Load(os.Getenv("SOVRA_CONFIG"))
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	cfg.Service = "api-gateway"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize telemetry
	telemetryCfg := telemetry.Config{
		Enabled:        cfg.Telemetry.Enabled,
		ServiceName:    cfg.Telemetry.ServiceName,
		ServiceVersion: cfg.Telemetry.ServiceVersion,
		Endpoint:       cfg.Telemetry.Endpoint,
		SampleRate:     cfg.Telemetry.SampleRate,
	}
	tp, err := telemetry.Init(ctx, telemetryCfg)
	if err != nil {
		logger.Warn("failed to initialize telemetry", "error", err)
	} else if tp != nil {
		defer tp.Shutdown(ctx)
		logger.Info("telemetry initialized", "enabled", cfg.Telemetry.Enabled)
	}

	db, err := postgres.Connect(ctx, cfg.Database.DSN())
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := postgres.Migrate(ctx, db); err != nil {
		logger.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}

	vaultClient, err := vault.NewClient(vault.Config{
		Address: cfg.Vault.Address,
		Token:   cfg.Vault.Token,
	})
	if err != nil {
		logger.Error("failed to create vault client", "error", err)
		os.Exit(1)
	}

	opaClient := policy.NewOPAClientAdapter(cfg.OPA.Address)

	wsRepo := postgres.NewWorkspaceRepository(db)
	fedRepo := postgres.NewFederationRepository(db)
	policyRepo := postgres.NewPolicyRepository(db)
	auditRepo := postgres.NewAuditRepository(db)
	edgeRepo := postgres.NewEdgeNodeRepository(db)

	auditSvc := audit.NewService(auditRepo, nil, nil)
	wsSvc := workspace.NewWorkspaceService(wsRepo, vaultClient, auditSvc)
	fedSvc := federation.NewFederationService(fedRepo, vaultClient, auditSvc)
	policySvc := policy.NewPolicyService(policyRepo, opaClient, auditSvc)
	crkMgr := crk.NewManager()
	crkCeremony := crk.NewCeremonyManager(crkMgr)

	// VaultFactory creates vault clients for edge nodes
	vaultFactory := func(address, token string) (*vault.Client, error) {
		return vault.NewClient(vault.Config{Address: address, Token: token})
	}
	edgeSvc := edge.NewEdgeService(edgeRepo, vaultFactory, auditSvc)

	services := &api.Services{
		Workspace:   wsSvc,
		Federation:  fedSvc,
		Policy:      policySvc,
		Audit:       auditSvc,
		Edge:        edgeSvc,
		CRKManager:  crkMgr,
		CRKCeremony: crkCeremony,
	}

	routerCfg := api.DefaultRouterConfig()
	routerCfg.Logger = logger
	router := api.NewRouter(routerCfg, services)

	server := &http.Server{
		Addr:         cfg.Server.Addr(),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	go func() {
		if cfg.Server.TLSEnabled {
			// Configure TLS
			tlsConfig := &tls.Config{
				MinVersion: tls.VersionTLS12,
			}

			// Configure mTLS if enabled
			if cfg.Server.MTLSEnabled && cfg.Server.TLSCAFile != "" {
				caCert, err := os.ReadFile(cfg.Server.TLSCAFile)
				if err != nil {
					logger.Error("failed to read CA file", "error", err)
					cancel()
					return
				}
				caCertPool := x509.NewCertPool()
				if !caCertPool.AppendCertsFromPEM(caCert) {
					logger.Error("failed to parse CA certificate")
					cancel()
					return
				}
				tlsConfig.ClientCAs = caCertPool
				tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
				logger.Info("mTLS enabled", "ca_file", cfg.Server.TLSCAFile)
			}

			server.TLSConfig = tlsConfig
			logger.Info("starting HTTPS server", "addr", cfg.Server.Addr(), "mtls", cfg.Server.MTLSEnabled)
			if err := server.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				logger.Error("server error", "error", err)
				cancel()
			}
		} else {
			logger.Info("starting HTTP server", "addr", cfg.Server.Addr())
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("server error", "error", err)
				cancel()
			}
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info("shutting down...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
	logger.Info("shutdown complete")
}
