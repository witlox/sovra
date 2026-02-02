// Package main implements the Sovra API Gateway service.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sovra-project/sovra/internal/api"
	"github.com/sovra-project/sovra/internal/audit"
	"github.com/sovra-project/sovra/internal/config"
	"github.com/sovra-project/sovra/internal/crk"
	"github.com/sovra-project/sovra/internal/edge"
	"github.com/sovra-project/sovra/internal/federation"
	"github.com/sovra-project/sovra/internal/policy"
	"github.com/sovra-project/sovra/internal/workspace"
	"github.com/sovra-project/sovra/pkg/postgres"
	"github.com/sovra-project/sovra/pkg/vault"
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
		logger.Info("starting HTTP server", "addr", cfg.Server.Addr())
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
			cancel()
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
