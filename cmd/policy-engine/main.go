// Package main implements the Sovra Policy Engine service.
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/witlox/sovra/internal/audit"
	"github.com/witlox/sovra/internal/config"
	"github.com/witlox/sovra/internal/policy"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/pkg/opa"
	"github.com/witlox/sovra/pkg/postgres"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	logger.Info("starting sovra policy-engine", "version", version)

	cfg, err := config.Load(os.Getenv("SOVRA_CONFIG"))
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	cfg.Service = "policy-engine"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize database
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

	// Initialize OPA client (raw client for health checks)
	opaRawClient := opa.NewClient(cfg.OPA.Address)
	opaClient := policy.NewOPAClientAdapter(cfg.OPA.Address)

	// Initialize services
	auditRepo := postgres.NewAuditRepository(db)
	auditSvc := audit.NewService(auditRepo, nil, nil)

	policyRepo := postgres.NewPolicyRepository(db)
	policySvc := policy.NewPolicyService(policyRepo, opaClient, auditSvc)

	// HTTP handlers
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		// Check OPA health
		if err := opaRawClient.Health(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "unhealthy", "error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	})

	mux.HandleFunc("/api/v1/policies/evaluate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var input models.PolicyInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		result, err := policySvc.Evaluate(r.Context(), input)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})

	mux.HandleFunc("/api/v1/policies/validate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Rego string `json:"rego"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if err := policySvc.Validate(r.Context(), req.Rego); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"valid": "false", "error": err.Error()})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"valid": "true"})
	})

	server := &http.Server{
		Addr:         cfg.Server.Addr(),
		Handler:      mux,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
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
