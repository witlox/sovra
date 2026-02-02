// Package main implements the Sovra Key Lifecycle service.
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

	"github.com/sovra-project/sovra/internal/config"
	"github.com/sovra-project/sovra/internal/crk"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/sovra-project/sovra/pkg/vault"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	logger.Info("starting sovra key-lifecycle", "version", version)

	cfg, err := config.Load(os.Getenv("SOVRA_CONFIG"))
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	cfg.Service = "key-lifecycle"

	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize Vault client for health checks
	vaultClient, err := vault.NewClient(vault.Config{
		Address: cfg.Vault.Address,
		Token:   cfg.Vault.Token,
	})
	if err != nil {
		logger.Error("failed to create vault client", "error", err)
		os.Exit(1)
	}

	// Initialize CRK services
	crkMgr := crk.NewManager()
	crkCeremony := crk.NewCeremonyManager(crkMgr)

	// HTTP handlers
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		health, err := vaultClient.Health(r.Context())
		if err != nil || health.Sealed {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "unhealthy",
				"vault":  health,
				"error":  err,
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	})

	mux.HandleFunc("/api/v1/crk/generate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			OrgID     string `json:"org_id"`
			Shares    int    `json:"shares"`
			Threshold int    `json:"threshold"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.Shares == 0 {
			req.Shares = 5
		}
		if req.Threshold == 0 {
			req.Threshold = 3
		}

		crkKey, err := crkMgr.Generate(req.OrgID, req.Shares, req.Threshold)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		shares, _ := crkMgr.GetShares(crkKey.ID)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"crk":    crkKey,
			"shares": shares,
		})
	})

	mux.HandleFunc("/api/v1/crk/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Shares    []models.CRKShare `json:"shares"`
			PublicKey []byte            `json:"public_key"`
			Data      []byte            `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		sig, err := crkMgr.Sign(req.Shares, req.PublicKey, req.Data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"signature": sig})
	})

	mux.HandleFunc("/api/v1/crk/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			PublicKey []byte `json:"public_key"`
			Data      []byte `json:"data"`
			Signature []byte `json:"signature"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		valid, err := crkMgr.Verify(req.PublicKey, req.Data, req.Signature)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"valid": valid})
	})

	mux.HandleFunc("/api/v1/crk/ceremony/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			OrgID     string `json:"org_id"`
			Operation string `json:"operation"`
			Threshold int    `json:"threshold"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		ceremony, err := crkCeremony.StartCeremony(req.OrgID, req.Operation, req.Threshold)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ceremony)
	})

	mux.HandleFunc("/api/v1/crk/ceremony/add-share", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			CeremonyID string          `json:"ceremony_id"`
			Share      models.CRKShare `json:"share"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if err := crkCeremony.AddShare(req.CeremonyID, req.Share); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "share_added"})
	})

	mux.HandleFunc("/api/v1/crk/ceremony/complete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			CeremonyID string `json:"ceremony_id"`
			Witness    string `json:"witness"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		result, err := crkCeremony.CompleteCeremony(req.CeremonyID, req.Witness)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"result": result})
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
