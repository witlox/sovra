// Package api handles API gateway functionality.
package api

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/witlox/sovra/internal/audit"
	"github.com/witlox/sovra/internal/crk"
	"github.com/witlox/sovra/internal/edge"
	"github.com/witlox/sovra/internal/federation"
	"github.com/witlox/sovra/internal/policy"
	"github.com/witlox/sovra/internal/workspace"
)

// RouterConfig holds router configuration.
type RouterConfig struct {
	Logger           *slog.Logger
	MTLSVerifier     MTLSVerifier
	Authenticator    Authenticator
	RateLimiter      RateLimiter
	MiddlewareConfig *MiddlewareConfig
}

// DefaultRouterConfig returns a default router configuration.
func DefaultRouterConfig() *RouterConfig {
	return &RouterConfig{
		Logger:           slog.Default(),
		MTLSVerifier:     NewDefaultMTLSVerifier(),
		Authenticator:    NewDefaultAuthenticator(),
		RateLimiter:      NewInMemoryRateLimiter(100, 60),
		MiddlewareConfig: DefaultMiddlewareConfig(),
	}
}

// Services holds all service dependencies for the API.
type Services struct {
	Workspace   workspace.Service
	Federation  federation.Service
	Policy      policy.Service
	Audit       audit.Service
	Edge        edge.Service
	CRKManager  crk.Manager
	CRKCeremony crk.CeremonyManager
}

// NewRouter creates a new chi router with all middleware and routes.
func NewRouter(config *RouterConfig, services *Services) chi.Router {
	if config == nil {
		config = DefaultRouterConfig()
	}

	r := chi.NewRouter()

	// Apply middleware stack
	r.Use(RequestIDMiddleware)
	r.Use(RecoveryMiddleware(config.Logger))
	r.Use(LoggingMiddleware(config.Logger))
	r.Use(middleware.RealIP)
	r.Use(ContentTypeMiddleware)

	// Apply security middleware
	if config.MTLSVerifier != nil {
		r.Use(MTLSMiddleware(config.MTLSVerifier, config.MiddlewareConfig))
	}
	if config.Authenticator != nil {
		r.Use(AuthMiddleware(config.Authenticator, config.MiddlewareConfig))
	}
	if config.RateLimiter != nil {
		r.Use(RateLimitMiddleware(config.RateLimiter, config.MiddlewareConfig))
	}

	// Register routes
	registerHealthRoutes(r)
	registerWorkspaceRoutes(r, services)
	registerFederationRoutes(r, services)
	registerPolicyRoutes(r, services)
	registerAuditRoutes(r, services)
	registerEdgeRoutes(r, services)
	registerCRKRoutes(r, services)

	return r
}

// registerHealthRoutes registers health check endpoints.
func registerHealthRoutes(r chi.Router) {
	r.Get("/health", handleHealth)
	r.Get("/ready", handleReady)
	r.Get("/live", handleLive)
}

// handleHealth returns overall API health.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, HealthResponse{
		Status:  "healthy",
		Version: "1.0.0",
	})
}

// handleReady returns readiness status.
func handleReady(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// handleLive returns liveness status.
func handleLive(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "alive"})
}

// HealthResponse represents health check response.
type HealthResponse struct {
	Status     string                      `json:"status"`
	Version    string                      `json:"version"`
	Components map[string]*ComponentHealth `json:"components,omitempty"`
}

// ComponentHealth represents individual component health.
type ComponentHealth struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// registerWorkspaceRoutes registers workspace endpoints.
func registerWorkspaceRoutes(r chi.Router, services *Services) {
	if services == nil || services.Workspace == nil {
		return
	}
	handler := NewWorkspaceHandler(services.Workspace)
	r.Route("/api/v1/workspaces", func(r chi.Router) {
		r.Post("/", handler.Create)
		r.Get("/", handler.List)
		r.Get("/{id}", handler.Get)
		r.Put("/{id}", handler.Update)
		r.Delete("/{id}", handler.Delete)
		r.Post("/{id}/encrypt", handler.Encrypt)
		r.Post("/{id}/decrypt", handler.Decrypt)
		r.Post("/{id}/participants", handler.AddParticipant)
		r.Delete("/{id}/participants/{orgId}", handler.RemoveParticipant)
		r.Post("/{id}/archive", handler.Archive)
	})
}

// registerFederationRoutes registers federation endpoints.
func registerFederationRoutes(r chi.Router, services *Services) {
	if services == nil || services.Federation == nil {
		return
	}
	handler := NewFederationHandler(services.Federation)
	r.Route("/api/v1/federation", func(r chi.Router) {
		r.Post("/init", handler.Init)
		r.Post("/establish", handler.Establish)
		r.Get("/", handler.List)
		r.Get("/{partnerId}", handler.Status)
		r.Delete("/{partnerId}", handler.Revoke)
		r.Get("/health", handler.HealthCheck)
		r.Post("/certificate/import", handler.ImportCertificate)
	})
}

// registerPolicyRoutes registers policy endpoints.
func registerPolicyRoutes(r chi.Router, services *Services) {
	if services == nil || services.Policy == nil {
		return
	}
	handler := NewPolicyHandler(services.Policy)
	r.Route("/api/v1/policies", func(r chi.Router) {
		r.Post("/", handler.Create)
		r.Get("/{id}", handler.Get)
		r.Put("/{id}", handler.Update)
		r.Delete("/{id}", handler.Delete)
		r.Get("/workspace/{workspaceId}", handler.GetForWorkspace)
		r.Post("/evaluate", handler.Evaluate)
		r.Post("/validate", handler.Validate)
	})
}

// registerAuditRoutes registers audit endpoints.
func registerAuditRoutes(r chi.Router, services *Services) {
	if services == nil || services.Audit == nil {
		return
	}
	handler := NewAuditHandler(services.Audit)
	r.Route("/api/v1/audit", func(r chi.Router) {
		r.Get("/", handler.Query)
		r.Get("/{id}", handler.Get)
		r.Post("/export", handler.Export)
		r.Get("/stats", handler.GetStats)
		r.Post("/verify", handler.VerifyIntegrity)
	})
}

// registerEdgeRoutes registers edge node endpoints.
func registerEdgeRoutes(r chi.Router, services *Services) {
	if services == nil || services.Edge == nil {
		return
	}
	handler := NewEdgeHandler(services.Edge)
	r.Route("/api/v1/edges", func(r chi.Router) {
		r.Post("/", handler.Register)
		r.Get("/", handler.List)
		r.Get("/{id}", handler.Get)
		r.Delete("/{id}", handler.Unregister)
		r.Get("/{id}/health", handler.HealthCheck)
		r.Post("/{id}/sync/policies", handler.SyncPolicies)
		r.Post("/{id}/sync/keys", handler.SyncWorkspaceKeys)
		r.Get("/{id}/sync/status", handler.GetSyncStatus)
	})
}

// registerCRKRoutes registers CRK (Customer Root Key) endpoints.
func registerCRKRoutes(r chi.Router, services *Services) {
	if services == nil || services.CRKManager == nil {
		return
	}
	handler := NewCRKHandler(services.CRKManager, services.CRKCeremony)
	r.Route("/api/v1/crk", func(r chi.Router) {
		r.Post("/generate", handler.Generate)
		r.Post("/sign", handler.Sign)
		r.Post("/verify", handler.Verify)
		r.Post("/ceremony/start", handler.StartCeremony)
		r.Post("/ceremony/{id}/share", handler.AddShare)
		r.Post("/ceremony/{id}/complete", handler.CompleteCeremony)
		r.Delete("/ceremony/{id}", handler.CancelCeremony)
	})
}
