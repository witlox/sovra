// Package api handles API gateway functionality.
package api

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/witlox/sovra/internal/audit"
	"github.com/witlox/sovra/internal/compliance"
	"github.com/witlox/sovra/internal/crk"
	"github.com/witlox/sovra/internal/edge"
	"github.com/witlox/sovra/internal/federation"
	"github.com/witlox/sovra/internal/identity"
	"github.com/witlox/sovra/internal/policy"
	"github.com/witlox/sovra/internal/rotation"
	"github.com/witlox/sovra/internal/workspace"
	"github.com/witlox/sovra/pkg/metrics"
	"github.com/witlox/sovra/pkg/vault"
)

// RouterConfig holds router configuration.
type RouterConfig struct {
	Logger                *slog.Logger
	MTLSVerifier          MTLSVerifier
	Authenticator         Authenticator
	RateLimiter           RateLimiter
	AdminIdentityResolver AdminIdentityResolver
	MiddlewareConfig      *MiddlewareConfig
	HealthCheckers        map[string]func() error
}

// DefaultRouterConfig returns a default router configuration.
func DefaultRouterConfig() *RouterConfig {
	return &RouterConfig{
		Logger:           slog.Default(),
		MTLSVerifier:     NewDefaultMTLSVerifier(),
		Authenticator:    NewDefaultAuthenticator(),
		RateLimiter:      NewInMemoryRateLimiter(100, 60),
		MiddlewareConfig: DefaultMiddlewareConfig(),
		HealthCheckers:   make(map[string]func() error),
	}
}

// Services holds all service dependencies for the API.
type Services struct {
	Workspace         workspace.Service
	Federation        federation.Service
	Policy            policy.Service
	Audit             audit.Service
	Edge              edge.Service
	CRKManager        crk.Manager
	CRKCeremony       crk.CeremonyManager
	Identity          *identity.Manager
	PKI               *vault.PKIClient
	EmergencyAccess   *identity.EmergencyAccessManager
	AccountRecovery   *identity.AccountRecoveryManager
	Compliance        *compliance.ReportGenerator
	RotationScheduler *rotation.Scheduler
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

	// Add enrollment/bootstrap paths to skip list for auth/mTLS
	config.MiddlewareConfig.SkipPaths = append(config.MiddlewareConfig.SkipPaths,
		"/api/v1/enrollment",
		"/api/v1/bootstrap",
	)

	// Apply security middleware
	if config.MTLSVerifier != nil {
		r.Use(MTLSMiddleware(config.MTLSVerifier, config.MiddlewareConfig))
	}
	if config.AdminIdentityResolver != nil {
		r.Use(AdminCertMiddleware(config.AdminIdentityResolver))
	}
	if config.Authenticator != nil {
		r.Use(AuthMiddleware(config.Authenticator, config.MiddlewareConfig))
	}
	if config.RateLimiter != nil {
		r.Use(RateLimitMiddleware(config.RateLimiter, config.MiddlewareConfig))
	}

	// Register routes
	registerHealthRoutes(r, config.HealthCheckers)
	registerWorkspaceRoutes(r, services)
	registerFederationRoutes(r, services)
	registerPolicyRoutes(r, services)
	registerAuditRoutes(r, services)
	registerEdgeRoutes(r, services)
	registerCRKRoutes(r, services)
	registerIdentityRoutes(r, services)
	registerEnrollmentRoutes(r, services)
	registerCertificateRoutes(r, services)
	registerEmergencyAccessRoutes(r, services)
	registerAccountRecoveryRoutes(r, services)
	registerComplianceRoutes(r, services)
	registerRotationPolicyRoutes(r, services)

	return r
}

// registerHealthRoutes registers health check endpoints.
func registerHealthRoutes(r chi.Router, healthCheckers map[string]func() error) {
	r.Get("/health", makeHealthHandler(healthCheckers))
	r.Get("/ready", handleReady)
	r.Get("/live", handleLive)
	r.Handle("/metrics", metrics.Handler())
}

// makeHealthHandler creates a health handler that checks all registered components.
func makeHealthHandler(healthCheckers map[string]func() error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response := HealthResponse{
			Status:     "healthy",
			Version:    "1.0.0",
			Components: make(map[string]*ComponentHealth),
		}

		// Check all registered health checkers
		for name, checker := range healthCheckers {
			component := &ComponentHealth{Status: "healthy"}
			if checker != nil {
				if err := checker(); err != nil {
					component.Status = "unhealthy"
					component.Message = err.Error()
					response.Status = "degraded"
				}
			}
			response.Components[name] = component
		}

		// If no components were checked, remove empty map
		if len(response.Components) == 0 {
			response.Components = nil
		}

		statusCode := http.StatusOK
		if response.Status == "degraded" {
			statusCode = http.StatusServiceUnavailable
		}
		writeJSON(w, statusCode, response)
	}
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
		r.Post("/{id}/rotate-dek", handler.RotateDEK)
		r.Post("/{id}/extend", handler.ExtendExpiration)
		r.Post("/{id}/invite", handler.InviteParticipant)
		r.Post("/{id}/accept-invitation", handler.AcceptInvitation)
		r.Post("/{id}/decline-invitation", handler.DeclineInvitation)
		r.Post("/{id}/participants", handler.AddParticipant)
		r.Delete("/{id}/participants/{orgId}", handler.RemoveParticipant)
		r.Post("/{id}/archive", handler.Archive)
		r.Post("/{id}/export", handler.Export)
		r.Post("/import", handler.Import)
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
		r.Post("/rotate", handler.RotateCRK)
		r.Post("/ceremony/start", handler.StartCeremony)
		r.Post("/ceremony/{id}/share", handler.AddShare)
		r.Post("/ceremony/{id}/complete", handler.CompleteCeremony)
		r.Delete("/ceremony/{id}", handler.CancelCeremony)
	})
}

// registerIdentityRoutes registers identity management endpoints.
func registerIdentityRoutes(r chi.Router, services *Services) {
	if services == nil || services.Identity == nil {
		return
	}
	handler := NewIdentityHandler(services.Identity)
	r.Route("/api/v1/identities", func(r chi.Router) {
		// Admin identities
		r.Post("/admins", handler.CreateAdmin)
		r.Get("/admins", handler.ListAdmins)
		r.Get("/admins/{id}", handler.GetAdmin)
		r.Put("/admins/{id}", handler.UpdateAdmin)
		r.Delete("/admins/{id}", handler.DeleteAdmin)
		r.Post("/admins/{id}/mfa/enable", handler.EnableMFA)
		r.Post("/admins/{id}/mfa/verify", handler.VerifyMFA)

		// User identities
		r.Post("/users/sso", handler.CreateUserFromSSO)
		r.Get("/users", handler.ListUsers)
		r.Get("/users/{id}", handler.GetUser)
		r.Delete("/users/{id}", handler.DeleteUser)

		// Service identities
		r.Post("/services", handler.CreateService)
		r.Get("/services", handler.ListServices)
		r.Get("/services/{id}", handler.GetService)
		r.Delete("/services/{id}", handler.DeleteService)

		// Device identities
		r.Post("/devices", handler.EnrollDevice)
		r.Get("/devices", handler.ListDevices)
		r.Get("/devices/{id}", handler.GetDevice)
		r.Post("/devices/{id}/revoke", handler.RevokeDevice)

		// Groups
		r.Post("/groups", handler.CreateGroup)
		r.Get("/groups", handler.ListGroups)
		r.Get("/groups/{id}", handler.GetGroup)
		r.Post("/groups/{id}/members", handler.AddGroupMember)
		r.Delete("/groups/{id}/members/{identityId}", handler.RemoveGroupMember)

		// Roles
		r.Post("/roles", handler.CreateRole)
		r.Get("/roles", handler.ListRoles)
		r.Get("/roles/{id}", handler.GetRole)
		r.Post("/roles/{id}/assign", handler.AssignRole)
		r.Delete("/roles/{id}/assignments/{identityId}", handler.UnassignRole)

		// Service credential rotation
		r.Post("/services/{id}/rotate", handler.RotateServiceCredentials)

		// Admin certificate management
		r.Post("/admins/{id}/certificate/renew", handler.RenewAdminCertificate)
	})
}

// registerEnrollmentRoutes registers unauthenticated enrollment and bootstrap endpoints.
func registerEnrollmentRoutes(r chi.Router, services *Services) {
	if services == nil || services.Identity == nil {
		return
	}
	handler := NewIdentityHandler(services.Identity)

	// Admin enrollment (unauthenticated — token serves as auth)
	r.Route("/api/v1/enrollment/admins/{id}", func(r chi.Router) {
		r.Get("/setup", handler.GetEnrollmentSetup)
		r.Post("/", handler.EnrollAdmin)
	})

	// Bootstrap admin (unauthenticated — only works when no admins exist)
	r.Post("/api/v1/bootstrap/admin", handler.BootstrapAdmin)
}

// registerCertificateRoutes registers certificate management endpoints.
func registerCertificateRoutes(r chi.Router, services *Services) {
	if services == nil || services.PKI == nil {
		return
	}
	handler := NewCertificateHandler(services.PKI)
	r.Route("/api/v1/certificates", func(r chi.Router) {
		r.Post("/issue", handler.Issue)
		r.Post("/revoke", handler.Revoke)
		r.Get("/", handler.List)
		r.Get("/ca-chain", handler.GetCAChain)
		r.Get("/{serial}", handler.Read)
		r.Post("/tidy", handler.Tidy)
	})
}

// registerEmergencyAccessRoutes registers emergency access endpoints.
func registerEmergencyAccessRoutes(r chi.Router, services *Services) {
	if services == nil || services.EmergencyAccess == nil {
		return
	}
	handler := NewEmergencyAccessHandler(services.EmergencyAccess)
	r.Route("/api/v1/emergency-access", func(r chi.Router) {
		r.Post("/request", handler.Request)
		r.Get("/", handler.ListEmergencyAccess)
		r.Get("/{id}", handler.GetEmergencyAccess)
		r.Post("/{id}/approve", handler.Approve)
		r.Post("/{id}/deny", handler.Deny)
		r.Post("/{id}/complete", handler.Complete)
		r.Post("/{id}/verify", handler.Verify)
	})
}

// registerAccountRecoveryRoutes registers account recovery endpoints.
func registerAccountRecoveryRoutes(r chi.Router, services *Services) {
	if services == nil || services.AccountRecovery == nil {
		return
	}
	handler := NewAccountRecoveryHandler(services.AccountRecovery)
	r.Route("/api/v1/account-recovery", func(r chi.Router) {
		r.Post("/initiate", handler.Initiate)
		r.Post("/{id}/share", handler.CollectShare)
		r.Post("/{id}/complete", handler.CompleteRecovery)
	})
}

// registerComplianceRoutes registers compliance report endpoints.
func registerComplianceRoutes(r chi.Router, services *Services) {
	if services == nil || services.Compliance == nil {
		return
	}
	handler := NewComplianceHandler(services.Compliance)
	r.Route("/api/v1/compliance/reports", func(r chi.Router) {
		r.Post("/summary", handler.GenerateSummary)
		r.Post("/gdpr-dsar", handler.GenerateDSAR)
		r.Post("/access-review", handler.GenerateAccessReview)
	})
}

// registerRotationPolicyRoutes registers rotation policy endpoints.
func registerRotationPolicyRoutes(r chi.Router, services *Services) {
	if services == nil || services.RotationScheduler == nil {
		return
	}
	handler := NewRotationPolicyHandler(services.RotationScheduler)
	r.Get("/api/v1/rotation-policies", handler.ListPolicies)
	r.Route("/api/v1/workspaces/{id}/rotation-policy", func(r chi.Router) {
		r.Put("/", handler.Set)
		r.Get("/", handler.Get)
		r.Delete("/", handler.Delete)
	})
}
