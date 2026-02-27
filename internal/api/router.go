// Package api handles API gateway functionality.
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/witlox/sovra/internal/audit"
	"github.com/witlox/sovra/internal/backup"
	"github.com/witlox/sovra/internal/compliance"
	"github.com/witlox/sovra/internal/crk"
	"github.com/witlox/sovra/internal/edge"
	"github.com/witlox/sovra/internal/federation"
	"github.com/witlox/sovra/internal/identity"
	"github.com/witlox/sovra/internal/messaging"
	"github.com/witlox/sovra/internal/policy"
	"github.com/witlox/sovra/internal/rotation"
	"github.com/witlox/sovra/internal/workspace"
	"github.com/witlox/sovra/pkg/metrics"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/pkg/telemetry"
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
	SSOIssuerURL          string
	SSOClientID           string
	ServiceMetrics        *metrics.ServiceMetrics
	ServiceName           string // for telemetry tracer
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
	Workspace                workspace.Service
	WorkspaceRequest         workspace.WorkspaceRequestService
	Federation               federation.Service
	Policy                   policy.Service
	Audit                    audit.Service
	Edge                     edge.Service
	CRKManager               crk.Manager
	CRKCeremony              crk.CeremonyManager
	CRKGenerationCeremony    crk.GenerationCeremonyManager
	Identity                 *identity.Manager
	PKI                      *vault.PKIClient
	EmergencyAccess          *identity.EmergencyAccessManager
	AccountRecovery          *identity.AccountRecoveryManager
	Compliance               *compliance.ReportGenerator
	RotationScheduler        *rotation.Scheduler
	GroupBindingRepo         workspace.GroupBindingRepository
	GroupFederationCouplings workspace.GroupFederationCouplingRepository
	AdmissionRepo            workspace.AdmissionRepository
	Backup                   backup.Service
	Messaging                messaging.Service
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

	// Telemetry and metrics middleware
	if config.ServiceName != "" {
		r.Use(telemetry.Middleware(config.ServiceName, metrics.SanitizePath))
	}
	if config.ServiceMetrics != nil {
		r.Use(metrics.Middleware(config.ServiceMetrics))
	}

	r.Use(ContentTypeMiddleware)

	// Add enrollment/bootstrap/sso-config paths to skip list for auth/mTLS
	config.MiddlewareConfig.SkipPaths = append(config.MiddlewareConfig.SkipPaths,
		"/api/v1/enrollment",
		"/api/v1/bootstrap",
		"/api/v1/sso-config",
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
	registerSSOConfigRoute(r, config)
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
	registerBackupRoutes(r, services)
	registerMessageRoutes(r, services)
	registerActivityRoutes(r, services)
	registerWorkspaceRequestRoutes(r, services)
	registerFederationRequestRoutes(r, services)
	registerGroupFederationCouplingRoutes(r, services)

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

// registerSSOConfigRoute registers the unauthenticated SSO config discovery endpoint.
func registerSSOConfigRoute(r chi.Router, config *RouterConfig) {
	if config.SSOIssuerURL == "" && config.SSOClientID == "" {
		return
	}
	r.Get("/api/v1/sso-config", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"issuer_url": config.SSOIssuerURL,
			"client_id":  config.SSOClientID,
		})
	})
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
		r.Post("/{id}/archive", handler.Archive)
		r.Post("/{id}/export", handler.Export)
		r.Post("/import", handler.Import)

		// Workspace access request (convenience: resolves bound group, creates join request)
		if services.Identity != nil && services.GroupBindingRepo != nil {
			accessHandler := NewWorkspaceAccessRequestHandler(services.Identity, services.GroupBindingRepo)
			r.Post("/{id}/request-access", accessHandler.RequestAccess)
		}

		// Workspace admission management
		if services.AdmissionRepo != nil {
			admHandler := NewWorkspaceAdmissionHandler(services.AdmissionRepo, services.Audit)
			r.Post("/{id}/admissions", admHandler.Grant)
			r.Get("/{id}/admissions", admHandler.List)
			r.Get("/{id}/admissions/{identityId}", admHandler.GetStatus)
			r.Delete("/{id}/admissions/{identityId}", admHandler.Revoke)
		}
	})
}

// registerFederationRoutes registers federation endpoints.
func registerFederationRoutes(r chi.Router, services *Services) {
	if services == nil || services.Federation == nil {
		return
	}
	var opts []func(*FederationHandler)
	if services.Policy != nil {
		opts = append(opts, WithFederationPolicyService(services.Policy))
	}
	handler := NewFederationHandler(services.Federation, opts...)
	r.Route("/api/v1/federation", func(r chi.Router) {
		r.Post("/init", handler.Init)
		r.Post("/establish", handler.Establish)
		r.Get("/", handler.List)
		r.Get("/{partnerId}", handler.Status)
		r.Delete("/{partnerId}", handler.Revoke)
		r.Get("/health", handler.HealthCheck)
		r.Post("/certificate/import", handler.ImportCertificate)
		r.Post("/{partnerId}/renew-cert", handler.RenewCertificate)
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

		// Generation ceremony (password-protected shares)
		if services.CRKGenerationCeremony != nil {
			genHandler := NewGenerationCeremonyHandler(services.CRKGenerationCeremony)
			r.Post("/generate-ceremony/start", genHandler.Start)
			r.Post("/generate-ceremony/{id}/seed", genHandler.Seed)
			r.Post("/generate-ceremony/{id}/complete", genHandler.Complete)
			r.Get("/generate-ceremony/{id}", genHandler.Status)
			r.Delete("/generate-ceremony/{id}", genHandler.Cancel)
			r.Get("/shares/{crkId}/{index}", genHandler.GetEncryptedShare)
		}
	})
}

// registerIdentityRoutes registers identity management endpoints.
func registerIdentityRoutes(r chi.Router, services *Services) {
	if services == nil || services.Identity == nil {
		return
	}
	// Wire policy evaluator for OPA-filtered group listing
	if services.Policy != nil {
		services.Identity.SetPolicyEvaluator(&policyServiceAdapter{svc: services.Policy})
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
		r.Put("/groups/{id}", handler.UpdateGroup)
		r.Post("/groups/{id}/members", handler.AddGroupMember)
		r.Delete("/groups/{id}/members/{identityId}", handler.RemoveGroupMember)

		// Group join requests
		r.Post("/groups/{id}/join-requests", handler.RequestGroupJoin)
		r.Get("/groups/{id}/join-requests", handler.ListGroupJoinRequests)
		r.Post("/groups/{id}/join-requests/{requestId}/approve", handler.ApproveJoinRequest)
		r.Post("/groups/{id}/join-requests/{requestId}/deny", handler.DenyJoinRequest)

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

// registerBackupRoutes registers backup/restore endpoints.
func registerBackupRoutes(r chi.Router, services *Services) {
	if services == nil || services.Backup == nil {
		return
	}
	handler := NewBackupHandler(services.Backup)
	r.Route("/api/v1/backups", func(r chi.Router) {
		r.Post("/", handler.Create)
		r.Get("/", handler.List)
		r.Get("/{id}", handler.Get)
		r.Post("/{id}/restore", handler.Restore)
	})
}

// registerMessageRoutes registers direct messaging endpoints.
func registerMessageRoutes(r chi.Router, services *Services) {
	if services == nil || services.Messaging == nil {
		return
	}
	handler := NewDirectMessageHandler(services.Messaging)
	r.Route("/api/v1/messages", func(r chi.Router) {
		r.Post("/", handler.Send)
		r.Get("/", handler.ListInbox)
		r.Get("/sent", handler.ListSent)
		r.Get("/{id}", handler.Read)
		r.Delete("/{id}", handler.Delete)
		r.Post("/deliver", handler.Deliver)
	})
}

// registerActivityRoutes registers user activity endpoints.
func registerActivityRoutes(r chi.Router, services *Services) {
	if services == nil || services.Audit == nil {
		return
	}
	handler := NewActivityHandler(services.Audit)
	r.Route("/api/v1/activity", func(r chi.Router) {
		r.Get("/", handler.List)
		r.Post("/export", handler.Export)
	})
}

// registerWorkspaceRequestRoutes registers workspace request endpoints.
func registerWorkspaceRequestRoutes(r chi.Router, services *Services) {
	if services == nil || services.WorkspaceRequest == nil {
		return
	}
	handler := NewWorkspaceRequestHandler(services.WorkspaceRequest)
	r.Route("/api/v1/workspace-requests", func(r chi.Router) {
		r.Post("/", handler.Create)
		r.Get("/", handler.ListMyRequests)
		r.Get("/pending", handler.ListPendingRequests)
		r.Get("/{requestId}", handler.GetRequest)
		r.Post("/{requestId}/approve", handler.ApproveRequest)
		r.Post("/{requestId}/deny", handler.DenyRequest)
	})

	// Register workspace relay handler for incoming federation messages
	relayHandler := NewWorkspaceRelayHandler(services.WorkspaceRequest)
	r.Post("/api/v1/workspace-relay", relayHandler.Handle)
}

// registerFederationRequestRoutes registers federation request endpoints.
func registerFederationRequestRoutes(r chi.Router, services *Services) {
	if services == nil || services.WorkspaceRequest == nil {
		return
	}
	handler := NewFederationRequestHandler(services.WorkspaceRequest)
	r.Route("/api/v1/federation-requests", func(r chi.Router) {
		r.Post("/", handler.Create)
		r.Get("/pending", handler.ListPending)
		r.Get("/{requestId}", handler.Get)
		r.Post("/{requestId}/approve", handler.Approve)
		r.Post("/{requestId}/deny", handler.Deny)
	})
}

// registerGroupFederationCouplingRoutes registers group-federation coupling endpoints.
func registerGroupFederationCouplingRoutes(r chi.Router, services *Services) {
	if services == nil || services.GroupFederationCouplings == nil {
		return
	}
	handler := NewGroupFederationCouplingHandler(services.GroupFederationCouplings)
	r.Get("/api/v1/group-federation-couplings", handler.List)
}

// policyServiceAdapter adapts policy.Service to identity.PolicyEvaluator.
type policyServiceAdapter struct {
	svc policy.Service
}

func (a *policyServiceAdapter) Evaluate(ctx context.Context, input models.PolicyInput) (*identity.PolicyEvaluationResult, error) {
	result, err := a.svc.Evaluate(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("evaluate policy: %w", err)
	}
	return &identity.PolicyEvaluationResult{
		Allowed:    result.Allowed,
		DenyReason: result.DenyReason,
	}, nil
}
