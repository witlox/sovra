// Package main implements the Sovra API Gateway service.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/witlox/sovra/internal/api"
	"github.com/witlox/sovra/internal/audit"
	"github.com/witlox/sovra/internal/backup"
	"github.com/witlox/sovra/internal/compliance"
	"github.com/witlox/sovra/internal/config"
	"github.com/witlox/sovra/internal/crk"
	"github.com/witlox/sovra/internal/edge"
	"github.com/witlox/sovra/internal/federation"
	"github.com/witlox/sovra/internal/identity"
	"github.com/witlox/sovra/internal/identity/idp"
	"github.com/witlox/sovra/internal/identity/sync"
	"github.com/witlox/sovra/internal/messaging"
	"github.com/witlox/sovra/internal/policy"
	"github.com/witlox/sovra/internal/reconciliation"
	"github.com/witlox/sovra/internal/rotation"
	"github.com/witlox/sovra/internal/workspace"
	"github.com/witlox/sovra/pkg/metrics"
	"github.com/witlox/sovra/pkg/models"
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

	crkRepo := postgres.NewCRKRepository(db)

	invitationRepo := postgres.NewWorkspaceInvitationRepository(db)
	groupBindingRepo := postgres.NewWorkspaceGroupBindingRepository(db)
	admissionRepo := postgres.NewWorkspaceAdmissionRepository(db)

	auditSvc := audit.NewAuditService(auditRepo)
	wsSvc := workspace.NewWorkspaceService(wsRepo, vaultClient, auditSvc, invitationRepo)

	// Wire air-gap cross-org DEK wrapping support
	wsSvc.SetFederationLookup(&workspace.FederationLookupAdapter{Repo: fedRepo})
	wsSvc.SetPrivateKeyStore(&workspace.VaultPrivateKeyStore{KV: vaultClient.KV("secret")})

	// Federation CRK verifier adapter
	transitClient := vaultClient.Transit(transitMountPath)
	fedCRKVerifier := &federationCRKVerifier{transit: transitClient}
	fedSvc := federation.NewFederationService(fedRepo, vaultClient, auditSvc, fedCRKVerifier)
	policySvc := policy.NewPolicyService(policyRepo, opaClient, auditSvc)
	crkMgr := crk.NewManagerWithRepo(crkRepo)
	crkCeremony := crk.NewCeremonyManager(crkMgr)

	encShareRepo := postgres.NewEncryptedShareRepository(db)
	genCeremonyMgr := crk.NewGenerationCeremonyManagerWithRepo(crkMgr, encShareRepo)

	// VaultFactory creates vault clients for edge nodes
	vaultFactory := func(address, token string) (*vault.Client, error) {
		return vault.NewClient(vault.Config{Address: address, Token: token})
	}
	edgeSvc := edge.NewEdgeService(edgeRepo, vaultFactory, auditSvc)

	adminRepo := postgres.NewAdminIdentityRepository(db)
	userRepo := postgres.NewUserIdentityRepository(db)
	serviceRepo := postgres.NewServiceIdentityRepository(db)
	deviceRepo := postgres.NewDeviceIdentityRepository(db)
	groupRepo := postgres.NewIdentityGroupRepository(db)
	roleRepo := postgres.NewRoleRepository(db)

	// PKI client for certificate management
	pkiClient := vaultClient.PKI("")

	// CRK provider adapter (shared by identity manager, emergency access, account recovery)
	crkProvider := &identity.CRKProviderAdapter{
		GetByOrgIDFn: crkRepo.GetByOrgID,
		VerifyFn:     crkMgr.Verify,
	}

	// PKI issuer adapter for admin certificate lifecycle
	pkiIssuer := &identity.PKIIssuerAdapter{
		IssueFn: func(ctx context.Context, role, cn string, altNames []string, ttl time.Duration) (*identity.PKICertResult, error) {
			cert, err := pkiClient.IssueCertificate(ctx, role, &vault.CertificateRequest{
				CommonName: cn,
				AltNames:   altNames,
				TTL:        ttl,
			})
			if err != nil {
				return nil, fmt.Errorf("pki issue certificate: %w", err)
			}
			return &identity.PKICertResult{
				Certificate:  cert.Certificate,
				CertKey:      cert.PrivateKey,
				SerialNumber: cert.SerialNumber,
				Expiration:   cert.Expiration,
			}, nil
		},
		RevokeFn: pkiClient.RevokeCertificate,
	}

	identityMgr := identity.NewManagerWithAdminSecurity(
		adminRepo, userRepo, serviceRepo, deviceRepo, groupRepo, roleRepo,
		crkProvider, identity.NewSimpleTokenGenerator(), pkiIssuer, auditSvc,
	)

	// Configure IdP checker and reconciliation scheduler
	var reconciler *reconciliation.Scheduler
	var groupSyncer *sync.Scheduler
	if cfg.Admin.IDPIssuerURL != "" {
		idpChecker, err := idp.NewOIDCChecker(idp.OIDCCheckerConfig{
			IssuerURL:  cfg.Admin.IDPIssuerURL,
			ClientID:   cfg.Admin.IDPClientID,
			OIDCSecret: cfg.Admin.IDPOIDCSecret,
		})
		if err != nil {
			logger.Error("failed to create IdP checker", "error", err)
			os.Exit(1)
		}
		identityMgr.SetIDPChecker(idpChecker)
		identityMgr.SetCertTTL(cfg.Admin.CertTTL)
		logger.Info("admin IdP integration enabled",
			"cert_ttl", cfg.Admin.CertTTL,
			"idp_issuer", cfg.Admin.IDPIssuerURL)

		if cfg.Admin.ReconciliationEnabled {
			reconciler = reconciliation.NewScheduler(
				adminRepo, idpChecker, identityMgr.DisableAdmin, auditSvc,
				cfg.Admin.ReconciliationInterval,
			)
			// Enable user reconciliation
			reconciler.SetUserReconciliation(userRepo, identityMgr.DisableUser)
			go reconciler.Start(ctx)
			logger.Info("IdP reconciliation enabled (admins + users)",
				"interval", cfg.Admin.ReconciliationInterval)
		}

		// Group membership sync
		if cfg.Admin.GroupSyncEnabled {
			groupChecker, err := idp.NewOIDCGroupChecker(idp.OIDCGroupCheckerConfig{
				IssuerURL:             cfg.Admin.IDPIssuerURL,
				ClientID:              cfg.Admin.IDPClientID,
				OIDCSecret:            cfg.Admin.IDPOIDCSecret,
				GroupEndpointTemplate: cfg.Admin.IDPGroupEndpoint,
			})
			if err != nil {
				logger.Error("failed to create IdP group checker", "error", err)
				os.Exit(1)
			}
			groupSyncer = sync.NewScheduler(
				groupRepo, groupChecker, auditSvc,
				cfg.Admin.GroupSyncInterval,
			)
			go groupSyncer.Start(ctx)
			logger.Info("IdP group sync enabled", "interval", cfg.Admin.GroupSyncInterval)
		}
	} else {
		// No IdP configured — air-gap mode assumption.
		// Use extended cert TTL unless the operator explicitly overrode it.
		airgapCertTTL := cfg.Admin.CertTTL
		if cfg.Admin.CertTTL == 24*time.Hour {
			// Default value was not overridden — extend for air-gap
			airgapCertTTL = 8760 * time.Hour
		}
		identityMgr.SetCertTTL(airgapCertTTL)

		logger.Warn("no admin IdP configured — assuming air-gap deployment",
			"cert_ttl", airgapCertTTL,
			"hint", "if this is not an air-gapped deployment, set admin.idp_issuer_url")

		auditSvc.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     cfg.OrgID,
			EventType: "admin.airgap.assumed",
			Actor:     "api-gateway",
			Result:    "warning",
			Metadata: map[string]any{
				"cert_ttl": airgapCertTTL.String(),
				"reason":   "no admin.idp_issuer_url configured",
				"hint":     "if this is not an air-gapped deployment, configure IdP integration",
			},
		})
	}

	// Emergency access and account recovery
	emergencyRepo := postgres.NewEmergencyAccessRepository(db)
	recoveryRepo := postgres.NewAccountRecoveryRepository(db)

	emergencyMgr := identity.NewEmergencyAccessManagerWithAudit(emergencyRepo, crkProvider, identity.NewSimpleTokenGenerator(), auditSvc)
	recoveryMgr := identity.NewAccountRecoveryManager(recoveryRepo, crkProvider)

	// Compliance report generator
	complianceGen := compliance.NewReportGenerator(auditSvc, wsSvc)

	// Rotation policy scheduler
	rotationScheduler := rotation.NewScheduler(wsSvc, time.Hour)
	rotationScheduler.Start(ctx)

	// Direct messaging service
	msgRepo := postgres.NewDirectMessageRepository(db)
	msgEncryptor := messaging.NewVaultEncryptor(vaultClient.Transit("transit"))
	msgResolver := &messaging.IdentityManagerAdapter{
		GetUserFn: func(ctx context.Context, id string) (any, error) {
			return identityMgr.GetUser(ctx, id)
		},
	}
	msgSvc := messaging.NewService(msgRepo, fedSvc, msgEncryptor, msgResolver, auditSvc)

	// Backup service with real implementation
	backupRepo := postgres.NewBackupRepository(db)
	backupCRKVerifier := &federationCRKVerifier{transit: transitClient}
	backupOrgRepo := postgres.NewOrganizationRepository(db)
	backupSvc := backup.NewService(backupRepo, backupCRKVerifier, transitClient, backupOrgRepo, wsRepo, fedRepo, policyRepo, auditSvc)

	services := &api.Services{
		Workspace:             wsSvc,
		Federation:            fedSvc,
		Policy:                policySvc,
		Audit:                 auditSvc,
		Edge:                  edgeSvc,
		CRKManager:            crkMgr,
		CRKCeremony:           crkCeremony,
		CRKGenerationCeremony: genCeremonyMgr,
		Identity:              identityMgr,
		PKI:                   pkiClient,
		EmergencyAccess:       emergencyMgr,
		AccountRecovery:       recoveryMgr,
		Compliance:            complianceGen,
		RotationScheduler:     rotationScheduler,
		Messaging:             msgSvc,
		Backup:                backupSvc,
		GroupBindingRepo:      groupBindingRepo,
		AdmissionRepo:         admissionRepo,
	}

	svcMetrics := metrics.NewServiceMetrics("api_gateway", version)

	routerCfg := api.DefaultRouterConfig()
	routerCfg.Logger = logger
	routerCfg.AdminIdentityResolver = &adminResolverAdapter{mgr: identityMgr}
	routerCfg.ServiceMetrics = svcMetrics
	routerCfg.ServiceName = cfg.Telemetry.ServiceName

	// Register health checkers for critical dependencies
	routerCfg.HealthCheckers["database"] = func() error {
		return db.PingContext(ctx)
	}
	routerCfg.HealthCheckers["vault"] = func() error {
		_, err := vaultClient.Health(ctx)
		if err != nil {
			return fmt.Errorf("vault health check: %w", err)
		}
		return nil
	}

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
	rotationScheduler.Stop()
	if reconciler != nil {
		reconciler.Stop()
	}
	if groupSyncer != nil {
		groupSyncer.Stop()
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
	logger.Info("shutdown complete")
}

// adminResolverAdapter adapts identity.Manager to api.AdminIdentityResolver.
type adminResolverAdapter struct {
	mgr *identity.Manager
}

func (a *adminResolverAdapter) GetAdminByCertCN(ctx context.Context, cn string) (*api.AdminCertIdentity, error) {
	admin, err := a.mgr.GetAdminByCertCN(ctx, cn)
	if err != nil {
		return nil, fmt.Errorf("get admin by cert CN: %w", err)
	}
	if admin == nil {
		return nil, nil
	}
	return &api.AdminCertIdentity{
		AdminID: admin.ID,
		OrgID:   admin.OrgID,
		Active:  admin.Active,
	}, nil
}

const transitMountPath = "transit"

// federationCRKVerifier adapts Vault transit to federation.SignatureVerifier.
type federationCRKVerifier struct {
	transit *vault.TransitClient
}

func (v *federationCRKVerifier) VerifyCRKSignature(ctx context.Context, orgID string, data, signature []byte) (bool, error) {
	keyName := "crk-" + orgID
	valid, err := v.transit.Verify(ctx, keyName, data, string(signature))
	if err != nil {
		return false, fmt.Errorf("verify CRK signature: %w", err)
	}
	return valid, nil
}
