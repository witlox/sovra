// Package reconciliation provides background IdP reconciliation for SSO-bound admins.
package reconciliation

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/witlox/sovra/internal/identity"
	"github.com/witlox/sovra/internal/identity/idp"
	"github.com/witlox/sovra/pkg/models"
)

// Scheduler periodically checks SSO-bound admin and user identities against the IdP
// and disables any whose subjects are no longer active.
type Scheduler struct {
	admins        identity.AdminRepository
	users         identity.UserRepository
	checker       idp.SubjectChecker
	disableFn     func(ctx context.Context, adminID string) error
	disableUserFn func(ctx context.Context, userID string) error
	auditor       identity.Auditor
	stopCh        chan struct{}
	interval      time.Duration
	logger        *slog.Logger
}

// NewScheduler creates a new reconciliation scheduler.
func NewScheduler(
	admins identity.AdminRepository,
	checker idp.SubjectChecker,
	disableFn func(ctx context.Context, adminID string) error,
	auditor identity.Auditor,
	interval time.Duration,
) *Scheduler {
	return &Scheduler{
		admins:    admins,
		checker:   checker,
		disableFn: disableFn,
		auditor:   auditor,
		stopCh:    make(chan struct{}),
		interval:  interval,
		logger:    slog.Default(),
	}
}

// SetUserReconciliation enables user identity reconciliation.
func (s *Scheduler) SetUserReconciliation(users identity.UserRepository, disableUserFn func(ctx context.Context, userID string) error) {
	s.users = users
	s.disableUserFn = disableUserFn
}

// Start begins the reconciliation loop.
func (s *Scheduler) Start(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.reconcile(ctx)
		}
	}
}

// Stop stops the scheduler loop.
func (s *Scheduler) Stop() {
	select {
	case <-s.stopCh:
		// already closed
	default:
		close(s.stopCh)
	}
}

func (s *Scheduler) reconcile(ctx context.Context) {
	s.reconcileAdmins(ctx)
	s.reconcileUsers(ctx)
}

func (s *Scheduler) reconcileAdmins(ctx context.Context) {
	admins, err := s.admins.ListActiveSSOBound(ctx)
	if err != nil {
		s.logger.ErrorContext(ctx, "reconciliation: list SSO-bound admins", "error", err)
		return
	}

	for _, admin := range admins {
		status := s.checker.CheckSubject(ctx, admin.SSOSubject)

		if status.Error != nil {
			s.logger.WarnContext(ctx, "reconciliation: IdP unreachable, skipping admin",
				"admin_id", admin.ID, "sso_subject", admin.SSOSubject, "error", status.Error)
			continue
		}

		if !status.Active {
			s.logger.InfoContext(ctx, "reconciliation: disabling admin, SSO subject not found",
				"admin_id", admin.ID, "sso_subject", admin.SSOSubject)
			if err := s.disableFn(ctx, admin.ID); err != nil {
				s.logger.ErrorContext(ctx, "reconciliation: disable admin failed",
					"admin_id", admin.ID, "error", err)
				continue
			}
			s.auditLog(ctx, admin.OrgID, "admin.reconciliation.disabled", map[string]any{
				"admin_id":    admin.ID,
				"sso_subject": admin.SSOSubject,
				"reason":      "SSO subject no longer active in IdP",
			})
		}
	}
}

func (s *Scheduler) reconcileUsers(ctx context.Context) {
	if s.users == nil || s.disableUserFn == nil {
		return
	}

	users, err := s.users.ListActiveSSOBound(ctx)
	if err != nil {
		s.logger.ErrorContext(ctx, "reconciliation: list SSO-bound users", "error", err)
		return
	}

	for _, user := range users {
		status := s.checker.CheckSubject(ctx, user.SSOSubject)

		if status.Error != nil {
			s.logger.WarnContext(ctx, "reconciliation: IdP unreachable, skipping user",
				"user_id", user.ID, "sso_subject", user.SSOSubject, "error", status.Error)
			continue
		}

		if !status.Active {
			s.logger.InfoContext(ctx, "reconciliation: disabling user, SSO subject not found",
				"user_id", user.ID, "sso_subject", user.SSOSubject)
			if err := s.disableUserFn(ctx, user.ID); err != nil {
				s.logger.ErrorContext(ctx, "reconciliation: disable user failed",
					"user_id", user.ID, "error", err)
				continue
			}
			s.auditLog(ctx, user.OrgID, string(models.AuditEventTypeUserReconcileDisabled), map[string]any{
				"user_id":     user.ID,
				"sso_subject": user.SSOSubject,
				"reason":      "SSO subject no longer active in IdP",
			})
		}
	}
}

func (s *Scheduler) auditLog(ctx context.Context, orgID, eventType string, metadata map[string]any) {
	if s.auditor == nil {
		return
	}
	_ = s.auditor.Log(ctx, &models.AuditEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		OrgID:     orgID,
		EventType: models.AuditEventType(eventType),
		Actor:     "reconciliation-scheduler",
		Result:    models.AuditEventResult("success"),
		Metadata:  metadata,
	})
}
