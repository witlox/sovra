// Package sync provides background IdP group membership synchronization.
package sync

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/witlox/sovra/internal/identity"
	"github.com/witlox/sovra/internal/identity/idp"
	"github.com/witlox/sovra/pkg/models"
)

// Scheduler periodically syncs group membership from an external IdP.
// Groups with a non-empty IDPGroupID are synced; members not in IdP are removed,
// new members in IdP are added.
type Scheduler struct {
	groups   identity.GroupRepository
	checker  idp.GroupMemberChecker
	auditor  identity.Auditor
	stopCh   chan struct{}
	interval time.Duration
	logger   *slog.Logger
}

// NewScheduler creates a new group sync scheduler.
func NewScheduler(
	groups identity.GroupRepository,
	checker idp.GroupMemberChecker,
	auditor identity.Auditor,
	interval time.Duration,
) *Scheduler {
	return &Scheduler{
		groups:   groups,
		checker:  checker,
		auditor:  auditor,
		stopCh:   make(chan struct{}),
		interval: interval,
		logger:   slog.Default(),
	}
}

// Start begins the sync loop.
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
			s.syncGroups(ctx)
		}
	}
}

// Stop stops the scheduler loop.
func (s *Scheduler) Stop() {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
}

func (s *Scheduler) syncGroups(ctx context.Context) {
	// List all groups — we filter by IDPGroupID below.
	// Use empty orgID to list all orgs.
	groups, err := s.groups.List(ctx, "")
	if err != nil {
		s.logger.ErrorContext(ctx, "group sync: list groups", "error", err)
		return
	}

	for _, group := range groups {
		if group.IDPGroupID == "" {
			continue
		}
		s.syncGroup(ctx, group)
	}
}

func (s *Scheduler) syncGroup(ctx context.Context, group *models.IdentityGroup) {
	idpMembers, err := s.checker.GetGroupMembers(ctx, group.IDPGroupID)
	if err != nil {
		// Fail-open: IdP unreachable → don't remove anyone
		s.logger.WarnContext(ctx, "group sync: IdP unreachable, skipping group",
			"group_id", group.ID, "idp_group_id", group.IDPGroupID, "error", err)
		return
	}

	currentMembers, err := s.groups.GetMembers(ctx, group.ID)
	if err != nil {
		s.logger.ErrorContext(ctx, "group sync: get current members", "group_id", group.ID, "error", err)
		return
	}

	// Build lookup maps
	idpSet := make(map[string]bool, len(idpMembers))
	for _, subject := range idpMembers {
		idpSet[subject] = true
	}

	currentSet := make(map[string]*models.GroupMembership, len(currentMembers))
	for _, m := range currentMembers {
		currentSet[m.IdentityID] = m
	}

	// Remove members not in IdP
	for _, m := range currentMembers {
		if !idpSet[m.IdentityID] {
			if err := s.groups.RemoveMember(ctx, group.ID, m.IdentityID); err != nil {
				s.logger.ErrorContext(ctx, "group sync: remove member", "group_id", group.ID, "identity_id", m.IdentityID, "error", err)
				continue
			}
			s.logger.InfoContext(ctx, "group sync: removed member",
				"group_id", group.ID, "identity_id", m.IdentityID)
			s.auditLog(ctx, group.OrgID, string(models.AuditEventTypeGroupMemberRemove), map[string]any{
				"group_id":    group.ID,
				"identity_id": m.IdentityID,
				"source":      "idp_sync",
			})
		}
	}

	// Add members in IdP but not in Sovra
	for _, subject := range idpMembers {
		if _, exists := currentSet[subject]; !exists {
			membership := &models.GroupMembership{
				GroupID:      group.ID,
				IdentityID:   subject,
				IdentityType: models.IdentityTypeUser,
				JoinedAt:     time.Now(),
			}
			if err := s.groups.AddMember(ctx, membership); err != nil {
				s.logger.ErrorContext(ctx, "group sync: add member", "group_id", group.ID, "identity_id", subject, "error", err)
				continue
			}
			s.logger.InfoContext(ctx, "group sync: added member",
				"group_id", group.ID, "identity_id", subject)
			s.auditLog(ctx, group.OrgID, string(models.AuditEventTypeGroupMemberAdd), map[string]any{
				"group_id":    group.ID,
				"identity_id": subject,
				"source":      "idp_sync",
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
		Actor:     "group-sync-scheduler",
		Result:    models.AuditEventResult("success"),
		Metadata:  metadata,
	})
}
