package workspace

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/witlox/sovra/pkg/models"
)

// requestService implements WorkspaceRequestService.
type requestService struct {
	requests   WorkspaceRequestRepository
	fedReqs    FederationRequestRepository
	couplings  GroupFederationCouplingRepository
	workspace  Service
	federation FederationRelay
	audit      AuditService
}

// NewWorkspaceRequestService creates a new workspace request service.
func NewWorkspaceRequestService(
	requests WorkspaceRequestRepository,
	fedReqs FederationRequestRepository,
	couplings GroupFederationCouplingRepository,
	workspace Service,
	federation FederationRelay,
	audit AuditService,
) WorkspaceRequestService {
	return &requestService{
		requests:   requests,
		fedReqs:    fedReqs,
		couplings:  couplings,
		workspace:  workspace,
		federation: federation,
		audit:      audit,
	}
}

func (s *requestService) CreateRequest(ctx context.Context, input CreateWorkspaceRequestInput) (*models.WorkspaceRequest, error) {
	if input.GroupID == "" {
		return nil, fmt.Errorf("group_id is required")
	}
	if input.OrgID == "" {
		return nil, fmt.Errorf("org_id is required")
	}

	req := &models.WorkspaceRequest{
		ID:                  uuid.New().String(),
		RequesterID:         input.RequesterID,
		OrgID:               input.OrgID,
		GroupID:             input.GroupID,
		FederationID:        input.FederationID,
		TargetOrgID:         input.TargetOrgID,
		Locked:              input.Locked,
		FederationRequested: input.FederationRequested,
		Justification:       input.Justification,
		Status:              models.WorkspaceRequestStatusPending,
		CreatedAt:           time.Now(),
	}

	if err := s.requests.Create(ctx, req); err != nil {
		return nil, fmt.Errorf("create workspace request: %w", err)
	}

	// If federation requested, create a separate federation request
	if input.FederationRequested && input.TargetOrgID != "" {
		fedReq := &models.FederationRequest{
			ID:            uuid.New().String(),
			RequesterID:   input.RequesterID,
			OrgID:         input.OrgID,
			TargetOrgID:   input.TargetOrgID,
			Justification: input.Justification,
			Status:        models.FederationRequestStatusPending,
			CreatedAt:     time.Now(),
		}
		if err := s.fedReqs.Create(ctx, fedReq); err != nil {
			return nil, fmt.Errorf("create federation request: %w", err)
		}
	}

	s.auditLog(ctx, req.OrgID, models.AuditEventTypeWorkspaceRequest, map[string]any{
		"request_id":   req.ID,
		"requester_id": req.RequesterID,
		"group_id":     req.GroupID,
	})

	return req, nil
}

func (s *requestService) ListPendingRequests(ctx context.Context, orgID string) ([]*models.WorkspaceRequest, error) {
	reqs, err := s.requests.ListPending(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("list pending requests: %w", err)
	}
	return reqs, nil
}

func (s *requestService) ListMyRequests(ctx context.Context, requesterID string) ([]*models.WorkspaceRequest, error) {
	reqs, err := s.requests.ListByRequester(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("list requests by requester: %w", err)
	}
	return reqs, nil
}

func (s *requestService) GetRequest(ctx context.Context, id string) (*models.WorkspaceRequest, error) {
	req, err := s.requests.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get request: %w", err)
	}
	return req, nil
}

func (s *requestService) ApproveRequest(ctx context.Context, requestID, adminID string, crkSig []byte) (*models.Workspace, error) {
	req, err := s.requests.Get(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("get request: %w", err)
	}
	if req.Status != models.WorkspaceRequestStatusPending {
		return nil, fmt.Errorf("request is not pending")
	}

	// Determine participants
	participants := []string{req.OrgID}
	if req.TargetOrgID != "" {
		participants = append(participants, req.TargetOrgID)
	}

	// Create group-federation coupling if federation is involved
	if req.FederationID != "" {
		existing, _ := s.couplings.GetByGroupAndFederation(ctx, req.GroupID, req.FederationID)
		if existing == nil {
			coupling := &models.GroupFederationCoupling{
				ID:           uuid.New().String(),
				GroupID:      req.GroupID,
				FederationID: req.FederationID,
				OrgID:        req.OrgID,
				CreatedAt:    time.Now(),
			}
			if err := s.couplings.Create(ctx, coupling); err != nil {
				return nil, fmt.Errorf("create coupling: %w", err)
			}
		}
	}

	// Determine if this is bilateral
	bilateral := req.TargetOrgID != "" && req.FederationID != ""

	// Determine initial status
	status := models.WorkspaceStatusActive
	if bilateral {
		status = models.WorkspaceStatusPendingPairing
	}

	// Create workspace
	groupPrefix := req.GroupID
	if len(groupPrefix) > 8 {
		groupPrefix = groupPrefix[:8]
	}
	idPrefix := req.ID
	if len(idPrefix) > 8 {
		idPrefix = idPrefix[:8]
	}
	ws, err := s.workspace.Create(ctx, CreateRequest{
		Name:           fmt.Sprintf("ws-%s-%s", groupPrefix, idPrefix),
		Participants:   participants,
		Classification: models.ClassificationConfidential,
		Mode:           models.WorkspaceModeConnected,
		CRKSignature:   crkSig,
	})
	if err != nil {
		return nil, fmt.Errorf("create workspace: %w", err)
	}

	// Set bilateral and federation fields
	ws.FederationID = req.FederationID
	ws.Bilateral = bilateral
	ws.Status = status

	// Update request
	req.Status = models.WorkspaceRequestStatusApproved
	req.ReviewedBy = adminID
	req.WorkspaceID = ws.ID
	req.ReviewedAt = time.Now()
	if err := s.requests.Update(ctx, req); err != nil {
		return nil, fmt.Errorf("update request: %w", err)
	}

	// For bilateral workspaces, relay pairing request to partner
	if bilateral && s.federation != nil {
		payload, _ := json.Marshal(map[string]any{
			"type":          "workspace_pairing_request",
			"workspace_id":  ws.ID,
			"federation_id": req.FederationID,
			"locked":        req.Locked,
			"org_id":        req.OrgID,
		})
		_, _ = s.federation.RelayMessage(ctx, req.TargetOrgID, payload)
	}

	s.auditLog(ctx, req.OrgID, models.AuditEventTypeWorkspaceRequestApprove, map[string]any{
		"request_id":   req.ID,
		"workspace_id": ws.ID,
		"admin_id":     adminID,
		"bilateral":    bilateral,
	})

	return ws, nil
}

func (s *requestService) DenyRequest(ctx context.Context, requestID, adminID, reason string) error {
	req, err := s.requests.Get(ctx, requestID)
	if err != nil {
		return fmt.Errorf("get request: %w", err)
	}
	if req.Status != models.WorkspaceRequestStatusPending {
		return fmt.Errorf("request is not pending")
	}

	req.Status = models.WorkspaceRequestStatusDenied
	req.ReviewedBy = adminID
	req.ReviewedAt = time.Now()
	if err := s.requests.Update(ctx, req); err != nil {
		return fmt.Errorf("update request: %w", err)
	}

	s.auditLog(ctx, req.OrgID, models.AuditEventTypeWorkspaceRequestDeny, map[string]any{
		"request_id": req.ID,
		"admin_id":   adminID,
		"reason":     reason,
	})

	return nil
}

func (s *requestService) HandlePairingRequest(ctx context.Context, payload []byte) error {
	var msg struct {
		Type         string `json:"type"`
		WorkspaceID  string `json:"workspace_id"`
		FederationID string `json:"federation_id"`
		Locked       bool   `json:"locked"`
		OrgID        string `json:"org_id"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		return fmt.Errorf("unmarshal pairing request: %w", err)
	}

	// Create a local workspace request for admin approval
	req := &models.WorkspaceRequest{
		ID:           uuid.New().String(),
		RequesterID:  "remote:" + msg.OrgID,
		OrgID:        msg.OrgID,
		FederationID: msg.FederationID,
		Locked:       msg.Locked,
		WorkspaceID:  msg.WorkspaceID,
		Status:       models.WorkspaceRequestStatusPending,
		CreatedAt:    time.Now(),
	}

	if err := s.requests.Create(ctx, req); err != nil {
		return fmt.Errorf("create pairing request: %w", err)
	}

	s.auditLog(ctx, msg.OrgID, models.AuditEventTypeWorkspacePair, map[string]any{
		"workspace_id":  msg.WorkspaceID,
		"federation_id": msg.FederationID,
		"remote_org":    msg.OrgID,
	})

	return nil
}

func (s *requestService) HandleArchiveNotification(ctx context.Context, payload []byte) error {
	var msg struct {
		Type        string `json:"type"`
		WorkspaceID string `json:"workspace_id"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		return fmt.Errorf("unmarshal archive notification: %w", err)
	}

	if err := s.workspace.Archive(ctx, msg.WorkspaceID, nil); err != nil {
		return fmt.Errorf("archive workspace: %w", err)
	}

	s.auditLog(ctx, "", models.AuditEventTypeWorkspaceArchiveRemote, map[string]any{
		"workspace_id": msg.WorkspaceID,
	})

	return nil
}

func (s *requestService) auditLog(ctx context.Context, orgID string, eventType models.AuditEventType, metadata map[string]any) {
	if s.audit == nil {
		return
	}
	event := &models.AuditEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		OrgID:     orgID,
		EventType: eventType,
		Result:    models.AuditEventResultSuccess,
		Metadata:  metadata,
	}
	_ = s.audit.Log(ctx, event)
}
