package workspace_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/workspace"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/tests/testutil/inmemory"
)

func createRequestTestService() (workspace.WorkspaceRequestService, *inmemory.WorkspaceRequestRepository, workspace.Service) {
	wsRepo := inmemory.NewWorkspaceRepository()
	keyMgr := inmemory.NewWorkspaceKeyManager()
	crypto := inmemory.NewWorkspaceCryptoService()
	wsSvc := workspace.NewService(wsRepo, keyMgr, crypto)

	reqRepo := inmemory.NewWorkspaceRequestRepository()
	fedReqRepo := inmemory.NewFederationRequestRepository()
	couplingRepo := inmemory.NewGroupFederationCouplingRepository()

	svc := workspace.NewWorkspaceRequestService(reqRepo, fedReqRepo, couplingRepo, wsSvc, nil, nil)
	return svc, reqRepo, wsSvc
}

func TestCreateWorkspaceRequest(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := createRequestTestService()

	t.Run("creates request with valid input", func(t *testing.T) {
		req, err := svc.CreateRequest(ctx, workspace.CreateWorkspaceRequestInput{
			RequesterID:   "user-1",
			OrgID:         "org-eth",
			GroupID:       "group-research",
			Justification: "Need workspace for research collaboration",
		})

		require.NoError(t, err)
		assert.NotEmpty(t, req.ID)
		assert.Equal(t, "user-1", req.RequesterID)
		assert.Equal(t, "org-eth", req.OrgID)
		assert.Equal(t, "group-research", req.GroupID)
		assert.Equal(t, models.WorkspaceRequestStatusPending, req.Status)
	})

	t.Run("fails without group_id", func(t *testing.T) {
		_, err := svc.CreateRequest(ctx, workspace.CreateWorkspaceRequestInput{
			RequesterID: "user-1",
			OrgID:       "org-eth",
		})
		require.Error(t, err)
	})

	t.Run("fails without org_id", func(t *testing.T) {
		_, err := svc.CreateRequest(ctx, workspace.CreateWorkspaceRequestInput{
			RequesterID: "user-1",
			GroupID:     "group-1",
		})
		require.Error(t, err)
	})
}

func TestListWorkspaceRequests(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := createRequestTestService()

	// Create some requests
	_, _ = svc.CreateRequest(ctx, workspace.CreateWorkspaceRequestInput{
		RequesterID: "user-1",
		OrgID:       "org-eth",
		GroupID:     "group-1",
	})
	_, _ = svc.CreateRequest(ctx, workspace.CreateWorkspaceRequestInput{
		RequesterID: "user-2",
		OrgID:       "org-eth",
		GroupID:     "group-2",
	})
	_, _ = svc.CreateRequest(ctx, workspace.CreateWorkspaceRequestInput{
		RequesterID: "user-1",
		OrgID:       "org-uzh",
		GroupID:     "group-3",
	})

	t.Run("lists pending requests for org", func(t *testing.T) {
		pending, err := svc.ListPendingRequests(ctx, "org-eth")
		require.NoError(t, err)
		assert.Len(t, pending, 2)
	})

	t.Run("lists requests by requester", func(t *testing.T) {
		mine, err := svc.ListMyRequests(ctx, "user-1")
		require.NoError(t, err)
		assert.Len(t, mine, 2)
	})
}

func TestApproveWorkspaceRequest(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := createRequestTestService()

	t.Run("approve creates workspace", func(t *testing.T) {
		req, err := svc.CreateRequest(ctx, workspace.CreateWorkspaceRequestInput{
			RequesterID: "user-1",
			OrgID:       "org-eth",
			GroupID:     "group-research",
		})
		require.NoError(t, err)

		ws, err := svc.ApproveRequest(ctx, req.ID, "admin-1", nil)
		require.NoError(t, err)
		assert.NotNil(t, ws)
		assert.NotEmpty(t, ws.ID)

		// Verify request is updated
		updated, _ := svc.GetRequest(ctx, req.ID)
		assert.Equal(t, models.WorkspaceRequestStatusApproved, updated.Status)
		assert.Equal(t, "admin-1", updated.ReviewedBy)
		assert.Equal(t, ws.ID, updated.WorkspaceID)
	})

	t.Run("approve with federation creates bilateral workspace", func(t *testing.T) {
		req, err := svc.CreateRequest(ctx, workspace.CreateWorkspaceRequestInput{
			RequesterID:  "user-1",
			OrgID:        "org-eth",
			GroupID:      "group-research",
			FederationID: "fed-1",
			TargetOrgID:  "org-uzh",
		})
		require.NoError(t, err)

		ws, err := svc.ApproveRequest(ctx, req.ID, "admin-1", nil)
		require.NoError(t, err)
		assert.True(t, ws.Bilateral)
		assert.Equal(t, "fed-1", ws.FederationID)
		assert.Equal(t, models.WorkspaceStatusPendingPairing, ws.Status)
	})

	t.Run("cannot approve non-pending request", func(t *testing.T) {
		req, _ := svc.CreateRequest(ctx, workspace.CreateWorkspaceRequestInput{
			RequesterID: "user-1",
			OrgID:       "org-eth",
			GroupID:     "group-1",
		})
		_, _ = svc.ApproveRequest(ctx, req.ID, "admin-1", nil)

		// Try to approve again
		_, err := svc.ApproveRequest(ctx, req.ID, "admin-2", nil)
		require.Error(t, err)
	})
}

func TestDenyWorkspaceRequest(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := createRequestTestService()

	t.Run("deny updates request status", func(t *testing.T) {
		req, _ := svc.CreateRequest(ctx, workspace.CreateWorkspaceRequestInput{
			RequesterID: "user-1",
			OrgID:       "org-eth",
			GroupID:     "group-1",
		})

		err := svc.DenyRequest(ctx, req.ID, "admin-1", "Not needed")
		require.NoError(t, err)

		updated, _ := svc.GetRequest(ctx, req.ID)
		assert.Equal(t, models.WorkspaceRequestStatusDenied, updated.Status)
		assert.Equal(t, "admin-1", updated.ReviewedBy)
	})

	t.Run("cannot deny non-pending request", func(t *testing.T) {
		req, _ := svc.CreateRequest(ctx, workspace.CreateWorkspaceRequestInput{
			RequesterID: "user-1",
			OrgID:       "org-eth",
			GroupID:     "group-1",
		})
		_ = svc.DenyRequest(ctx, req.ID, "admin-1", "reason")

		err := svc.DenyRequest(ctx, req.ID, "admin-2", "reason")
		require.Error(t, err)
	})
}

func TestHandlePairingRequest(t *testing.T) {
	ctx := context.Background()
	svc, reqRepo, _ := createRequestTestService()

	t.Run("creates local request from pairing payload", func(t *testing.T) {
		payload, _ := json.Marshal(map[string]any{
			"type":          "workspace_pairing_request",
			"workspace_id":  "ws-123",
			"federation_id": "fed-1",
			"locked":        false,
			"org_id":        "org-remote",
		})

		err := svc.HandlePairingRequest(ctx, payload)
		require.NoError(t, err)

		// Verify a request was created
		pending, _ := reqRepo.ListPending(ctx, "org-remote")
		assert.Len(t, pending, 1)
		assert.Equal(t, "ws-123", pending[0].WorkspaceID)
	})
}

func TestHandleArchiveNotification(t *testing.T) {
	ctx := context.Background()
	svc, _, wsSvc := createRequestTestService()

	t.Run("archives workspace on notification", func(t *testing.T) {
		// Create a workspace first
		ws, err := wsSvc.Create(ctx, workspace.CreateRequest{
			Name:         "archive-test",
			Participants: []string{"org-eth"},
		})
		require.NoError(t, err)

		payload, _ := json.Marshal(map[string]string{
			"type":         "workspace_archive",
			"workspace_id": ws.ID,
		})

		err = svc.HandleArchiveNotification(ctx, payload)
		require.NoError(t, err)

		// Verify workspace is archived
		archived, _ := wsSvc.Get(ctx, ws.ID)
		assert.True(t, archived.Archived)
	})
}
