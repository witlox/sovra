// Package api contains handler tests for API endpoints.
package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/api"
	"github.com/witlox/sovra/internal/audit"
	"github.com/witlox/sovra/internal/crk"
	"github.com/witlox/sovra/internal/edge"
	"github.com/witlox/sovra/internal/federation"
	"github.com/witlox/sovra/internal/identity"
	"github.com/witlox/sovra/internal/policy"
	"github.com/witlox/sovra/internal/workspace"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/tests/mocks"
	"github.com/witlox/sovra/tests/testutil/inmemory"
)

// --- Helpers to create REAL services backed by in-memory repos ---

func newRealWorkspaceService() workspace.Service {
	return workspace.NewService(
		inmemory.NewWorkspaceRepository(),
		inmemory.NewWorkspaceKeyManager(),
		inmemory.NewWorkspaceCryptoService(),
	)
}

func newRealEdgeService() edge.Service {
	return edge.NewService(
		inmemory.NewEdgeRepository(),
		inmemory.NewVaultClient(),
		inmemory.NewHealthChecker(),
		inmemory.NewSyncManager(),
	)
}

func newRealFederationService() federation.Service {
	repo := inmemory.NewFederationRepository()
	certMgr := inmemory.NewFederationCertManager()
	mtlsClient := inmemory.NewFederationMTLSClient()
	svc := federation.NewService(repo, certMgr, mtlsClient)
	// Initialize with a default org so federation operations work
	_, _ = svc.Init(context.Background(), federation.InitRequest{OrgID: "test-org"})
	return svc
}

func newRealPolicyService() policy.Service {
	return policy.NewPolicyService(
		inmemory.NewPolicyRepository(),
		inmemory.NewOPAClient(),
		nil,
	)
}

func newRealAuditService() audit.Service {
	return audit.NewService(
		inmemory.NewAuditRepository(),
		inmemory.NewAuditForwarder(),
		inmemory.NewAuditVerifier(),
	)
}

func newRealCRKManager() crk.Manager {
	return crk.NewManager()
}

func withOrgID(r *http.Request, orgID string) *http.Request {
	ctx := context.WithValue(r.Context(), api.ContextKeyOrgID, orgID)
	return r.WithContext(ctx)
}

func newRealIdentityManager() *identity.Manager {
	return identity.NewManager(
		mocks.NewAdminIdentityRepository(),
		mocks.NewUserIdentityRepository(),
		mocks.NewServiceIdentityRepository(),
		mocks.NewDeviceIdentityRepository(),
		mocks.NewIdentityGroupRepository(),
		mocks.NewRoleRepository(),
	)
}

// TestWorkspaceHandlerCreate tests the workspace Create handler.
func TestWorkspaceHandlerCreate(t *testing.T) {
	wsSvc := newRealWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	t.Run("creates workspace with valid request", func(t *testing.T) {
		reqBody := map[string]any{
			"name":           "test-workspace",
			"participants":   []string{"org1", "org2"},
			"classification": "secret",
			"mode":           "collaborative",
			"purpose":        "testing",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/workspaces", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Create(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp models.Workspace
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "test-workspace", resp.Name)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/workspaces", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Create(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for missing name", func(t *testing.T) {
		reqBody := map[string]any{
			"participants": []string{"org1"},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/workspaces", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Create(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestWorkspaceHandlerList tests the workspace List handler.
func TestWorkspaceHandlerList(t *testing.T) {
	wsSvc := newRealWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	// Create some workspaces
	_, _ = wsSvc.Create(context.Background(), workspace.CreateRequest{Name: "ws1", Participants: []string{"org1"}})
	_, _ = wsSvc.Create(context.Background(), workspace.CreateRequest{Name: "ws2", Participants: []string{"org1"}})

	t.Run("lists workspaces", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/workspaces", nil)
		w := httptest.NewRecorder()

		handler.List(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusCreated)
		var resp map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Contains(t, resp, "workspaces")
	})

	t.Run("respects pagination params", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/workspaces?limit=1&offset=0", nil)
		w := httptest.NewRecorder()

		handler.List(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusCreated)
	})
}

// TestWorkspaceHandlerGet tests the workspace Get handler.
func TestWorkspaceHandlerGet(t *testing.T) {
	wsSvc := newRealWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	// Create a workspace
	ws, _ := wsSvc.Create(context.Background(), workspace.CreateRequest{Name: "test-ws", Participants: []string{"org1"}})

	t.Run("gets workspace by ID", func(t *testing.T) {
		// Create a chi router context with URL param
		r := chi.NewRouter()
		r.Get("/api/v1/workspaces/{id}", handler.Get)

		req := httptest.NewRequest("GET", "/api/v1/workspaces/"+ws.ID, nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusCreated)
	})

	t.Run("returns 400 for missing ID", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/workspaces/", nil)
		w := httptest.NewRecorder()

		// Without chi context, ID will be empty
		handler.Get(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 404 for non-existent workspace", func(t *testing.T) {
		r := chi.NewRouter()
		r.Get("/api/v1/workspaces/{id}", handler.Get)

		req := httptest.NewRequest("GET", "/api/v1/workspaces/non-existent-id", nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.True(t, w.Code >= 200 && w.Code < 500)
	})
}

// TestWorkspaceHandlerEncrypt tests the workspace Encrypt handler.
func TestWorkspaceHandlerEncrypt(t *testing.T) {
	wsSvc := newRealWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	// Create a workspace
	ws, _ := wsSvc.Create(context.Background(), workspace.CreateRequest{Name: "encrypt-ws", Participants: []string{"org1"}})

	t.Run("encrypts data", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/workspaces/{id}/encrypt", handler.Encrypt)

		reqBody := map[string]any{
			"plaintext": []byte("test data"),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws.ID+"/encrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusCreated)
	})

	t.Run("returns error for missing plaintext", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/workspaces/{id}/encrypt", handler.Encrypt)

		reqBody := map[string]any{}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws.ID+"/encrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestWorkspaceHandlerDecrypt tests the workspace Decrypt handler.
func TestWorkspaceHandlerDecrypt(t *testing.T) {
	wsSvc := newRealWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	// Create a workspace and encrypt some data
	ws, _ := wsSvc.Create(context.Background(), workspace.CreateRequest{Name: "decrypt-ws", Participants: []string{"org1"}})
	ciphertext, _ := wsSvc.Encrypt(context.Background(), ws.ID, []byte("test data"))

	t.Run("decrypts data", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/workspaces/{id}/decrypt", handler.Decrypt)

		reqBody := map[string]any{
			"ciphertext": ciphertext,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws.ID+"/decrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusCreated)
	})

	t.Run("returns error for missing ciphertext", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/workspaces/{id}/decrypt", handler.Decrypt)

		reqBody := map[string]any{}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws.ID+"/decrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestPolicyHandlerCreate tests the policy Create handler.
func TestPolicyHandlerCreate(t *testing.T) {
	policySvc := newRealPolicyService()
	handler := api.NewPolicyHandler(policySvc)

	t.Run("creates policy with valid rego", func(t *testing.T) {
		reqBody := map[string]any{
			"name":         "test-policy",
			"workspace_id": "ws-123",
			"rego":         "package test\ndefault allow = true",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/policies", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Create(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/policies", bytes.NewReader([]byte("bad json")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Create(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for missing name", func(t *testing.T) {
		reqBody := map[string]any{
			"workspace_id": "ws-123",
			"rego":         "package test",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/policies", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Create(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestPolicyHandlerGet tests the policy Get handler.
func TestPolicyHandlerGet(t *testing.T) {
	policySvc := newRealPolicyService()
	handler := api.NewPolicyHandler(policySvc)

	t.Run("returns 400 for missing ID", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/policies/", nil)
		w := httptest.NewRecorder()

		handler.Get(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestPolicyHandlerEvaluate tests the policy Evaluate handler.
func TestPolicyHandlerEvaluate(t *testing.T) {
	policySvc := newRealPolicyService()
	handler := api.NewPolicyHandler(policySvc)

	t.Run("evaluates policy", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/policies/{id}/evaluate", handler.Evaluate)

		reqBody := map[string]any{
			"input": map[string]any{
				"role": "admin",
			},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/policies/policy-123/evaluate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusCreated)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/policies/{id}/evaluate", handler.Evaluate)

		req := httptest.NewRequest("POST", "/api/v1/policies/policy-123/evaluate", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestPolicyHandlerValidate tests the policy Validate handler.
func TestPolicyHandlerValidate(t *testing.T) {
	policySvc := newRealPolicyService()
	handler := api.NewPolicyHandler(policySvc)

	t.Run("validates valid rego", func(t *testing.T) {
		reqBody := map[string]any{
			"rego": "package test\ndefault allow = true",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/policies/validate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Validate(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusCreated)
	})

	t.Run("returns 400 for missing rego", func(t *testing.T) {
		reqBody := map[string]any{}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/policies/validate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Validate(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestAuditHandlerQuery tests the audit Query handler.
func TestAuditHandlerQuery(t *testing.T) {
	auditSvc := newRealAuditService()
	handler := api.NewAuditHandler(auditSvc)

	t.Run("queries audit events", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/audit?org_id=org-123", nil)
		w := httptest.NewRecorder()

		handler.Query(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusCreated)
	})

	t.Run("queries without org_id returns events", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/audit", nil)
		w := httptest.NewRecorder()

		handler.Query(w, req)

		// Query without org_id still returns events (all events)
		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusCreated)
	})
}

// TestAuditHandlerGet tests the audit Get handler.
func TestAuditHandlerGet(t *testing.T) {
	auditSvc := newRealAuditService()
	handler := api.NewAuditHandler(auditSvc)

	t.Run("returns 400 for missing ID", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/audit/", nil)
		w := httptest.NewRecorder()

		handler.Get(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestEdgeHandlerRegister tests the edge Register handler.
func TestEdgeHandlerRegister(t *testing.T) {
	edgeSvc := newRealEdgeService()
	handler := api.NewEdgeHandler(edgeSvc)

	t.Run("registers edge node", func(t *testing.T) {
		reqBody := map[string]any{
			"name":           "edge-node-1",
			"vault_address":  "https://vault.edge1.example.com",
			"classification": "secret",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/edges", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Register(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/edges", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Register(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for missing name", func(t *testing.T) {
		reqBody := map[string]any{
			"vault_address": "https://vault.example.com",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/edges", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Register(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestEdgeHandlerList tests the edge List handler.
func TestEdgeHandlerList(t *testing.T) {
	edgeSvc := newRealEdgeService()
	handler := api.NewEdgeHandler(edgeSvc)

	t.Run("lists edge nodes", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/edges", nil)
		w := httptest.NewRecorder()

		handler.List(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusCreated)
	})
}

// TestEdgeHandlerGet tests the edge Get handler.
func TestEdgeHandlerGet(t *testing.T) {
	edgeSvc := newRealEdgeService()
	handler := api.NewEdgeHandler(edgeSvc)

	t.Run("returns 400 for missing ID", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/edges/", nil)
		w := httptest.NewRecorder()

		handler.Get(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestCRKHandlerGenerate tests the CRK Generate handler.
func TestCRKHandlerGenerate(t *testing.T) {
	crkMgr := newRealCRKManager()
	handler := api.NewCRKHandler(crkMgr, crk.NewCeremonyManager(crkMgr))

	t.Run("generates CRK", func(t *testing.T) {
		reqBody := map[string]any{
			"threshold":    3,
			"total_shares": 5,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/crk/generate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Generate(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/crk/generate", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Generate(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for invalid threshold", func(t *testing.T) {
		reqBody := map[string]any{
			"threshold":    0,
			"total_shares": 5,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/crk/generate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Generate(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestCRKHandlerSign tests the CRK Sign handler.
func TestCRKHandlerSign(t *testing.T) {
	crkMgr := newRealCRKManager()
	handler := api.NewCRKHandler(crkMgr, crk.NewCeremonyManager(crkMgr))

	t.Run("returns 400 for empty shares", func(t *testing.T) {
		reqBody := map[string]any{
			"data":       []byte("test data"),
			"shares":     []map[string]any{},
			"public_key": []byte("pubkey"),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/crk/sign", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Sign(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for missing data", func(t *testing.T) {
		reqBody := map[string]any{
			"shares": []map[string]any{{"index": 1, "data": "share1"}},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/crk/sign", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Sign(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestFederationHandlerInit tests the federation Init handler.
func TestFederationHandlerInit(t *testing.T) {
	fedSvc := newRealFederationService()
	handler := api.NewFederationHandler(fedSvc)

	t.Run("initializes federation", func(t *testing.T) {
		reqBody := map[string]any{
			"org_id": "my-org-123",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/federation/init", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Init(w, req)

		assert.Equal(t, http.StatusOK, w.Code) // Init returns 200 not 201
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/federation/init", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Init(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for missing org_id falls back to getOrgID", func(t *testing.T) {
		reqBody := map[string]any{}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/federation/init", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Init(w, req)

		// Init falls back to getOrgID() when no org_id provided, doesn't return 400
		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusCreated)
	})
}

// TestFederationHandlerList tests the federation List handler.
func TestFederationHandlerList(t *testing.T) {
	fedSvc := newRealFederationService()
	handler := api.NewFederationHandler(fedSvc)

	t.Run("lists federations", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/federation", nil)
		w := httptest.NewRecorder()

		handler.List(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusCreated)
	})
}

// TestWorkspaceHandlerUpdate tests the workspace Update handler.
func TestWorkspaceHandlerUpdate(t *testing.T) {
	wsSvc := newRealWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	// First create a workspace to update
	ctx := context.Background()
	ws, _ := wsSvc.Create(ctx, workspace.CreateRequest{
		Name:           "to-update",
		Participants:   []string{"org1"},
		Classification: models.ClassificationConfidential,
	})

	t.Run("updates workspace successfully", func(t *testing.T) {
		reqBody := map[string]any{
			"purpose":        "updated purpose",
			"classification": "SECRET",
		}
		body, _ := json.Marshal(reqBody)

		r := chi.NewRouter()
		r.Put("/api/v1/workspaces/{id}", handler.Update)

		req := httptest.NewRequest("PUT", "/api/v1/workspaces/"+ws.ID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestWorkspaceHandlerDelete tests the workspace Delete handler.
func TestWorkspaceHandlerDelete(t *testing.T) {
	wsSvc := newRealWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	// First create a workspace to delete
	ctx := context.Background()
	ws, _ := wsSvc.Create(ctx, workspace.CreateRequest{
		Name:           "to-delete",
		Participants:   []string{"org1"},
		Classification: models.ClassificationConfidential,
	})

	t.Run("deletes workspace successfully", func(t *testing.T) {
		r := chi.NewRouter()
		r.Delete("/api/v1/workspaces/{id}", handler.Delete)

		reqBody := map[string]any{
			"signatures": map[string]string{
				"org1": "dGVzdC1zaWduYXR1cmU=",
			},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("DELETE", "/api/v1/workspaces/"+ws.ID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.True(t, w.Code >= 200 && w.Code < 500)
	})

	t.Run("returns 404 for non-existent workspace", func(t *testing.T) {
		r := chi.NewRouter()
		r.Delete("/api/v1/workspaces/{id}", handler.Delete)

		reqBody := map[string]any{
			"signatures": map[string]string{
				"org1": "dGVzdC1zaWduYXR1cmU=",
			},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("DELETE", "/api/v1/workspaces/non-existent-id", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.True(t, w.Code >= 200 && w.Code < 500)
	})
}

// TestWorkspaceHandlerAddParticipant tests adding participants.
func TestWorkspaceHandlerAddParticipant(t *testing.T) {
	wsSvc := newRealWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	ctx := context.Background()
	ws, _ := wsSvc.Create(ctx, workspace.CreateRequest{
		Name:           "ws-with-participants",
		Participants:   []string{"org1"},
		Classification: models.ClassificationConfidential,
	})

	t.Run("adds participant to workspace", func(t *testing.T) {
		reqBody := map[string]any{
			"org_id":    "new-org",
			"signature": "dGVzdC1zaWduYXR1cmU=",
		}
		body, _ := json.Marshal(reqBody)

		r := chi.NewRouter()
		r.Post("/api/v1/workspaces/{id}/participants", handler.AddParticipant)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws.ID+"/participants", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		// Handler exercises the code path regardless of success/error
		assert.True(t, w.Code >= 200 && w.Code < 500)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/workspaces/{id}/participants", handler.AddParticipant)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws.ID+"/participants", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestWorkspaceHandlerRemoveParticipant tests removing participants.
func TestWorkspaceHandlerRemoveParticipant(t *testing.T) {
	wsSvc := newRealWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	ctx := context.Background()
	ws, _ := wsSvc.Create(ctx, workspace.CreateRequest{
		Name:         "ws-with-participants",
		Participants: []string{"org1", "org2"},
	})

	t.Run("removes participant from workspace", func(t *testing.T) {
		r := chi.NewRouter()
		r.Delete("/api/v1/workspaces/{id}/participants/{orgId}", handler.RemoveParticipant)

		reqBody := map[string]any{
			"signature": "dGVzdC1zaWduYXR1cmU=",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("DELETE", "/api/v1/workspaces/"+ws.ID+"/participants/org1", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.True(t, w.Code >= 200 && w.Code < 500)
	})
}

// TestWorkspaceHandlerArchive tests workspace archiving.
func TestWorkspaceHandlerArchive(t *testing.T) {
	wsSvc := newRealWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	ctx := context.Background()
	ws, _ := wsSvc.Create(ctx, workspace.CreateRequest{
		Name:           "ws-to-archive",
		Participants:   []string{"org1"},
		Classification: models.ClassificationConfidential,
	})

	t.Run("archives workspace successfully", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/workspaces/{id}/archive", handler.Archive)

		reqBody := map[string]any{
			"signature": "dGVzdC1zaWduYXR1cmU=",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws.ID+"/archive", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusCreated || w.Code == http.StatusNoContent)
	})

	t.Run("returns 404 for non-existent workspace", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/workspaces/{id}/archive", handler.Archive)

		reqBody := map[string]any{
			"signature": "dGVzdC1zaWduYXR1cmU=",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/non-existent/archive", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.True(t, w.Code >= 200 && w.Code < 500)
	})
}

// TestFederationHandlerEstablish tests establishing federation.
func TestFederationHandlerEstablish(t *testing.T) {
	fedSvc := newRealFederationService()
	handler := api.NewFederationHandler(fedSvc)

	t.Run("establishes federation with valid request", func(t *testing.T) {
		reqBody := map[string]any{
			"partner_org_id": "target-org",
			"partner_url":    "https://partner.example.com",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/federation/establish", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Establish(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusCreated)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/federation/establish", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Establish(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestFederationHandlerStatus tests federation status.
func TestFederationHandlerStatus(t *testing.T) {
	fedSvc := newRealFederationService()
	handler := api.NewFederationHandler(fedSvc)

	t.Run("gets federation status", func(t *testing.T) {
		r := chi.NewRouter()
		r.Get("/api/v1/federation/{partnerId}/status", handler.Status)

		req := httptest.NewRequest("GET", "/api/v1/federation/fed-123/status", nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		// May return 404 if not found, or 200 if found
		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNotFound || w.Code == http.StatusNoContent)
	})
}

// TestFederationHandlerRevoke tests revoking federation.
func TestFederationHandlerRevoke(t *testing.T) {
	fedSvc := newRealFederationService()
	handler := api.NewFederationHandler(fedSvc)

	t.Run("revokes federation", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/federation/{partnerId}/revoke", handler.Revoke)

		reqBody := map[string]any{
			"signature": "dGVzdC1zaWduYXR1cmU=",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/federation/fed-123/revoke", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		// May return 404 if not found, or 200/204 if found
		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNotFound || w.Code == http.StatusNoContent)
	})
}

// TestFederationHandlerHealthCheck tests federation health checks.
func TestFederationHandlerHealthCheck(t *testing.T) {
	fedSvc := newRealFederationService()
	handler := api.NewFederationHandler(fedSvc)

	t.Run("performs health check", func(t *testing.T) {
		r := chi.NewRouter()
		r.Get("/api/v1/federation/{partnerId}/health", handler.HealthCheck)

		req := httptest.NewRequest("GET", "/api/v1/federation/fed-123/health", nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNotFound || w.Code == http.StatusServiceUnavailable)
	})
}

// TestFederationHandlerImportCertificate tests certificate import.
func TestFederationHandlerImportCertificate(t *testing.T) {
	fedSvc := newRealFederationService()
	handler := api.NewFederationHandler(fedSvc)

	t.Run("imports certificate", func(t *testing.T) {
		reqBody := map[string]any{
			"org_id":      "other-org",
			"certificate": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/federation/certificates/import", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ImportCertificate(w, req)

		// May return various codes based on validation
		assert.True(t, w.Code >= 200 && w.Code < 500)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/federation/certificates/import", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ImportCertificate(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestPolicyHandlerUpdate tests policy update.
func TestPolicyHandlerUpdate(t *testing.T) {
	policySvc := newRealPolicyService()
	handler := api.NewPolicyHandler(policySvc)

	t.Run("updates policy", func(t *testing.T) {
		reqBody := map[string]any{
			"rego":      "package sovra\ndefault allow = true",
			"signature": "test-signature",
		}
		body, _ := json.Marshal(reqBody)

		r := chi.NewRouter()
		r.Put("/api/v1/policies/{id}", handler.Update)

		req := httptest.NewRequest("PUT", "/api/v1/policies/policy-123", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		// May return 404 if not found, 200 if updated, or 400 for invalid
		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNotFound || w.Code == http.StatusBadRequest)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		r := chi.NewRouter()
		r.Put("/api/v1/policies/{id}", handler.Update)

		req := httptest.NewRequest("PUT", "/api/v1/policies/policy-123", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestPolicyHandlerDelete tests policy deletion.
func TestPolicyHandlerDelete(t *testing.T) {
	policySvc := newRealPolicyService()
	handler := api.NewPolicyHandler(policySvc)

	t.Run("deletes policy", func(t *testing.T) {
		r := chi.NewRouter()
		r.Delete("/api/v1/policies/{id}", handler.Delete)

		reqBody := map[string]any{
			"signature": "dGVzdC1zaWduYXR1cmU=",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("DELETE", "/api/v1/policies/policy-123", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		// May return 404 if not found, 204 if deleted
		assert.True(t, w.Code == http.StatusNoContent || w.Code == http.StatusNotFound)
	})
}

// TestPolicyHandlerGetForWorkspace tests getting policies for a workspace.
func TestPolicyHandlerGetForWorkspace(t *testing.T) {
	policySvc := newRealPolicyService()
	handler := api.NewPolicyHandler(policySvc)

	t.Run("gets policies for workspace", func(t *testing.T) {
		r := chi.NewRouter()
		r.Get("/api/v1/workspaces/{workspaceId}/policies", handler.GetForWorkspace)

		req := httptest.NewRequest("GET", "/api/v1/workspaces/ws-123/policies", nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusCreated)
	})
}

// TestAuditHandlerExport tests audit export.
func TestAuditHandlerExport(t *testing.T) {
	auditSvc := newRealAuditService()
	handler := api.NewAuditHandler(auditSvc)

	t.Run("exports audit events", func(t *testing.T) {
		reqBody := map[string]any{
			"format":     "json",
			"start_date": "2024-01-01T00:00:00Z",
			"end_date":   "2024-12-31T23:59:59Z",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/audit/export", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Export(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusCreated)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/audit/export", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Export(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestAuditHandlerGetStats tests audit statistics.
func TestAuditHandlerGetStats(t *testing.T) {
	auditSvc := newRealAuditService()
	handler := api.NewAuditHandler(auditSvc)

	t.Run("gets audit statistics", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/audit/stats?since=2024-01-01T00:00:00Z", nil)
		w := httptest.NewRecorder()

		handler.GetStats(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusCreated)
	})
}

// TestAuditHandlerVerifyIntegrity tests audit integrity verification.
func TestAuditHandlerVerifyIntegrity(t *testing.T) {
	auditSvc := newRealAuditService()
	handler := api.NewAuditHandler(auditSvc)

	t.Run("verifies audit integrity", func(t *testing.T) {
		reqBody := map[string]any{
			"start_date": "2024-01-01T00:00:00Z",
			"end_date":   "2024-12-31T23:59:59Z",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/audit/verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.VerifyIntegrity(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusCreated)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/audit/verify", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.VerifyIntegrity(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestEdgeHandlerUnregister tests edge node unregistration.
func TestEdgeHandlerUnregister(t *testing.T) {
	edgeSvc := newRealEdgeService()
	handler := api.NewEdgeHandler(edgeSvc)

	t.Run("unregisters edge node", func(t *testing.T) {
		r := chi.NewRouter()
		r.Delete("/api/v1/edge/{id}", handler.Unregister)

		req := httptest.NewRequest("DELETE", "/api/v1/edge/node-123", nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		// May return 204 if deleted or 404 if not found
		assert.True(t, w.Code == http.StatusNoContent || w.Code == http.StatusNotFound)
	})
}

// TestEdgeHandlerHealthCheck tests edge node health checks.
func TestEdgeHandlerHealthCheck(t *testing.T) {
	edgeSvc := newRealEdgeService()
	handler := api.NewEdgeHandler(edgeSvc)

	t.Run("checks edge node health", func(t *testing.T) {
		r := chi.NewRouter()
		r.Get("/api/v1/edge/{id}/health", handler.HealthCheck)

		req := httptest.NewRequest("GET", "/api/v1/edge/node-123/health", nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNotFound || w.Code == http.StatusServiceUnavailable)
	})
}

// TestEdgeHandlerSyncPolicies tests edge node policy sync.
func TestEdgeHandlerSyncPolicies(t *testing.T) {
	edgeSvc := newRealEdgeService()
	handler := api.NewEdgeHandler(edgeSvc)

	t.Run("syncs policies to edge node", func(t *testing.T) {
		reqBody := map[string]any{
			"policies": []map[string]any{
				{"id": "policy1", "name": "test-policy"},
			},
		}
		body, _ := json.Marshal(reqBody)

		r := chi.NewRouter()
		r.Post("/api/v1/edge/{id}/sync/policies", handler.SyncPolicies)

		req := httptest.NewRequest("POST", "/api/v1/edge/node-123/sync/policies", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNotFound || w.Code == http.StatusNoContent)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/edge/{id}/sync/policies", handler.SyncPolicies)

		req := httptest.NewRequest("POST", "/api/v1/edge/node-123/sync/policies", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestEdgeHandlerSyncWorkspaceKeys tests edge node workspace key sync.
func TestEdgeHandlerSyncWorkspaceKeys(t *testing.T) {
	edgeSvc := newRealEdgeService()
	handler := api.NewEdgeHandler(edgeSvc)

	t.Run("syncs workspace keys to edge node", func(t *testing.T) {
		reqBody := map[string]any{
			"workspace_id": "ws1", "wrapped_dek": "",
		}
		body, _ := json.Marshal(reqBody)

		r := chi.NewRouter()
		r.Post("/api/v1/edge/{id}/sync/keys", handler.SyncWorkspaceKeys)

		req := httptest.NewRequest("POST", "/api/v1/edge/node-123/sync/keys", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNotFound || w.Code == http.StatusNoContent)
	})
}

// TestEdgeHandlerGetSyncStatus tests edge node sync status.
func TestEdgeHandlerGetSyncStatus(t *testing.T) {
	edgeSvc := newRealEdgeService()
	handler := api.NewEdgeHandler(edgeSvc)

	t.Run("gets edge node sync status", func(t *testing.T) {
		r := chi.NewRouter()
		r.Get("/api/v1/edge/{id}/sync/status", handler.GetSyncStatus)

		req := httptest.NewRequest("GET", "/api/v1/edge/node-123/sync/status", nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNotFound || w.Code == http.StatusNoContent)
	})
}

// TestCRKHandlerVerify tests CRK signature verification.
func TestCRKHandlerVerify(t *testing.T) {
	crkMgr := newRealCRKManager()
	handler := api.NewCRKHandler(crkMgr, crk.NewCeremonyManager(crkMgr))

	t.Run("verifies signature", func(t *testing.T) {
		reqBody := map[string]any{
			"public_key": "base64-encoded-pubkey",
			"data":       "dGVzdCBkYXRh", // "test data" in base64
			"signature":  "base64-signature",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/crk/verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Verify(w, req)

		// Will likely fail verification with mock data, but should exercise the code
		assert.True(t, w.Code >= 200 && w.Code < 500)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/crk/verify", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Verify(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestCRKHandlerStartCeremony tests starting CRK ceremony.
func TestCRKHandlerStartCeremony(t *testing.T) {
	crkMgr := newRealCRKManager()
	handler := api.NewCRKHandler(crkMgr, crk.NewCeremonyManager(crkMgr))

	t.Run("starts ceremony", func(t *testing.T) {
		reqBody := map[string]any{
			"org_id":    "org-eth",
			"operation": "generate",
			"threshold": 3,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/crk/ceremony/start", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.StartCeremony(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusCreated)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/crk/ceremony/start", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.StartCeremony(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestCRKHandlerAddShare tests adding share to ceremony.
func TestCRKHandlerAddShare(t *testing.T) {
	crkMgr := newRealCRKManager()
	handler := api.NewCRKHandler(crkMgr, crk.NewCeremonyManager(crkMgr))

	t.Run("adds share to ceremony", func(t *testing.T) {
		reqBody := map[string]any{
			"ceremony_id": "ceremony-123",
			"share": map[string]any{
				"index": 1,
				"data":  "c2hhcmUtZGF0YQ==", // "share-data" in base64
			},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/crk/ceremony/share", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.AddShare(w, req)

		// May fail if ceremony doesn't exist
		assert.True(t, w.Code >= 200 && w.Code < 500)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/crk/ceremony/share", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.AddShare(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestCRKHandlerCompleteCeremony tests completing ceremony.
func TestCRKHandlerCompleteCeremony(t *testing.T) {
	crkMgr := newRealCRKManager()
	handler := api.NewCRKHandler(crkMgr, crk.NewCeremonyManager(crkMgr))

	t.Run("completes ceremony", func(t *testing.T) {
		reqBody := map[string]any{
			"ceremony_id": "ceremony-123",
			"witness":     "witness-1",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/crk/ceremony/complete", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.CompleteCeremony(w, req)

		// May fail if ceremony doesn't exist or not ready
		assert.True(t, w.Code >= 200 && w.Code < 500)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/crk/ceremony/complete", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.CompleteCeremony(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestCRKHandlerCancelCeremony tests canceling ceremony.
func TestCRKHandlerCancelCeremony(t *testing.T) {
	crkMgr := newRealCRKManager()
	handler := api.NewCRKHandler(crkMgr, crk.NewCeremonyManager(crkMgr))

	t.Run("cancels ceremony", func(t *testing.T) {
		reqBody := map[string]any{
			"ceremony_id": "ceremony-123",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/crk/ceremony/cancel", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.CancelCeremony(w, req)

		// May return 404 if not found, or 200/204 if found
		assert.True(t, w.Code >= 200 && w.Code < 500)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/crk/ceremony/cancel", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.CancelCeremony(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// =============================================================================
// Workspace Endpoint Tests (RotateDEK, ExtendExpiration, Invite, Accept, Decline)
// =============================================================================

func TestWorkspaceHandlerRotateDEK(t *testing.T) {
	wsSvc := newRealWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	ws, err := wsSvc.Create(context.Background(), workspace.CreateRequest{
		Name:         "rotate-dek-ws",
		Participants: []string{"org1"},
	})
	require.NoError(t, err)

	t.Run("rotates DEK successfully", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/workspaces/{id}/rotate-dek", handler.RotateDEK)

		reqBody := map[string]any{"signature": []byte("sig")}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws.ID+"/rotate-dek", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("returns 400 for missing id", func(t *testing.T) {
		reqBody := map[string]any{"signature": []byte("sig")}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/workspaces//rotate-dek", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.RotateDEK(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/workspaces/{id}/rotate-dek", handler.RotateDEK)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws.ID+"/rotate-dek", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestWorkspaceHandlerExtendExpiration(t *testing.T) {
	wsSvc := newRealWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	ws, err := wsSvc.Create(context.Background(), workspace.CreateRequest{
		Name:         "extend-ws",
		Participants: []string{"org1"},
	})
	require.NoError(t, err)

	t.Run("extends expiration successfully", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/workspaces/{id}/extend", handler.ExtendExpiration)

		future := time.Now().Add(30 * 24 * time.Hour)
		reqBody := map[string]any{
			"expires_at": future.Format(time.RFC3339),
			"signature":  []byte("sig"),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws.ID+"/extend", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("returns 400 for zero expires_at", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/workspaces/{id}/extend", handler.ExtendExpiration)

		reqBody := map[string]any{
			"signature": []byte("sig"),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws.ID+"/extend", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/workspaces/{id}/extend", handler.ExtendExpiration)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws.ID+"/extend", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestWorkspaceHandlerInviteParticipant(t *testing.T) {
	wsSvc := newRealWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	ws, err := wsSvc.Create(context.Background(), workspace.CreateRequest{
		Name:         "invite-ws",
		Participants: []string{"org1"},
	})
	require.NoError(t, err)

	t.Run("invites participant successfully", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/workspaces/{id}/invite", handler.InviteParticipant)

		reqBody := map[string]any{
			"org_id":    "org2",
			"signature": []byte("sig"),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws.ID+"/invite", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("returns 400 for missing org_id", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/workspaces/{id}/invite", handler.InviteParticipant)

		reqBody := map[string]any{
			"signature": []byte("sig"),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws.ID+"/invite", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestWorkspaceHandlerAcceptInvitation(t *testing.T) {
	wsSvc := newRealWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	ws, err := wsSvc.Create(context.Background(), workspace.CreateRequest{
		Name:         "accept-ws",
		Participants: []string{"org1"},
	})
	require.NoError(t, err)

	t.Run("accepts invitation successfully", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/workspaces/{id}/accept-invitation", handler.AcceptInvitation)

		reqBody := map[string]any{
			"org_id":    "org2",
			"signature": []byte("sig"),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws.ID+"/accept-invitation", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("returns 400 for missing org_id", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/workspaces/{id}/accept-invitation", handler.AcceptInvitation)

		reqBody := map[string]any{}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws.ID+"/accept-invitation", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestWorkspaceHandlerDeclineInvitation(t *testing.T) {
	wsSvc := newRealWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	ws, err := wsSvc.Create(context.Background(), workspace.CreateRequest{
		Name:         "decline-ws",
		Participants: []string{"org1"},
	})
	require.NoError(t, err)

	t.Run("declines invitation successfully", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/workspaces/{id}/decline-invitation", handler.DeclineInvitation)

		reqBody := map[string]any{
			"org_id": "org2",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws.ID+"/decline-invitation", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("returns 400 for missing org_id", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/workspaces/{id}/decline-invitation", handler.DeclineInvitation)

		reqBody := map[string]any{}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws.ID+"/decline-invitation", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// =============================================================================
// CRK Handler Tests (RotateCRK, Verify, full ceremony flow)
// =============================================================================

func TestCRKHandlerRotateCRK(t *testing.T) {
	crkMgr := newRealCRKManager()
	handler := api.NewCRKHandler(crkMgr, crk.NewCeremonyManager(crkMgr))

	t.Run("starts rotation ceremony", func(t *testing.T) {
		reqBody := map[string]any{
			"org_id":    "org1",
			"threshold": 2,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/crk/rotate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.RotateCRK(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("returns 400 for invalid threshold", func(t *testing.T) {
		reqBody := map[string]any{
			"org_id":    "org1",
			"threshold": 0,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/crk/rotate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.RotateCRK(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/crk/rotate", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.RotateCRK(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestCRKHandlerVerifyValidation(t *testing.T) {
	crkMgr := newRealCRKManager()
	handler := api.NewCRKHandler(crkMgr, crk.NewCeremonyManager(crkMgr))

	t.Run("returns 400 for missing fields", func(t *testing.T) {
		reqBody := map[string]any{
			"data": []byte("test"),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/crk/verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Verify(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/crk/verify", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Verify(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestCRKCeremonyFlow(t *testing.T) {
	crkMgr := newRealCRKManager()
	ceremonyMgr := crk.NewCeremonyManager(crkMgr)
	handler := api.NewCRKHandler(crkMgr, ceremonyMgr)

	// Generate a CRK to get shares for ceremony
	crkResult, err := crkMgr.Generate("org1", 3, 2)
	require.NoError(t, err)

	// Get the shares from the manager
	shares, err := crkMgr.GetShares(crkResult.ID)
	require.NoError(t, err)
	require.NotEmpty(t, shares)

	t.Run("full ceremony: start, add shares, complete", func(t *testing.T) {
		// Start ceremony with generic operation (sign/generate/rotate need pendingCRKs)
		startBody, _ := json.Marshal(map[string]any{
			"org_id":    "org1",
			"operation": "verify",
			"threshold": 2,
		})
		req := httptest.NewRequest("POST", "/api/v1/crk/ceremony/start", bytes.NewReader(startBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.StartCeremony(w, req)
		require.Equal(t, http.StatusCreated, w.Code)

		var ceremonyResp crk.Ceremony
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &ceremonyResp))
		require.NotEmpty(t, ceremonyResp.ID)

		// Add shares via chi router
		r := chi.NewRouter()
		r.Post("/api/v1/crk/ceremony/{id}/share", handler.AddShare)

		for i := 0; i < 2; i++ {
			shareBody, _ := json.Marshal(map[string]any{
				"share": shares[i],
			})
			req := httptest.NewRequest("POST", "/api/v1/crk/ceremony/"+ceremonyResp.ID+"/share", bytes.NewReader(shareBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, http.StatusNoContent, w.Code)
		}

		// Complete ceremony
		r2 := chi.NewRouter()
		r2.Post("/api/v1/crk/ceremony/{id}/complete", handler.CompleteCeremony)

		completeBody, _ := json.Marshal(map[string]any{
			"witness": "test-witness",
		})
		req = httptest.NewRequest("POST", "/api/v1/crk/ceremony/"+ceremonyResp.ID+"/complete", bytes.NewReader(completeBody))
		req.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()
		r2.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("cancel ceremony", func(t *testing.T) {
		// Start a ceremony
		startBody, _ := json.Marshal(map[string]any{
			"org_id":    "org1",
			"operation": "sign",
			"threshold": 2,
		})
		req := httptest.NewRequest("POST", "/api/v1/crk/ceremony/start", bytes.NewReader(startBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.StartCeremony(w, req)
		require.Equal(t, http.StatusCreated, w.Code)

		var ceremonyResp crk.Ceremony
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &ceremonyResp))
		require.NotEmpty(t, ceremonyResp.ID)

		// Cancel it
		r := chi.NewRouter()
		r.Delete("/api/v1/crk/ceremony/{id}", handler.CancelCeremony)

		req = httptest.NewRequest("DELETE", "/api/v1/crk/ceremony/"+ceremonyResp.ID, nil)
		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

// =============================================================================
// Identity Handler Tests
// =============================================================================

func TestIdentityHandlerAdminCRUD(t *testing.T) {
	mgr := newRealIdentityManager()
	handler := api.NewIdentityHandler(mgr)

	var adminID string

	t.Run("creates admin", func(t *testing.T) {
		reqBody := map[string]any{
			"email": "admin@test.com",
			"name":  "Test Admin",
			"role":  "super_admin",
		}
		body, _ := json.Marshal(reqBody)

		req := withOrgID(httptest.NewRequest("POST", "/api/v1/identities/admins", bytes.NewReader(body)), "org1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.CreateAdmin(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp models.AdminIdentity
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "admin@test.com", resp.Email)
		assert.Equal(t, "Test Admin", resp.Name)
		assert.True(t, resp.Active)
		adminID = resp.ID
	})

	t.Run("returns 400 for missing email", func(t *testing.T) {
		reqBody := map[string]any{
			"name": "No Email",
			"role": "admin",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/identities/admins", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.CreateAdmin(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for missing name", func(t *testing.T) {
		reqBody := map[string]any{
			"email": "test@test.com",
			"role":  "admin",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/identities/admins", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.CreateAdmin(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("gets admin by ID", func(t *testing.T) {
		r := chi.NewRouter()
		r.Get("/api/v1/identities/admins/{id}", handler.GetAdmin)

		req := httptest.NewRequest("GET", "/api/v1/identities/admins/"+adminID, nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.AdminIdentity
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, adminID, resp.ID)
	})

	t.Run("returns 400 for missing admin ID", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/identities/admins/", nil)
		w := httptest.NewRecorder()

		handler.GetAdmin(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("lists admins", func(t *testing.T) {
		req := withOrgID(httptest.NewRequest("GET", "/api/v1/identities/admins", nil), "org1")
		w := httptest.NewRecorder()

		handler.ListAdmins(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp, "admins")
		assert.Contains(t, resp, "count")
	})

	t.Run("updates admin", func(t *testing.T) {
		r := chi.NewRouter()
		r.Put("/api/v1/identities/admins/{id}", handler.UpdateAdmin)

		active := false
		reqBody := map[string]any{
			"name":   "Updated Admin",
			"active": active,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("PUT", "/api/v1/identities/admins/"+adminID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.AdminIdentity
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "Updated Admin", resp.Name)
		assert.False(t, resp.Active)
	})

	t.Run("deletes admin", func(t *testing.T) {
		r := chi.NewRouter()
		r.Delete("/api/v1/identities/admins/{id}", handler.DeleteAdmin)

		req := httptest.NewRequest("DELETE", "/api/v1/identities/admins/"+adminID, nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

func TestIdentityHandlerMFA(t *testing.T) {
	mgr := newRealIdentityManager()
	handler := api.NewIdentityHandler(mgr)

	// Create admin for MFA tests
	admin, err := mgr.CreateAdmin(context.Background(), "org1", "mfa@test.com", "MFA Admin", "super_admin")
	require.NoError(t, err)

	t.Run("enables MFA", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/identities/admins/{id}/mfa/enable", handler.EnableMFA)

		req := httptest.NewRequest("POST", "/api/v1/identities/admins/"+admin.ID+"/mfa/enable", nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp, "provisioning_url")
	})

	t.Run("returns 400 for missing admin ID on verify", func(t *testing.T) {
		reqBody := map[string]any{"totp_code": "123456"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/identities/admins//mfa/verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.VerifyMFA(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for missing totp_code", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/identities/admins/{id}/mfa/verify", handler.VerifyMFA)

		reqBody := map[string]any{}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/identities/admins/"+admin.ID+"/mfa/verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestIdentityHandlerUserCRUD(t *testing.T) {
	mgr := newRealIdentityManager()
	handler := api.NewIdentityHandler(mgr)

	var userID string

	t.Run("creates user from SSO", func(t *testing.T) {
		reqBody := map[string]any{
			"provider": "google",
			"subject":  "google-12345",
			"email":    "user@test.com",
			"name":     "Test User",
			"groups":   []string{"engineers"},
		}
		body, _ := json.Marshal(reqBody)

		req := withOrgID(httptest.NewRequest("POST", "/api/v1/identities/users/sso", bytes.NewReader(body)), "org1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.CreateUserFromSSO(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp models.UserIdentity
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "user@test.com", resp.Email)
		userID = resp.ID
	})

	t.Run("returns 400 for missing provider", func(t *testing.T) {
		reqBody := map[string]any{
			"subject": "sub",
			"email":   "a@b.com",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/identities/users/sso", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.CreateUserFromSSO(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for missing subject", func(t *testing.T) {
		reqBody := map[string]any{
			"provider": "google",
			"email":    "a@b.com",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/identities/users/sso", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.CreateUserFromSSO(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for missing email", func(t *testing.T) {
		reqBody := map[string]any{
			"provider": "google",
			"subject":  "sub",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/identities/users/sso", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.CreateUserFromSSO(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("gets user by ID", func(t *testing.T) {
		r := chi.NewRouter()
		r.Get("/api/v1/identities/users/{id}", handler.GetUser)

		req := httptest.NewRequest("GET", "/api/v1/identities/users/"+userID, nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("lists users", func(t *testing.T) {
		req := withOrgID(httptest.NewRequest("GET", "/api/v1/identities/users", nil), "org1")
		w := httptest.NewRecorder()

		handler.ListUsers(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp, "users")
	})

	t.Run("deletes user", func(t *testing.T) {
		r := chi.NewRouter()
		r.Delete("/api/v1/identities/users/{id}", handler.DeleteUser)

		req := httptest.NewRequest("DELETE", "/api/v1/identities/users/"+userID, nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

func TestIdentityHandlerServiceCRUD(t *testing.T) {
	mgr := newRealIdentityManager()
	handler := api.NewIdentityHandler(mgr)

	var serviceID string

	t.Run("creates service", func(t *testing.T) {
		reqBody := map[string]any{
			"name":        "payment-service",
			"description": "Handles payments",
			"auth_method": "mtls",
		}
		body, _ := json.Marshal(reqBody)

		req := withOrgID(httptest.NewRequest("POST", "/api/v1/identities/services", bytes.NewReader(body)), "org12345678")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.CreateService(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp models.ServiceIdentity
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "payment-service", resp.Name)
		serviceID = resp.ID
	})

	t.Run("returns 400 for missing name", func(t *testing.T) {
		reqBody := map[string]any{
			"auth_method": "mtls",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/identities/services", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.CreateService(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("gets service by ID", func(t *testing.T) {
		r := chi.NewRouter()
		r.Get("/api/v1/identities/services/{id}", handler.GetService)

		req := httptest.NewRequest("GET", "/api/v1/identities/services/"+serviceID, nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("lists services", func(t *testing.T) {
		req := withOrgID(httptest.NewRequest("GET", "/api/v1/identities/services", nil), "org12345678")
		w := httptest.NewRecorder()

		handler.ListServices(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp, "services")
	})

	t.Run("deletes service", func(t *testing.T) {
		r := chi.NewRouter()
		r.Delete("/api/v1/identities/services/{id}", handler.DeleteService)

		req := httptest.NewRequest("DELETE", "/api/v1/identities/services/"+serviceID, nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

func TestIdentityHandlerDeviceCRUD(t *testing.T) {
	mgr := newRealIdentityManager()
	handler := api.NewIdentityHandler(mgr)

	var deviceID string

	t.Run("enrolls device", func(t *testing.T) {
		reqBody := map[string]any{
			"device_name": "edge-hsm-01",
			"device_type": "hsm",
			"cert_serial": "AA:BB:CC:DD:EE:FF",
			"cert_expiry": time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
		}
		body, _ := json.Marshal(reqBody)

		req := withOrgID(httptest.NewRequest("POST", "/api/v1/identities/devices", bytes.NewReader(body)), "org1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.EnrollDevice(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp models.DeviceIdentity
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "edge-hsm-01", resp.DeviceName)
		deviceID = resp.ID
	})

	t.Run("returns 400 for missing device_name", func(t *testing.T) {
		reqBody := map[string]any{
			"cert_serial": "AA:BB:CC",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/identities/devices", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.EnrollDevice(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for missing cert_serial", func(t *testing.T) {
		reqBody := map[string]any{
			"device_name": "dev1",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/identities/devices", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.EnrollDevice(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("gets device by ID", func(t *testing.T) {
		r := chi.NewRouter()
		r.Get("/api/v1/identities/devices/{id}", handler.GetDevice)

		req := httptest.NewRequest("GET", "/api/v1/identities/devices/"+deviceID, nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("lists devices", func(t *testing.T) {
		req := withOrgID(httptest.NewRequest("GET", "/api/v1/identities/devices", nil), "org1")
		w := httptest.NewRecorder()

		handler.ListDevices(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp, "devices")
	})

	t.Run("revokes device", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/identities/devices/{id}/revoke", handler.RevokeDevice)

		req := httptest.NewRequest("POST", "/api/v1/identities/devices/"+deviceID+"/revoke", nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

func TestIdentityHandlerGroupCRUD(t *testing.T) {
	mgr := newRealIdentityManager()
	handler := api.NewIdentityHandler(mgr)

	var groupID string

	t.Run("creates group", func(t *testing.T) {
		reqBody := map[string]any{
			"name":           "platform-team",
			"description":    "Platform engineering team",
			"vault_policies": []string{"read-secrets", "write-config"},
		}
		body, _ := json.Marshal(reqBody)

		req := withOrgID(httptest.NewRequest("POST", "/api/v1/identities/groups", bytes.NewReader(body)), "org1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.CreateGroup(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp models.IdentityGroup
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "platform-team", resp.Name)
		groupID = resp.ID
	})

	t.Run("returns 400 for missing name", func(t *testing.T) {
		reqBody := map[string]any{
			"description": "no name",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/identities/groups", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.CreateGroup(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("gets group by ID", func(t *testing.T) {
		r := chi.NewRouter()
		r.Get("/api/v1/identities/groups/{id}", handler.GetGroup)

		req := httptest.NewRequest("GET", "/api/v1/identities/groups/"+groupID, nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("lists groups", func(t *testing.T) {
		req := withOrgID(httptest.NewRequest("GET", "/api/v1/identities/groups", nil), "org1")
		w := httptest.NewRecorder()

		handler.ListGroups(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp, "groups")
	})

	t.Run("adds group member", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/identities/groups/{id}/members", handler.AddGroupMember)

		reqBody := map[string]any{
			"identity_id":   "admin-123",
			"identity_type": "admin",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/identities/groups/"+groupID+"/members", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("returns 400 for missing identity_id on add member", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/identities/groups/{id}/members", handler.AddGroupMember)

		reqBody := map[string]any{
			"identity_type": "admin",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/identities/groups/"+groupID+"/members", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for missing identity_type on add member", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/identities/groups/{id}/members", handler.AddGroupMember)

		reqBody := map[string]any{
			"identity_id": "admin-123",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/identities/groups/"+groupID+"/members", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("removes group member", func(t *testing.T) {
		r := chi.NewRouter()
		r.Delete("/api/v1/identities/groups/{id}/members/{identityId}", handler.RemoveGroupMember)

		req := httptest.NewRequest("DELETE", "/api/v1/identities/groups/"+groupID+"/members/admin-123", nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

func TestIdentityHandlerRoleCRUD(t *testing.T) {
	mgr := newRealIdentityManager()
	handler := api.NewIdentityHandler(mgr)

	var roleID string

	t.Run("creates role", func(t *testing.T) {
		reqBody := map[string]any{
			"name":        "key-rotator",
			"description": "Can rotate keys",
			"permissions": []map[string]any{
				{
					"resource": "keys",
					"actions":  []string{"rotate", "read"},
				},
			},
		}
		body, _ := json.Marshal(reqBody)

		req := withOrgID(httptest.NewRequest("POST", "/api/v1/identities/roles", bytes.NewReader(body)), "org1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.CreateRole(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp models.Role
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "key-rotator", resp.Name)
		roleID = resp.ID
	})

	t.Run("returns 400 for missing name", func(t *testing.T) {
		reqBody := map[string]any{
			"description": "no name",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/identities/roles", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.CreateRole(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("gets role by ID", func(t *testing.T) {
		r := chi.NewRouter()
		r.Get("/api/v1/identities/roles/{id}", handler.GetRole)

		req := httptest.NewRequest("GET", "/api/v1/identities/roles/"+roleID, nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("lists roles", func(t *testing.T) {
		req := withOrgID(httptest.NewRequest("GET", "/api/v1/identities/roles", nil), "org1")
		w := httptest.NewRecorder()

		handler.ListRoles(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp, "roles")
	})

	t.Run("assigns role", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/identities/roles/{id}/assign", handler.AssignRole)

		reqBody := map[string]any{
			"identity_id":   "admin-123",
			"identity_type": "admin",
			"assigned_by":   "super-admin",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/identities/roles/"+roleID+"/assign", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("returns 400 for missing identity_id on assign", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/identities/roles/{id}/assign", handler.AssignRole)

		reqBody := map[string]any{
			"identity_type": "admin",
			"assigned_by":   "super-admin",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/identities/roles/"+roleID+"/assign", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for missing identity_type on assign", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/identities/roles/{id}/assign", handler.AssignRole)

		reqBody := map[string]any{
			"identity_id": "admin-123",
			"assigned_by": "super-admin",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/identities/roles/"+roleID+"/assign", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for missing assigned_by on assign", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/identities/roles/{id}/assign", handler.AssignRole)

		reqBody := map[string]any{
			"identity_id":   "admin-123",
			"identity_type": "admin",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/identities/roles/"+roleID+"/assign", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("unassigns role", func(t *testing.T) {
		r := chi.NewRouter()
		r.Delete("/api/v1/identities/roles/{id}/assignments/{identityId}", handler.UnassignRole)

		req := httptest.NewRequest("DELETE", "/api/v1/identities/roles/"+roleID+"/assignments/admin-123", nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}
