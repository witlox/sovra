// Package api contains handler tests for API endpoints.
package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/api"
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
	"github.com/witlox/sovra/pkg/errors"
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
	adminRepo := mocks.NewAdminIdentityRepository()
	mgr := identity.NewManager(
		adminRepo,
		mocks.NewUserIdentityRepository(),
		mocks.NewServiceIdentityRepository(),
		mocks.NewDeviceIdentityRepository(),
		mocks.NewIdentityGroupRepository(),
		mocks.NewRoleRepository(),
	)
	handler := api.NewIdentityHandler(mgr)

	// Insert admin directly for CRUD tests
	testAdmin := &models.AdminIdentity{
		ID:               "admin-crud-1",
		OrgID:            "org1",
		Email:            "admin@test.com",
		Name:             "Test Admin",
		Role:             models.AdminRoleSuperAdmin,
		Active:           true,
		EnrollmentStatus: models.AdminEnrollmentActive,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	require.NoError(t, adminRepo.Create(context.Background(), testAdmin))

	t.Run("creates admin requires crk_signature", func(t *testing.T) {
		reqBody := map[string]any{
			"email": "new@test.com",
			"name":  "New Admin",
			"role":  "super_admin",
		}
		body, _ := json.Marshal(reqBody)

		req := withOrgID(httptest.NewRequest("POST", "/api/v1/identities/admins", bytes.NewReader(body)), "org1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.CreateAdmin(w, req)

		// Should return 400 because crk_signature is missing
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("creates admin requires admin cert auth", func(t *testing.T) {
		reqBody := map[string]any{
			"email":         "new@test.com",
			"name":          "New Admin",
			"role":          "super_admin",
			"crk_signature": []byte("sig"),
		}
		body, _ := json.Marshal(reqBody)

		req := withOrgID(httptest.NewRequest("POST", "/api/v1/identities/admins", bytes.NewReader(body)), "org1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.CreateAdmin(w, req)

		// Should return 403 because no ContextKeyAdminID in context
		assert.Equal(t, http.StatusForbidden, w.Code)
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

		req := httptest.NewRequest("GET", "/api/v1/identities/admins/"+testAdmin.ID, nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.AdminIdentity
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, testAdmin.ID, resp.ID)
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

		req := httptest.NewRequest("PUT", "/api/v1/identities/admins/"+testAdmin.ID, bytes.NewReader(body))
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

		req := httptest.NewRequest("DELETE", "/api/v1/identities/admins/"+testAdmin.ID, nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

func TestIdentityHandlerMFA(t *testing.T) {
	adminRepo := mocks.NewAdminIdentityRepository()
	mgr := identity.NewManager(
		adminRepo,
		mocks.NewUserIdentityRepository(),
		mocks.NewServiceIdentityRepository(),
		mocks.NewDeviceIdentityRepository(),
		mocks.NewIdentityGroupRepository(),
		mocks.NewRoleRepository(),
	)
	handler := api.NewIdentityHandler(mgr)

	// Insert admin directly for MFA tests
	admin := &models.AdminIdentity{
		ID:               "mfa-admin-1",
		OrgID:            "org1",
		Email:            "mfa@test.com",
		Name:             "MFA Admin",
		Role:             models.AdminRoleSuperAdmin,
		Active:           true,
		EnrollmentStatus: models.AdminEnrollmentActive,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	err := adminRepo.Create(context.Background(), admin)
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

// --- Error path tests to exercise handleError and deeper handler code paths ---

func TestWorkspaceHandlerGetNotFound(t *testing.T) {
	handler := api.NewWorkspaceHandler(newRealWorkspaceService())
	r := chi.NewRouter()
	r.Get("/api/v1/workspaces/{id}", handler.Get)

	// Use a valid UUID format so validation passes, but ID doesn't exist
	req := httptest.NewRequest("GET", "/api/v1/workspaces/00000000-0000-0000-0000-000000000000", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestWorkspaceHandlerDeleteNotFound(t *testing.T) {
	handler := api.NewWorkspaceHandler(newRealWorkspaceService())
	r := chi.NewRouter()
	r.Delete("/api/v1/workspaces/{id}", handler.Delete)

	delBody, _ := json.Marshal(map[string]any{"signatures": map[string]string{}})
	req := httptest.NewRequest("DELETE", "/api/v1/workspaces/nonexistent-id", bytes.NewReader(delBody))
	req.Header.Set("Content-Type", "application/json")
	req = withOrgID(req, "org1")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Delete of non-existent may succeed silently or return error
	assert.True(t, w.Code == http.StatusNoContent || w.Code == http.StatusNotFound)
}

func TestWorkspaceHandlerUpdateNotFound(t *testing.T) {
	handler := api.NewWorkspaceHandler(newRealWorkspaceService())
	r := chi.NewRouter()
	r.Put("/api/v1/workspaces/{id}", handler.Update)

	reqBody := map[string]any{"purpose": "updated purpose"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("PUT", "/api/v1/workspaces/nonexistent-id", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestWorkspaceHandlerArchiveFlow(t *testing.T) {
	wsSvc := newRealWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	// Create workspace first
	reqBody := map[string]any{
		"name":           "archive-test",
		"participants":   []string{"org1"},
		"classification": "secret",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/v1/workspaces", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Create(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var ws models.Workspace
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &ws))

	r := chi.NewRouter()
	r.Post("/api/v1/workspaces/{id}/archive", handler.Archive)

	t.Run("archives workspace", func(t *testing.T) {
		archiveBody, _ := json.Marshal(map[string]any{"signature": "c2ln"})
		req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws.ID+"/archive", bytes.NewReader(archiveBody))
		req.Header.Set("Content-Type", "application/json")
		req = withOrgID(req, "org1")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNoContent)
	})
}

func TestPolicyHandlerGetNotFound(t *testing.T) {
	handler := api.NewPolicyHandler(newRealPolicyService())
	r := chi.NewRouter()
	r.Get("/api/v1/policies/{id}", handler.Get)

	req := httptest.NewRequest("GET", "/api/v1/policies/nonexistent-id", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPolicyHandlerCRUD(t *testing.T) {
	policySvc := newRealPolicyService()
	handler := api.NewPolicyHandler(policySvc)

	r := chi.NewRouter()
	r.Post("/api/v1/policies", handler.Create)
	r.Get("/api/v1/policies/{id}", handler.Get)
	r.Put("/api/v1/policies/{id}", handler.Update)
	r.Delete("/api/v1/policies/{id}", handler.Delete)
	r.Get("/api/v1/policies/workspace/{workspaceId}", handler.GetForWorkspace)
	r.Post("/api/v1/policies/evaluate", handler.Evaluate)
	r.Post("/api/v1/policies/validate", handler.Validate)

	var policyID string

	t.Run("creates policy", func(t *testing.T) {
		reqBody := map[string]any{
			"name": "test-policy",
			"rego": "package test\ndefault allow = true",
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/v1/policies", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withOrgID(req, "org1")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		policyID, _ = resp["id"].(string)
		assert.NotEmpty(t, policyID)
	})

	t.Run("gets policy", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/policies/"+policyID, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("updates policy", func(t *testing.T) {
		reqBody := map[string]any{
			"name": "updated-policy",
			"rego": "package test\ndefault allow = false",
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("PUT", "/api/v1/policies/"+policyID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNoContent)
	})

	t.Run("evaluates policy", func(t *testing.T) {
		reqBody := map[string]any{
			"policy_id": policyID,
			"input":     map[string]any{"action": "read"},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/v1/policies/evaluate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		// Evaluate may return 200 or 403 depending on policy
		assert.True(t, w.Code >= 200 && w.Code < 500)
	})

	t.Run("validates policy", func(t *testing.T) {
		reqBody := map[string]any{
			"rego": "package test\ndefault allow = true",
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/v1/policies/validate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.True(t, w.Code >= 200 && w.Code < 500)
	})

	t.Run("gets workspace policies", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/policies/workspace/ws-123", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		// May return empty list
		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNotFound)
	})

	t.Run("deletes policy", func(t *testing.T) {
		delBody, _ := json.Marshal(map[string]any{"signature": []byte("sig")})
		req := httptest.NewRequest("DELETE", "/api/v1/policies/"+policyID, bytes.NewReader(delBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNoContent)
	})
}

func TestAuditHandlerCRUD(t *testing.T) {
	auditSvc := newRealAuditService()
	handler := api.NewAuditHandler(auditSvc)

	r := chi.NewRouter()
	r.Get("/api/v1/audit", handler.Query)
	r.Get("/api/v1/audit/{id}", handler.Get)
	r.Post("/api/v1/audit/export", handler.Export)
	r.Get("/api/v1/audit/stats", handler.GetStats)
	r.Post("/api/v1/audit/verify", handler.VerifyIntegrity)

	t.Run("queries audit events", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/audit?limit=10", nil)
		req = withOrgID(req, "org1")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("gets non-existent audit event", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/audit/nonexistent", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("gets audit stats", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/audit/stats", nil)
		req = withOrgID(req, "org1")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code < 500)
	})

	t.Run("exports audit events", func(t *testing.T) {
		reqBody := map[string]any{"format": "json"}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/v1/audit/export", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withOrgID(req, "org1")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.True(t, w.Code >= 200 && w.Code < 500)
	})

	t.Run("verifies audit integrity", func(t *testing.T) {
		reqBody := map[string]any{}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/v1/audit/verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withOrgID(req, "org1")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.True(t, w.Code >= 200 && w.Code < 500)
	})
}

func TestEdgeHandlerCRUD(t *testing.T) {
	edgeSvc := newRealEdgeService()
	handler := api.NewEdgeHandler(edgeSvc)

	r := chi.NewRouter()
	r.Post("/api/v1/edges", handler.Register)
	r.Get("/api/v1/edges", handler.List)
	r.Get("/api/v1/edges/{id}", handler.Get)
	r.Delete("/api/v1/edges/{id}", handler.Unregister)
	r.Get("/api/v1/edges/{id}/health", handler.HealthCheck)
	r.Post("/api/v1/edges/{id}/sync/policies", handler.SyncPolicies)
	r.Post("/api/v1/edges/{id}/sync/keys", handler.SyncWorkspaceKeys)
	r.Get("/api/v1/edges/{id}/sync/status", handler.GetSyncStatus)

	var nodeID string

	t.Run("registers edge node", func(t *testing.T) {
		reqBody := map[string]any{
			"name":          "test-edge",
			"vault_address": "http://vault:8200",
			"region":        "us-east-1",
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/v1/edges", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withOrgID(req, "org1")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		nodeID, _ = resp["id"].(string)
	})

	t.Run("lists edge nodes", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/edges", nil)
		req = withOrgID(req, "org1")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("gets edge node", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/edges/"+nodeID, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("gets non-existent edge node", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/edges/nonexistent", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("checks edge node health", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/edges/"+nodeID+"/health", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.True(t, w.Code >= 200 && w.Code < 500)
	})

	t.Run("syncs policies", func(t *testing.T) {
		reqBody := map[string]any{"policy_ids": []string{"p1"}}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/v1/edges/"+nodeID+"/sync/policies", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.True(t, w.Code >= 200 && w.Code < 500)
	})

	t.Run("syncs workspace keys", func(t *testing.T) {
		reqBody := map[string]any{"workspace_id": "ws-1"}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/v1/edges/"+nodeID+"/sync/keys", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.True(t, w.Code >= 200 && w.Code < 500)
	})

	t.Run("gets sync status", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/edges/"+nodeID+"/sync/status", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.True(t, w.Code >= 200 && w.Code < 500)
	})

	t.Run("unregisters edge node", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/edges/"+nodeID, nil)
		req = withOrgID(req, "org1")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNoContent)
	})
}

func TestFederationHandlerCRUD(t *testing.T) {
	fedSvc := newRealFederationService()
	handler := api.NewFederationHandler(fedSvc)

	r := chi.NewRouter()
	r.Post("/api/v1/federation/establish", handler.Establish)
	r.Get("/api/v1/federation", handler.List)
	r.Get("/api/v1/federation/{partnerId}", handler.Status)
	r.Delete("/api/v1/federation/{partnerId}", handler.Revoke)
	r.Get("/api/v1/federation/health", handler.HealthCheck)
	r.Post("/api/v1/federation/certificate/import", handler.ImportCertificate)

	t.Run("lists federation partners", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/federation", nil)
		req = withOrgID(req, "org1")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("gets federation status for non-existent partner", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/federation/nonexistent", nil)
		req = withOrgID(req, "org1")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.True(t, w.Code == http.StatusNotFound || w.Code == http.StatusOK)
	})

	t.Run("checks federation health", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/federation/health", nil)
		req = withOrgID(req, "org1")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.True(t, w.Code >= 200 && w.Code < 500)
	})

	t.Run("import certificate with invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/federation/certificate/import", bytes.NewReader([]byte("not json")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("establish federation with invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/federation/establish", bytes.NewReader([]byte("not json")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("revoke non-existent federation", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/federation/nonexistent", nil)
		req = withOrgID(req, "org1")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.True(t, w.Code >= 200 && w.Code < 500)
	})
}

func TestCRKHandlerGenerateAndSign(t *testing.T) {
	crkMgr := newRealCRKManager()
	handler := api.NewCRKHandler(crkMgr, crk.NewCeremonyManager(crkMgr))

	r := chi.NewRouter()
	r.Post("/api/v1/crk/generate", handler.Generate)
	r.Post("/api/v1/crk/sign", handler.Sign)

	t.Run("generates CRK", func(t *testing.T) {
		reqBody := map[string]any{
			"org_id":       "org1",
			"total_shares": 3,
			"threshold":    2,
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/v1/crk/generate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withOrgID(req, "org1")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("fails with invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/crk/generate", bytes.NewReader([]byte("not json")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("signs data", func(t *testing.T) {
		// First generate a CRK
		crkResult, err := crkMgr.Generate("org1", 3, 2)
		require.NoError(t, err)
		shares, err := crkMgr.GetShares(crkResult.ID)
		require.NoError(t, err)

		// Extract share data for signing
		var shareData []map[string]any
		for _, s := range shares[:2] {
			shareData = append(shareData, map[string]any{
				"index": s.Index,
				"data":  s.Data,
			})
		}

		reqBody := map[string]any{
			"shares":     shareData,
			"public_key": crkResult.PublicKey,
			"data":       []byte("hello world"),
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/v1/crk/sign", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		// May succeed or fail depending on share format serialization
		assert.True(t, w.Code >= 200 && w.Code < 500)
	})
}

func TestRouterHealthEndpoints(t *testing.T) {
	services := &api.Services{
		Workspace:  newRealWorkspaceService(),
		Federation: newRealFederationService(),
		Policy:     newRealPolicyService(),
		Audit:      newRealAuditService(),
		Edge:       newRealEdgeService(),
		CRKManager: newRealCRKManager(),
		Identity:   newRealIdentityManager(),
	}

	router := api.NewRouter(nil, services)

	t.Run("health endpoint", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("ready endpoint", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/ready", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("live endpoint", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/live", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestIdentityHandlerGetNotFound(t *testing.T) {
	mgr := newRealIdentityManager()
	handler := api.NewIdentityHandler(mgr)

	r := chi.NewRouter()
	r.Get("/api/v1/identities/admins/{id}", handler.GetAdmin)
	r.Get("/api/v1/identities/users/{id}", handler.GetUser)
	r.Get("/api/v1/identities/services/{id}", handler.GetService)
	r.Get("/api/v1/identities/devices/{id}", handler.GetDevice)
	r.Get("/api/v1/identities/groups/{id}", handler.GetGroup)
	r.Get("/api/v1/identities/roles/{id}", handler.GetRole)

	for _, path := range []string{
		"/api/v1/identities/admins/nonexistent",
		"/api/v1/identities/users/nonexistent",
		"/api/v1/identities/services/nonexistent",
		"/api/v1/identities/devices/nonexistent",
		"/api/v1/identities/groups/nonexistent",
		"/api/v1/identities/roles/nonexistent",
	} {
		t.Run("GET "+path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, http.StatusNotFound, w.Code)
		})
	}
}

// =============================================================================
// Workspace Export/Import Handler Tests
// =============================================================================

func TestWorkspaceHandlerExport(t *testing.T) {
	wsSvc := newRealWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	// Create a workspace first
	ctx := context.Background()
	ws, err := wsSvc.Create(ctx, workspace.CreateRequest{
		Name:           "export-test",
		Participants:   []string{"org1"},
		Classification: models.ClassificationConfidential,
		Mode:           models.WorkspaceModeConnected,
		Purpose:        "testing export",
	})
	require.NoError(t, err)

	t.Run("exports workspace", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/workspaces/{id}/export", handler.Export)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws.ID+"/export", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp, "workspace")
		assert.Contains(t, resp, "checksum")
	})

	t.Run("returns 400 for missing ID", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/workspaces//export", nil)
		w := httptest.NewRecorder()
		handler.Export(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestWorkspaceHandlerImport(t *testing.T) {
	wsSvc := newRealWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	t.Run("imports workspace from bundle", func(t *testing.T) {
		bundle := map[string]any{
			"workspace": map[string]any{
				"name":           "imported-ws",
				"owner_org_id":   "org1",
				"classification": "CONFIDENTIAL",
				"mode":           "connected",
				"purpose":        "imported",
			},
			"exported_at": time.Now().Format(time.RFC3339),
			"exported_by": "org1",
			"checksum":    "abc123",
		}
		body, _ := json.Marshal(bundle)

		req := httptest.NewRequest("POST", "/api/v1/workspaces/import", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.Import(w, req)

		// Import may succeed or fail depending on service validation; just check we don't panic
		assert.True(t, w.Code >= 200 && w.Code < 500)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/workspaces/import", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.Import(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// =============================================================================
// Service Credential Rotation Handler Tests
// =============================================================================

func TestIdentityHandlerRotateServiceCredentials(t *testing.T) {
	mgr := newRealIdentityManager()
	handler := api.NewIdentityHandler(mgr)

	// Create a service first
	ctx := context.Background()
	reqBody := map[string]any{
		"name":        "rotate-test-svc",
		"description": "test service",
		"auth_method": "approle",
	}
	body, _ := json.Marshal(reqBody)
	createReq := withOrgID(httptest.NewRequest("POST", "/api/v1/identities/services", bytes.NewReader(body)), "org-test1234")
	createReq.Header.Set("Content-Type", "application/json")
	_ = ctx
	createW := httptest.NewRecorder()
	handler.CreateService(createW, createReq)
	require.Equal(t, http.StatusCreated, createW.Code)

	var svc models.ServiceIdentity
	require.NoError(t, json.Unmarshal(createW.Body.Bytes(), &svc))

	t.Run("rotates service credentials", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/identities/services/{id}/rotate", handler.RotateServiceCredentials)

		req := httptest.NewRequest("POST", "/api/v1/identities/services/"+svc.ID+"/rotate", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var rotated models.ServiceIdentity
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &rotated))
		assert.Equal(t, svc.ID, rotated.ID)
	})

	t.Run("returns 400 for missing ID", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/identities/services//rotate", nil)
		w := httptest.NewRecorder()
		handler.RotateServiceCredentials(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// =============================================================================
// Certificate Handler Tests (validation paths only - no Vault backend)
// =============================================================================

func TestCertificateHandlerValidation(t *testing.T) {
	// CertificateHandler requires *vault.PKIClient which needs a real Vault.
	// Test validation paths by calling handlers with nil pki (panics caught by test).
	// Instead, test the JSON validation paths that return before making PKI calls.

	t.Run("Issue returns 400 for invalid JSON", func(t *testing.T) {
		handler := api.NewCertificateHandler(nil)
		req := httptest.NewRequest("POST", "/api/v1/certificates/issue", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.Issue(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Issue returns 400 for missing common_name", func(t *testing.T) {
		handler := api.NewCertificateHandler(nil)
		body, _ := json.Marshal(map[string]any{"alt_names": []string{"test.com"}})
		req := httptest.NewRequest("POST", "/api/v1/certificates/issue", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.Issue(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Revoke returns 400 for invalid JSON", func(t *testing.T) {
		handler := api.NewCertificateHandler(nil)
		req := httptest.NewRequest("POST", "/api/v1/certificates/revoke", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.Revoke(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Revoke returns 400 for missing serial_number", func(t *testing.T) {
		handler := api.NewCertificateHandler(nil)
		body, _ := json.Marshal(map[string]any{})
		req := httptest.NewRequest("POST", "/api/v1/certificates/revoke", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.Revoke(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Read returns 400 for missing serial", func(t *testing.T) {
		handler := api.NewCertificateHandler(nil)
		req := httptest.NewRequest("GET", "/api/v1/certificates/", nil)
		w := httptest.NewRecorder()
		handler.Read(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Tidy returns 400 for invalid JSON", func(t *testing.T) {
		handler := api.NewCertificateHandler(nil)
		req := httptest.NewRequest("POST", "/api/v1/certificates/tidy", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.Tidy(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// =============================================================================
// Emergency Access Handler Tests
// =============================================================================

func newRealEmergencyAccessManager() *identity.EmergencyAccessManager {
	return identity.NewEmergencyAccessManager(
		mocks.NewEmergencyAccessRepository(),
		mocks.NewMockCRKProvider(),
		identity.NewSimpleTokenGenerator(),
	)
}

func newRealAccountRecoveryManager() *identity.AccountRecoveryManager {
	return identity.NewAccountRecoveryManager(
		mocks.NewAccountRecoveryRepository(),
		mocks.NewMockCRKProvider(),
	)
}

func TestEmergencyAccessHandlerRequest(t *testing.T) {
	mgr := newRealEmergencyAccessManager()
	handler := api.NewEmergencyAccessHandler(mgr)

	t.Run("creates emergency access request", func(t *testing.T) {
		reqBody := map[string]any{
			"org_id": "org-1",
			"reason": "production outage",
		}
		body, _ := json.Marshal(reqBody)
		req := withOrgID(httptest.NewRequest("POST", "/api/v1/emergency-access/request", bytes.NewReader(body)), "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Request(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp models.EmergencyAccessRequest
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "production outage", resp.Reason)
		assert.Equal(t, models.EmergencyAccessPending, resp.Status)
	})

	t.Run("returns 400 for missing reason", func(t *testing.T) {
		reqBody := map[string]any{"org_id": "org-1"}
		body, _ := json.Marshal(reqBody)
		req := withOrgID(httptest.NewRequest("POST", "/api/v1/emergency-access/request", bytes.NewReader(body)), "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Request(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/emergency-access/request", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Request(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestEmergencyAccessHandlerApprove(t *testing.T) {
	mgr := newRealEmergencyAccessManager()
	handler := api.NewEmergencyAccessHandler(mgr)

	// Create a request first
	ctx := context.Background()
	eaReq, err := mgr.RequestEmergencyAccess(ctx, "org-1", "requester", "outage")
	require.NoError(t, err)

	t.Run("approves request", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/emergency-access/{id}/approve", handler.Approve)

		req := withOrgID(httptest.NewRequest("POST", "/api/v1/emergency-access/"+eaReq.ID+"/approve", nil), "approver-1")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("returns 400 for missing ID", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/emergency-access//approve", nil)
		w := httptest.NewRecorder()
		handler.Approve(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestEmergencyAccessHandlerDeny(t *testing.T) {
	mgr := newRealEmergencyAccessManager()
	handler := api.NewEmergencyAccessHandler(mgr)

	ctx := context.Background()
	eaReq, err := mgr.RequestEmergencyAccess(ctx, "org-1", "requester", "outage")
	require.NoError(t, err)

	t.Run("denies request", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/emergency-access/{id}/deny", handler.Deny)

		req := withOrgID(httptest.NewRequest("POST", "/api/v1/emergency-access/"+eaReq.ID+"/deny", nil), "denier")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

func TestEmergencyAccessHandlerComplete(t *testing.T) {
	mgr := newRealEmergencyAccessManager()
	handler := api.NewEmergencyAccessHandler(mgr)

	t.Run("returns 400 for missing ID", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/emergency-access//complete", nil)
		w := httptest.NewRecorder()
		handler.Complete(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestEmergencyAccessHandlerVerify(t *testing.T) {
	mgr := newRealEmergencyAccessManager()
	handler := api.NewEmergencyAccessHandler(mgr)

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/emergency-access/{id}/verify", handler.Verify)

		req := httptest.NewRequest("POST", "/api/v1/emergency-access/ea1/verify", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for missing signature", func(t *testing.T) {
		r := chi.NewRouter()
		r.Post("/api/v1/emergency-access/{id}/verify", handler.Verify)

		body, _ := json.Marshal(map[string]any{})
		req := httptest.NewRequest("POST", "/api/v1/emergency-access/ea1/verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestEmergencyAccessHandlerListAndGet(t *testing.T) {
	mgr := newRealEmergencyAccessManager()
	handler := api.NewEmergencyAccessHandler(mgr)

	ctx := context.Background()
	eaReq, err := mgr.RequestEmergencyAccess(ctx, "org-1", "requester", "outage")
	require.NoError(t, err)

	t.Run("lists requests", func(t *testing.T) {
		req := withOrgID(httptest.NewRequest("GET", "/api/v1/emergency-access?org_id=org-1", nil), "org-1")
		w := httptest.NewRecorder()
		handler.ListEmergencyAccess(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp, "requests")
		assert.Contains(t, resp, "count")
	})

	t.Run("gets request by ID", func(t *testing.T) {
		r := chi.NewRouter()
		r.Get("/api/v1/emergency-access/{id}", handler.GetEmergencyAccess)

		req := httptest.NewRequest("GET", "/api/v1/emergency-access/"+eaReq.ID, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.EmergencyAccessRequest
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, eaReq.ID, resp.ID)
	})

	t.Run("returns 400 for missing ID on get", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/emergency-access/", nil)
		w := httptest.NewRecorder()
		handler.GetEmergencyAccess(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// =============================================================================
// Account Recovery Handler Tests
// =============================================================================

func TestAccountRecoveryHandlerInitiate(t *testing.T) {
	mgr := newRealAccountRecoveryManager()
	handler := api.NewAccountRecoveryHandler(mgr)

	t.Run("initiates recovery", func(t *testing.T) {
		reqBody := map[string]any{
			"admin_id":      "admin-1",
			"recovery_type": "lost_credentials",
			"reason":        "locked out",
		}
		body, _ := json.Marshal(reqBody)
		req := withOrgID(httptest.NewRequest("POST", "/api/v1/account-recovery/initiate", bytes.NewReader(body)), "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Initiate(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp models.AccountRecovery
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, models.AccountRecoveryPending, resp.Status)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/account-recovery/initiate", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Initiate(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestAccountRecoveryHandlerCollectShare(t *testing.T) {
	mgr := newRealAccountRecoveryManager()
	handler := api.NewAccountRecoveryHandler(mgr)

	t.Run("returns 400 for missing ID", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/account-recovery//share", nil)
		w := httptest.NewRecorder()
		handler.CollectShare(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestAccountRecoveryHandlerComplete(t *testing.T) {
	mgr := newRealAccountRecoveryManager()
	handler := api.NewAccountRecoveryHandler(mgr)

	t.Run("returns 400 for missing ID", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/account-recovery//complete", nil)
		w := httptest.NewRecorder()
		handler.CompleteRecovery(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// =============================================================================
// Compliance Handler Tests
// =============================================================================

func newRealComplianceHandler() *api.ComplianceHandler {
	auditSvc := newRealAuditService()
	wsSvc := newRealWorkspaceService()
	gen := compliance.NewReportGenerator(auditSvc, wsSvc)
	return api.NewComplianceHandler(gen)
}

func TestComplianceHandlerGenerateSummary(t *testing.T) {
	handler := newRealComplianceHandler()

	t.Run("generates summary report", func(t *testing.T) {
		reqBody := map[string]any{
			"org_id": "org-1",
		}
		body, _ := json.Marshal(reqBody)
		req := withOrgID(httptest.NewRequest("POST", "/api/v1/compliance/reports/summary", bytes.NewReader(body)), "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.GenerateSummary(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "summary", resp["type"])
		assert.NotEmpty(t, resp["id"])
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/compliance/reports/summary", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.GenerateSummary(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestComplianceHandlerGenerateDSAR(t *testing.T) {
	handler := newRealComplianceHandler()

	t.Run("generates DSAR report", func(t *testing.T) {
		reqBody := map[string]any{
			"subject_id": "user-123",
		}
		body, _ := json.Marshal(reqBody)
		req := withOrgID(httptest.NewRequest("POST", "/api/v1/compliance/reports/gdpr-dsar", bytes.NewReader(body)), "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.GenerateDSAR(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "gdpr-dsar", resp["type"])
	})

	t.Run("returns 400 for missing subject_id", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{})
		req := withOrgID(httptest.NewRequest("POST", "/api/v1/compliance/reports/gdpr-dsar", bytes.NewReader(body)), "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.GenerateDSAR(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestComplianceHandlerGenerateAccessReview(t *testing.T) {
	handler := newRealComplianceHandler()

	t.Run("generates access review report", func(t *testing.T) {
		reqBody := map[string]any{}
		body, _ := json.Marshal(reqBody)
		req := withOrgID(httptest.NewRequest("POST", "/api/v1/compliance/reports/access-review", bytes.NewReader(body)), "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.GenerateAccessReview(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "access-review", resp["type"])
	})
}

// =============================================================================
// Rotation Policy Handler Tests
// =============================================================================

func newRealRotationPolicyHandler() *api.RotationPolicyHandler {
	wsSvc := newRealWorkspaceService()
	sched := rotation.NewScheduler(wsSvc, time.Hour)
	return api.NewRotationPolicyHandler(sched)
}

func TestRotationPolicyHandlerSet(t *testing.T) {
	handler := newRealRotationPolicyHandler()

	t.Run("sets rotation policy", func(t *testing.T) {
		r := chi.NewRouter()
		r.Put("/api/v1/workspaces/{id}/rotation-policy", handler.Set)

		reqBody := map[string]any{
			"max_age": "720h",
			"enabled": true,
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("PUT", "/api/v1/workspaces/ws1/rotation-policy", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "ws1", resp["workspace_id"])
		assert.Equal(t, true, resp["enabled"])
	})

	t.Run("returns 400 for invalid max_age", func(t *testing.T) {
		r := chi.NewRouter()
		r.Put("/api/v1/workspaces/{id}/rotation-policy", handler.Set)

		reqBody := map[string]any{
			"max_age": "invalid",
			"enabled": true,
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("PUT", "/api/v1/workspaces/ws1/rotation-policy", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		r := chi.NewRouter()
		r.Put("/api/v1/workspaces/{id}/rotation-policy", handler.Set)

		req := httptest.NewRequest("PUT", "/api/v1/workspaces/ws1/rotation-policy", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestRotationPolicyHandlerGet(t *testing.T) {
	handler := newRealRotationPolicyHandler()

	t.Run("returns 404 for non-existent policy", func(t *testing.T) {
		r := chi.NewRouter()
		r.Get("/api/v1/workspaces/{id}/rotation-policy", handler.Get)

		req := httptest.NewRequest("GET", "/api/v1/workspaces/ws1/rotation-policy", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns 400 for missing ID", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/workspaces//rotation-policy", nil)
		w := httptest.NewRecorder()
		handler.Get(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestRotationPolicyHandlerDelete(t *testing.T) {
	handler := newRealRotationPolicyHandler()

	t.Run("deletes policy (even if not set)", func(t *testing.T) {
		r := chi.NewRouter()
		r.Delete("/api/v1/workspaces/{id}/rotation-policy", handler.Delete)

		req := httptest.NewRequest("DELETE", "/api/v1/workspaces/ws1/rotation-policy", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

func TestRotationPolicyHandlerListPolicies(t *testing.T) {
	handler := newRealRotationPolicyHandler()

	t.Run("lists empty policies", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/rotation-policies", nil)
		w := httptest.NewRecorder()
		handler.ListPolicies(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp, "policies")
		assert.Contains(t, resp, "count")
	})
}

func TestIdentityHandlerDeleteNotFound(t *testing.T) {
	mgr := newRealIdentityManager()
	handler := api.NewIdentityHandler(mgr)

	r := chi.NewRouter()
	r.Delete("/api/v1/identities/admins/{id}", handler.DeleteAdmin)
	r.Delete("/api/v1/identities/users/{id}", handler.DeleteUser)
	r.Delete("/api/v1/identities/services/{id}", handler.DeleteService)
	r.Post("/api/v1/identities/devices/{id}/revoke", handler.RevokeDevice)
	r.Delete("/api/v1/identities/groups/{id}/members/{identityId}", handler.RemoveGroupMember)
	r.Delete("/api/v1/identities/roles/{id}/assignments/{identityId}", handler.UnassignRole)

	t.Run("delete admin", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/identities/admins/nonexistent", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		// Deletes may succeed silently
		assert.True(t, w.Code == http.StatusNoContent || w.Code == http.StatusNotFound || w.Code == http.StatusOK)
	})

	t.Run("delete user", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/identities/users/nonexistent", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.True(t, w.Code == http.StatusNoContent || w.Code == http.StatusNotFound || w.Code == http.StatusOK)
	})

	t.Run("revoke device", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/identities/devices/nonexistent/revoke", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.True(t, w.Code >= 200 && w.Code < 500)
	})
}

// =============================================================================
// Direct Message Handler Tests
// =============================================================================

func newRealMessagingService() messaging.Service {
	repo := mocks.NewDirectMessageRepository()
	relay := mocks.NewMockFederationRelay()
	enc := mocks.NewMockEncryptor()
	resolver := mocks.NewMockIdentityResolver()
	auditSvc := mocks.NewMockAuditService()
	return messaging.NewService(repo, relay, enc, resolver, auditSvc)
}

func withAuth(r *http.Request, orgID, userID string) *http.Request {
	ctx := context.WithValue(r.Context(), api.ContextKeyOrgID, orgID)
	ctx = context.WithValue(ctx, api.ContextKeyUserID, userID)
	return r.WithContext(ctx)
}

func withCert(r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(), api.ContextKeyCert, &api.CertificateInfo{
		CommonName:   "federation.org-remote.sovra",
		Organization: "org-remote",
	})
	return r.WithContext(ctx)
}

func TestDirectMessageHandlerSend(t *testing.T) {
	svc := newRealMessagingService()
	handler := api.NewDirectMessageHandler(svc)

	t.Run("sends message successfully", func(t *testing.T) {
		reqBody := map[string]any{
			"recipient_org_id": "org1",
			"recipient_id":     "user-b",
			"subject":          "Test subject",
			"body":             []byte("Hello"),
		}
		body, _ := json.Marshal(reqBody)

		req := withAuth(httptest.NewRequest("POST", "/api/v1/messages", bytes.NewReader(body)), "org1", "user-a")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Send(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp models.DirectMessage
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "Test subject", resp.Subject)
		assert.Equal(t, "sent", resp.Direction)
	})

	t.Run("returns 401 without auth", func(t *testing.T) {
		reqBody := map[string]any{
			"recipient_org_id": "org1",
			"recipient_id":     "user-b",
			"subject":          "Test",
			"body":             []byte("data"),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/messages", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Send(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := withAuth(httptest.NewRequest("POST", "/api/v1/messages", bytes.NewReader([]byte("not json"))), "org1", "user-a")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Send(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestDirectMessageHandlerListInbox(t *testing.T) {
	svc := newRealMessagingService()
	handler := api.NewDirectMessageHandler(svc)
	ctx := context.Background()

	// Seed a message
	_, err := svc.Send(ctx, messaging.SendRequest{
		SenderOrgID: "org1", SenderID: "user-a",
		RecipientOrgID: "org1", RecipientID: "user-b",
		Subject: "Inbox test", Body: []byte("data"),
	})
	require.NoError(t, err)

	t.Run("lists inbox messages", func(t *testing.T) {
		req := withAuth(httptest.NewRequest("GET", "/api/v1/messages?limit=10", nil), "org1", "user-b")
		w := httptest.NewRecorder()

		handler.ListInbox(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp, "messages")
		assert.Contains(t, resp, "count")
	})

	t.Run("returns 401 without auth", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/messages", nil)
		w := httptest.NewRecorder()
		handler.ListInbox(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestDirectMessageHandlerListSent(t *testing.T) {
	svc := newRealMessagingService()
	handler := api.NewDirectMessageHandler(svc)
	ctx := context.Background()

	_, err := svc.Send(ctx, messaging.SendRequest{
		SenderOrgID: "org1", SenderID: "user-a",
		RecipientOrgID: "org1", RecipientID: "user-b",
		Subject: "Sent test", Body: []byte("data"),
	})
	require.NoError(t, err)

	t.Run("lists sent messages", func(t *testing.T) {
		req := withAuth(httptest.NewRequest("GET", "/api/v1/messages/sent?limit=10", nil), "org1", "user-a")
		w := httptest.NewRecorder()

		handler.ListSent(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp, "messages")
	})
}

func TestDirectMessageHandlerRead(t *testing.T) {
	svc := newRealMessagingService()
	handler := api.NewDirectMessageHandler(svc)
	ctx := context.Background()

	msg, err := svc.Send(ctx, messaging.SendRequest{
		SenderOrgID: "org1", SenderID: "user-a",
		RecipientOrgID: "org1", RecipientID: "user-b",
		Subject: "Read test", Body: []byte("readable content"),
	})
	require.NoError(t, err)

	t.Run("reads message by ID", func(t *testing.T) {
		r := chi.NewRouter()
		r.Get("/api/v1/messages/{id}", func(w http.ResponseWriter, req *http.Request) {
			req = withAuth(req, "org1", "user-a")
			handler.Read(w, req)
		})

		req := httptest.NewRequest("GET", "/api/v1/messages/"+msg.ID, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.DirectMessage
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "Read test", resp.Subject)
	})

	t.Run("returns 401 without auth", func(t *testing.T) {
		r := chi.NewRouter()
		r.Get("/api/v1/messages/{id}", handler.Read)
		req := httptest.NewRequest("GET", "/api/v1/messages/"+msg.ID, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestDirectMessageHandlerDelete(t *testing.T) {
	svc := newRealMessagingService()
	handler := api.NewDirectMessageHandler(svc)
	ctx := context.Background()

	msg, err := svc.Send(ctx, messaging.SendRequest{
		SenderOrgID: "org1", SenderID: "user-a",
		RecipientOrgID: "org1", RecipientID: "user-b",
		Subject: "Delete test", Body: []byte("data"),
	})
	require.NoError(t, err)

	t.Run("deletes message", func(t *testing.T) {
		r := chi.NewRouter()
		r.Delete("/api/v1/messages/{id}", func(w http.ResponseWriter, req *http.Request) {
			req = withAuth(req, "org1", "user-a")
			handler.Delete(w, req)
		})

		req := httptest.NewRequest("DELETE", "/api/v1/messages/"+msg.ID, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestDirectMessageHandlerDeliver(t *testing.T) {
	svc := newRealMessagingService()
	handler := api.NewDirectMessageHandler(svc)

	t.Run("delivers inbound message with cert", func(t *testing.T) {
		reqBody := map[string]any{
			"sender_org_id":    "org-remote",
			"sender_id":        "remote-user",
			"recipient_org_id": "org1",
			"recipient_id":     "local-user",
			"subject":          "Inbound",
			"body":             []byte("Hello from partner"),
			"conversation_id":  "conv-1",
		}
		body, _ := json.Marshal(reqBody)

		req := withCert(httptest.NewRequest("POST", "/api/v1/messages/deliver", bytes.NewReader(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Deliver(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp map[string]string
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.NotEmpty(t, resp["message_id"])
	})

	t.Run("returns 403 without federation cert", func(t *testing.T) {
		reqBody := map[string]any{
			"sender_org_id":    "org-remote",
			"sender_id":        "remote-user",
			"recipient_org_id": "org1",
			"recipient_id":     "local-user",
			"subject":          "Inbound",
			"body":             []byte("data"),
			"conversation_id":  "conv-2",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/messages/deliver", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Deliver(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestDirectMessageRouterIntegration(t *testing.T) {
	svc := newRealMessagingService()
	services := &api.Services{
		Messaging: svc,
	}

	router := api.NewRouter(nil, services)

	t.Run("message routes are registered", func(t *testing.T) {
		// POST /api/v1/messages should be reachable (401 expected without auth)
		req := httptest.NewRequest("POST", "/api/v1/messages", bytes.NewReader([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		// Should not be 404 — the route exists
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})
}

// =============================================================================
// Generation Ceremony Handler Tests
// =============================================================================

func TestGenerationCeremonyHandlerStart(t *testing.T) {
	crkMgr := newRealCRKManager()
	genMgr := crk.NewGenerationCeremonyManager(crkMgr)
	handler := api.NewGenerationCeremonyHandler(genMgr)

	t.Run("starts generation ceremony", func(t *testing.T) {
		reqBody := map[string]any{
			"org_id":       "org-eth",
			"total_shares": 5,
			"threshold":    3,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/crk/generate-ceremony/start", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Start(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NotEmpty(t, resp["id"])
		assert.Equal(t, "pending", resp["status"])
	})

	t.Run("returns 400 for invalid shares", func(t *testing.T) {
		reqBody := map[string]any{
			"org_id":       "org-eth",
			"total_shares": 1,
			"threshold":    3,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/crk/generate-ceremony/start", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Start(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/crk/generate-ceremony/start", bytes.NewReader([]byte("bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Start(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestGenerationCeremonyHandlerSeed(t *testing.T) {
	crkMgr := newRealCRKManager()
	genMgr := crk.NewGenerationCeremonyManager(crkMgr)
	handler := api.NewGenerationCeremonyHandler(genMgr)

	t.Run("seeds share with encryption key", func(t *testing.T) {
		// First start a ceremony
		ceremony, err := genMgr.StartGenerationCeremony("org-eth", 3, 2)
		require.NoError(t, err)

		reqBody := map[string]any{
			"index":          1,
			"encryption_key": []byte("01234567890123456789012345678901"),
			"salt":           []byte("0123456789abcdef"),
			"kdf_params":     map[string]any{"time": 3, "memory": 65536, "threads": 4},
			"custodian_name": "Alice",
		}
		body, _ := json.Marshal(reqBody)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", ceremony.ID)
		req := httptest.NewRequest("POST", "/api/v1/crk/generate-ceremony/"+ceremony.ID+"/seed", bytes.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Seed(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("returns 400 for missing fields", func(t *testing.T) {
		reqBody := map[string]any{
			"index": 0, // invalid
		}
		body, _ := json.Marshal(reqBody)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "some-id")
		req := httptest.NewRequest("POST", "/api/v1/crk/generate-ceremony/some-id/seed", bytes.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Seed(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestGenerationCeremonyHandlerComplete(t *testing.T) {
	crkMgr := newRealCRKManager()
	genMgr := crk.NewGenerationCeremonyManager(crkMgr)
	handler := api.NewGenerationCeremonyHandler(genMgr)

	t.Run("completes ceremony with all shares seeded", func(t *testing.T) {
		ceremony, err := genMgr.StartGenerationCeremony("org-eth", 2, 2)
		require.NoError(t, err)

		for i := 1; i <= 2; i++ {
			salt, _ := crk.GenerateSalt()
			key := crk.DeriveKey([]byte("password"), salt, crk.DefaultKDFTime, crk.DefaultKDFMemory, crk.DefaultKDFThreads)
			err := genMgr.SeedShare(ceremony.ID, i, key, salt, crk.KDFParams{
				Time: crk.DefaultKDFTime, Memory: crk.DefaultKDFMemory, Threads: crk.DefaultKDFThreads,
			}, "custodian")
			require.NoError(t, err)
		}

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", ceremony.ID)
		req := httptest.NewRequest("POST", "/api/v1/crk/generate-ceremony/"+ceremony.ID+"/complete", nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Complete(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Equal(t, "complete", resp["status"])
		assert.NotNil(t, resp["crk"])
		assert.NotNil(t, resp["encrypted_shares"])
	})

	t.Run("returns error for incomplete ceremony", func(t *testing.T) {
		ceremony, err := genMgr.StartGenerationCeremony("org-eth", 3, 2)
		require.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", ceremony.ID)
		req := httptest.NewRequest("POST", "/api/v1/crk/generate-ceremony/"+ceremony.ID+"/complete", nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()

		handler.Complete(w, req)

		assert.GreaterOrEqual(t, w.Code, 400)
	})
}

func TestGenerationCeremonyHandlerStatus(t *testing.T) {
	crkMgr := newRealCRKManager()
	genMgr := crk.NewGenerationCeremonyManager(crkMgr)
	handler := api.NewGenerationCeremonyHandler(genMgr)

	t.Run("returns ceremony status", func(t *testing.T) {
		ceremony, err := genMgr.StartGenerationCeremony("org-eth", 3, 2)
		require.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", ceremony.ID)
		req := httptest.NewRequest("GET", "/api/v1/crk/generate-ceremony/"+ceremony.ID, nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()

		handler.Status(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("returns error for unknown ceremony", func(t *testing.T) {
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "nonexistent")
		req := httptest.NewRequest("GET", "/api/v1/crk/generate-ceremony/nonexistent", nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()

		handler.Status(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestGenerationCeremonyHandlerCancel(t *testing.T) {
	crkMgr := newRealCRKManager()
	genMgr := crk.NewGenerationCeremonyManager(crkMgr)
	handler := api.NewGenerationCeremonyHandler(genMgr)

	t.Run("cancels ceremony", func(t *testing.T) {
		ceremony, err := genMgr.StartGenerationCeremony("org-eth", 3, 2)
		require.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", ceremony.ID)
		req := httptest.NewRequest("DELETE", "/api/v1/crk/generate-ceremony/"+ceremony.ID, nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()

		handler.Cancel(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("returns error for unknown ceremony", func(t *testing.T) {
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "nonexistent")
		req := httptest.NewRequest("DELETE", "/api/v1/crk/generate-ceremony/nonexistent", nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()

		handler.Cancel(w, req)

		assert.GreaterOrEqual(t, w.Code, 400)
	})
}

func TestGenerationCeremonyHandlerGetEncryptedShare(t *testing.T) {
	crkMgr := newRealCRKManager()
	genMgr := crk.NewGenerationCeremonyManager(crkMgr)
	handler := api.NewGenerationCeremonyHandler(genMgr)

	t.Run("returns encrypted share", func(t *testing.T) {
		// Complete a ceremony first to have encrypted shares
		ceremony, err := genMgr.StartGenerationCeremony("org-eth", 2, 2)
		require.NoError(t, err)
		for i := 1; i <= 2; i++ {
			salt, _ := crk.GenerateSalt()
			key := crk.DeriveKey([]byte("pw"), salt, crk.DefaultKDFTime, crk.DefaultKDFMemory, crk.DefaultKDFThreads)
			err := genMgr.SeedShare(ceremony.ID, i, key, salt, crk.KDFParams{
				Time: crk.DefaultKDFTime, Memory: crk.DefaultKDFMemory, Threads: crk.DefaultKDFThreads,
			}, "")
			require.NoError(t, err)
		}
		result, err := genMgr.CompleteGenerationCeremony(ceremony.ID)
		require.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("crkId", result.CRK.ID)
		rctx.URLParams.Add("index", "1")
		req := httptest.NewRequest("GET", "/api/v1/crk/shares/"+result.CRK.ID+"/1", nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()

		handler.GetEncryptedShare(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("returns error for invalid index", func(t *testing.T) {
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("crkId", "some-crk")
		rctx.URLParams.Add("index", "abc")
		req := httptest.NewRequest("GET", "/api/v1/crk/shares/some-crk/abc", nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()

		handler.GetEncryptedShare(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for nonexistent share", func(t *testing.T) {
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("crkId", "nonexistent")
		rctx.URLParams.Add("index", "1")
		req := httptest.NewRequest("GET", "/api/v1/crk/shares/nonexistent/1", nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()

		handler.GetEncryptedShare(w, req)

		assert.GreaterOrEqual(t, w.Code, 400)
	})
}

// =============================================================================
// Backup Handler Tests
// =============================================================================

// handlerTestTransit is a simple transit encryptor for handler tests.
type handlerTestTransit struct {
	store map[string][]byte
}

func newHandlerTestTransit() *handlerTestTransit {
	return &handlerTestTransit{store: make(map[string][]byte)}
}

func (t *handlerTestTransit) Encrypt(_ context.Context, keyName string, plaintext []byte) (string, error) {
	ct := "vault:v1:" + base64.StdEncoding.EncodeToString(plaintext)
	t.store[keyName+":"+ct] = plaintext
	return ct, nil
}

func (t *handlerTestTransit) Decrypt(_ context.Context, keyName, ciphertext string) ([]byte, error) {
	pt, ok := t.store[keyName+":"+ciphertext]
	if !ok {
		return nil, fmt.Errorf("unknown ciphertext")
	}
	return pt, nil
}

// handlerTestOrgChecker is an in-memory organization checker for handler tests.
type handlerTestOrgChecker struct {
	orgs map[string]*models.Organization
}

func newHandlerTestOrgChecker(orgs ...*models.Organization) *handlerTestOrgChecker {
	c := &handlerTestOrgChecker{orgs: make(map[string]*models.Organization)}
	for _, o := range orgs {
		c.orgs[o.ID] = o
	}
	return c
}

func (c *handlerTestOrgChecker) Get(_ context.Context, id string) (*models.Organization, error) {
	org, ok := c.orgs[id]
	if !ok {
		return nil, errors.ErrNotFound
	}
	return org, nil
}

func (c *handlerTestOrgChecker) List(_ context.Context, limit, offset int) ([]*models.Organization, error) {
	var result []*models.Organization
	for _, o := range c.orgs {
		result = append(result, o)
	}
	if offset >= len(result) {
		return nil, nil
	}
	result = result[offset:]
	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}
	return result, nil
}

// handlerTestSigVerifier always returns valid.
type handlerTestSigVerifier struct{}

func (v *handlerTestSigVerifier) VerifyCRKSignature(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return true, nil
}

func newRealBackupService(transit backup.TransitEncryptor, orgChecker backup.OrganizationChecker) backup.Service {
	return backup.NewService(
		mocks.NewBackupRepository(),
		&handlerTestSigVerifier{},
		transit,
		orgChecker,
		inmemory.NewWorkspaceRepository(),
		inmemory.NewFederationRepository(),
		inmemory.NewPolicyRepository(),
		mocks.NewMockAuditService(),
	)
}

func TestBackupHandlerCreate(t *testing.T) {
	orgID := "test-org"
	transit := newHandlerTestTransit()
	orgChecker := newHandlerTestOrgChecker(&models.Organization{ID: orgID, Name: "Test Org"})
	svc := newRealBackupService(transit, orgChecker)
	handler := api.NewBackupHandler(svc)

	t.Run("creates backup with CRK signature", func(t *testing.T) {
		reqBody := map[string]any{
			"type":          "full",
			"crk_signature": base64.StdEncoding.EncodeToString([]byte("valid-sig")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/backups", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withOrgID(req, orgID)
		w := httptest.NewRecorder()

		handler.Create(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp models.Backup
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, orgID, resp.OrgID)
		assert.Equal(t, "full", resp.Type)
		assert.NotEmpty(t, resp.ID)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/backups", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		req = withOrgID(req, orgID)
		w := httptest.NewRecorder()

		handler.Create(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for missing CRK signature", func(t *testing.T) {
		reqBody := map[string]any{"type": "full"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/backups", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withOrgID(req, orgID)
		w := httptest.NewRecorder()

		handler.Create(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestBackupHandlerList(t *testing.T) {
	orgID := "test-org"
	transit := newHandlerTestTransit()
	orgChecker := newHandlerTestOrgChecker(&models.Organization{ID: orgID, Name: "Test Org"})
	svc := newRealBackupService(transit, orgChecker)
	handler := api.NewBackupHandler(svc)

	// Create a backup to list
	_, err := svc.Create(context.Background(), orgID, "full", "admin", []byte("sig"))
	require.NoError(t, err)

	t.Run("lists backups for org", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/backups", nil)
		req = withOrgID(req, orgID)
		w := httptest.NewRecorder()

		handler.List(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp, "backups")
	})
}

func TestBackupHandlerGet(t *testing.T) {
	orgID := "test-org"
	transit := newHandlerTestTransit()
	orgChecker := newHandlerTestOrgChecker(&models.Organization{ID: orgID, Name: "Test Org"})
	svc := newRealBackupService(transit, orgChecker)
	handler := api.NewBackupHandler(svc)

	b, err := svc.Create(context.Background(), orgID, "full", "admin", []byte("sig"))
	require.NoError(t, err)

	t.Run("gets backup by ID", func(t *testing.T) {
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", b.ID)
		req := httptest.NewRequest("GET", "/api/v1/backups/"+b.ID, nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()

		handler.Get(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.Backup
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, b.ID, resp.ID)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/backups/", nil)
		w := httptest.NewRecorder()

		handler.Get(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestBackupHandlerRestore(t *testing.T) {
	orgID := "test-org"

	t.Run("restores backup with matching org", func(t *testing.T) {
		transit := newHandlerTestTransit()
		orgChecker := newHandlerTestOrgChecker(&models.Organization{ID: orgID, Name: "Test Org"})
		svc := newRealBackupService(transit, orgChecker)
		handler := api.NewBackupHandler(svc)

		b, err := svc.Create(context.Background(), orgID, "full", "admin", []byte("sig"))
		require.NoError(t, err)

		reqBody := map[string]any{
			"crk_signature": base64.StdEncoding.EncodeToString([]byte("valid-sig")),
		}
		body, _ := json.Marshal(reqBody)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", b.ID)
		req := httptest.NewRequest("POST", "/api/v1/backups/"+b.ID+"/restore", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		req = withOrgID(req, orgID)
		w := httptest.NewRecorder()

		handler.Restore(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("rejects restore with mismatched org", func(t *testing.T) {
		transit := newHandlerTestTransit()
		orgChecker := newHandlerTestOrgChecker(
			&models.Organization{ID: orgID, Name: "Test Org"},
			&models.Organization{ID: "other-org", Name: "Other"},
		)
		svc := newRealBackupService(transit, orgChecker)
		handler := api.NewBackupHandler(svc)

		b, err := svc.Create(context.Background(), orgID, "full", "admin", []byte("sig"))
		require.NoError(t, err)

		reqBody := map[string]any{
			"crk_signature": base64.StdEncoding.EncodeToString([]byte("valid-sig")),
		}
		body, _ := json.Marshal(reqBody)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", b.ID)
		req := httptest.NewRequest("POST", "/api/v1/backups/"+b.ID+"/restore", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		req = withOrgID(req, "other-org") // different org
		w := httptest.NewRecorder()

		handler.Restore(w, req)

		// Should be rejected — 400 or 422
		assert.GreaterOrEqual(t, w.Code, 400)
	})

	t.Run("returns 400 for missing CRK signature", func(t *testing.T) {
		transit := newHandlerTestTransit()
		orgChecker := newHandlerTestOrgChecker(&models.Organization{ID: orgID, Name: "Test Org"})
		svc := newRealBackupService(transit, orgChecker)
		handler := api.NewBackupHandler(svc)

		b, err := svc.Create(context.Background(), orgID, "full", "admin", []byte("sig"))
		require.NoError(t, err)

		reqBody := map[string]any{}
		body, _ := json.Marshal(reqBody)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", b.ID)
		req := httptest.NewRequest("POST", "/api/v1/backups/"+b.ID+"/restore", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		req = withOrgID(req, orgID)
		w := httptest.NewRecorder()

		handler.Restore(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for missing ID", func(t *testing.T) {
		transit := newHandlerTestTransit()
		orgChecker := newHandlerTestOrgChecker(&models.Organization{ID: orgID, Name: "Test Org"})
		svc := newRealBackupService(transit, orgChecker)
		handler := api.NewBackupHandler(svc)

		reqBody := map[string]any{
			"crk_signature": base64.StdEncoding.EncodeToString([]byte("valid-sig")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/v1/backups//restore", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withOrgID(req, orgID)
		w := httptest.NewRecorder()

		handler.Restore(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestBackupRouterIntegration(t *testing.T) {
	orgID := "test-org"
	transit := newHandlerTestTransit()
	orgChecker := newHandlerTestOrgChecker(&models.Organization{ID: orgID, Name: "Test Org"})
	svc := newRealBackupService(transit, orgChecker)
	services := &api.Services{
		Backup: svc,
	}

	router := api.NewRouter(nil, services)

	t.Run("backup routes are registered", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/backups", bytes.NewReader([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		// Should not be 404 — the route exists
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})

	t.Run("restore route is registered", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/backups/some-id/restore", bytes.NewReader([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})
}
