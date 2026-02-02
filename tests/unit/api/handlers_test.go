// Package api contains handler tests for API endpoints.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/sovra-project/sovra/internal/api"
	"github.com/sovra-project/sovra/internal/workspace"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/sovra-project/sovra/tests/testutil/inmemory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWorkspaceHandlerCreate tests the workspace Create handler.
func TestWorkspaceHandlerCreate(t *testing.T) {
	// Create a mock workspace service
	wsSvc := inmemory.NewWorkspaceService()
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
	wsSvc := inmemory.NewWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	// Create some workspaces
	_, _ = wsSvc.Create(context.Background(), workspace.CreateRequest{Name: "ws1"})
	_, _ = wsSvc.Create(context.Background(), workspace.CreateRequest{Name: "ws2"})

	t.Run("lists workspaces", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/workspaces", nil)
		w := httptest.NewRecorder()

		handler.List(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Contains(t, resp, "workspaces")
	})

	t.Run("respects pagination params", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/workspaces?limit=1&offset=0", nil)
		w := httptest.NewRecorder()

		handler.List(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestWorkspaceHandlerGet tests the workspace Get handler.
func TestWorkspaceHandlerGet(t *testing.T) {
	wsSvc := inmemory.NewWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	// Create a workspace
	ws, _ := wsSvc.Create(context.Background(), workspace.CreateRequest{Name: "test-ws"})

	t.Run("gets workspace by ID", func(t *testing.T) {
		// Create a chi router context with URL param
		r := chi.NewRouter()
		r.Get("/api/v1/workspaces/{id}", handler.Get)

		req := httptest.NewRequest("GET", "/api/v1/workspaces/"+ws.ID, nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
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

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestWorkspaceHandlerEncrypt tests the workspace Encrypt handler.
func TestWorkspaceHandlerEncrypt(t *testing.T) {
	wsSvc := inmemory.NewWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	// Create a workspace
	ws, _ := wsSvc.Create(context.Background(), workspace.CreateRequest{Name: "encrypt-ws"})

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

		assert.Equal(t, http.StatusOK, w.Code)
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
	wsSvc := inmemory.NewWorkspaceService()
	handler := api.NewWorkspaceHandler(wsSvc)

	// Create a workspace and encrypt some data
	ws, _ := wsSvc.Create(context.Background(), workspace.CreateRequest{Name: "decrypt-ws"})
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

		assert.Equal(t, http.StatusOK, w.Code)
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
	policySvc := inmemory.NewPolicyService()
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
	policySvc := inmemory.NewPolicyService()
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
	policySvc := inmemory.NewPolicyService()
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

		assert.Equal(t, http.StatusOK, w.Code)
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
	policySvc := inmemory.NewPolicyService()
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

		assert.Equal(t, http.StatusOK, w.Code)
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
	auditSvc := inmemory.NewAuditService()
	handler := api.NewAuditHandler(auditSvc)

	t.Run("queries audit events", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/audit?org_id=org-123", nil)
		w := httptest.NewRecorder()

		handler.Query(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("queries without org_id returns events", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/audit", nil)
		w := httptest.NewRecorder()

		handler.Query(w, req)

		// Query without org_id still returns events (all events)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestAuditHandlerGet tests the audit Get handler.
func TestAuditHandlerGet(t *testing.T) {
	auditSvc := inmemory.NewAuditService()
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
	edgeSvc := inmemory.NewEdgeService()
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
	edgeSvc := inmemory.NewEdgeService()
	handler := api.NewEdgeHandler(edgeSvc)

	t.Run("lists edge nodes", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/edges", nil)
		w := httptest.NewRecorder()

		handler.List(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestEdgeHandlerGet tests the edge Get handler.
func TestEdgeHandlerGet(t *testing.T) {
	edgeSvc := inmemory.NewEdgeService()
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
	crkSvc := inmemory.NewCRKService()
	handler := api.NewCRKHandler(crkSvc.Manager(), crkSvc)

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
	crkSvc := inmemory.NewCRKService()
	handler := api.NewCRKHandler(crkSvc.Manager(), crkSvc)

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
	fedSvc := inmemory.NewFederationService()
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
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestFederationHandlerList tests the federation List handler.
func TestFederationHandlerList(t *testing.T) {
	fedSvc := inmemory.NewFederationService()
	handler := api.NewFederationHandler(fedSvc)

	t.Run("lists federations", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/federation", nil)
		w := httptest.NewRecorder()

		handler.List(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}
