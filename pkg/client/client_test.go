package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/pkg/models"
)

// mockServer creates a test HTTP server with a chi router and returns the server and client.
func mockServer(t *testing.T, setup func(r chi.Router)) (*httptest.Server, *Client) {
	t.Helper()
	r := chi.NewRouter()
	setup(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	c := New(Config{BaseURL: srv.URL, Token: "test-token", OrgID: "test-org"})
	return srv, c
}

func writeJSONResponse(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func TestNew(t *testing.T) {
	c := New(Config{BaseURL: "http://localhost", Token: "tok", OrgID: "org1"})
	assert.Equal(t, "http://localhost", c.baseURL)
	assert.Equal(t, "tok", c.token)
	assert.Equal(t, "org1", c.orgID)
}

func TestNewDefaultTimeout(t *testing.T) {
	c := New(Config{BaseURL: "http://localhost"})
	assert.Equal(t, 30*time.Second, c.httpClient.Timeout)
}

func TestNewCustomTimeout(t *testing.T) {
	c := New(Config{BaseURL: "http://localhost", Timeout: 5 * time.Second})
	assert.Equal(t, 5*time.Second, c.httpClient.Timeout)
}

func TestSetToken(t *testing.T) {
	c := New(Config{BaseURL: "http://localhost"})
	c.SetToken("new-token")
	assert.Equal(t, "new-token", c.token)
}

func TestSetOrgID(t *testing.T) {
	c := New(Config{BaseURL: "http://localhost"})
	c.SetOrgID("new-org")
	assert.Equal(t, "new-org", c.orgID)
}

func TestRequestSetsHeaders(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Equal(t, "application/json", r.Header.Get("Accept"))
			assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
			assert.Equal(t, "test-org", r.Header.Get("X-Org-ID"))
			writeJSONResponse(w, http.StatusOK, map[string]string{"ok": "true"})
		})
	})
	err := c.request(context.Background(), http.MethodPost, "/test", map[string]string{"k": "v"}, nil)
	require.NoError(t, err)
}

func TestRequestAPIError(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/fail", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusBadRequest, ErrorResponse{Error: "bad input"})
		})
	})
	err := c.request(context.Background(), http.MethodGet, "/fail", nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad input")
}

func TestRequestAPIErrorNonJSON(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/fail", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("server error"))
		})
	})
	err := c.request(context.Background(), http.MethodGet, "/fail", nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server error")
}

func TestCreateWorkspace(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/workspaces", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.Workspace{ID: "ws1", Name: "test"})
		})
	})
	ws, err := c.CreateWorkspace(context.Background(), WorkspaceCreateRequest{Name: "test"})
	require.NoError(t, err)
	assert.Equal(t, "ws1", ws.ID)
	assert.Equal(t, "test", ws.Name)
}

func TestGetWorkspace(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/workspaces/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.Workspace{ID: chi.URLParam(r, "id"), Name: "test"})
		})
	})
	ws, err := c.GetWorkspace(context.Background(), "ws1")
	require.NoError(t, err)
	assert.Equal(t, "ws1", ws.ID)
}

func TestListWorkspaces(t *testing.T) {
	// ListWorkspaces builds query params into path, use catch-all handler
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, []*models.Workspace{{ID: "ws1"}, {ID: "ws2"}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := New(Config{BaseURL: srv.URL})
	wss, err := c.ListWorkspaces(context.Background(), 10, 0)
	require.NoError(t, err)
	assert.Len(t, wss, 2)
}

func TestEncrypt(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/workspaces/{id}/encrypt", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, EncryptResponse{Ciphertext: []byte("encrypted")})
		})
	})
	ct, err := c.Encrypt(context.Background(), "ws1", []byte("hello"))
	require.NoError(t, err)
	assert.Equal(t, []byte("encrypted"), ct)
}

func TestDecrypt(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/workspaces/{id}/decrypt", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, DecryptResponse{Data: []byte("decrypted")})
		})
	})
	pt, err := c.Decrypt(context.Background(), "ws1", []byte("cipher"))
	require.NoError(t, err)
	assert.Equal(t, []byte("decrypted"), pt)
}

func TestUpdateWorkspace(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Put("/api/v1/workspaces/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.Workspace{ID: chi.URLParam(r, "id"), Purpose: "updated"})
		})
	})
	ws, err := c.UpdateWorkspace(context.Background(), "ws1", UpdateWorkspaceRequest{Purpose: "updated"})
	require.NoError(t, err)
	assert.Equal(t, "updated", ws.Purpose)
}

func TestRotateWorkspaceDEK(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/workspaces/{id}/rotate-dek", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	err := c.RotateWorkspaceDEK(context.Background(), "ws1", []byte("sig"))
	require.NoError(t, err)
}

func TestExtendWorkspace(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/workspaces/{id}/extend", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	err := c.ExtendWorkspace(context.Background(), "ws1", time.Now().Add(24*time.Hour), []byte("sig"))
	require.NoError(t, err)
}

func TestInviteParticipant(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/workspaces/{id}/invite", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.WorkspaceInvitation{ID: "inv1", WorkspaceID: chi.URLParam(r, "id")})
		})
	})
	inv, err := c.InviteParticipant(context.Background(), "ws1", InviteParticipantRequest{OrgID: "org2"})
	require.NoError(t, err)
	assert.Equal(t, "inv1", inv.ID)
}

func TestAcceptInvitation(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/workspaces/{id}/accept-invitation", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	err := c.AcceptInvitation(context.Background(), "ws1", AcceptInvitationRequest{OrgID: "org2"})
	require.NoError(t, err)
}

func TestDeclineInvitation(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/workspaces/{id}/decline-invitation", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	err := c.DeclineInvitation(context.Background(), "ws1", DeclineInvitationRequest{OrgID: "org2"})
	require.NoError(t, err)
}

func TestListFederations(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/federation", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, []*models.Federation{{ID: "fed1"}})
		})
	})
	feds, err := c.ListFederations(context.Background())
	require.NoError(t, err)
	assert.Len(t, feds, 1)
}

func TestGetFederationStatus(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/federation/{partnerId}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.Federation{ID: "fed1"})
		})
	})
	fed, err := c.GetFederationStatus(context.Background(), "partner1")
	require.NoError(t, err)
	assert.Equal(t, "fed1", fed.ID)
}

func TestQueryAudit(t *testing.T) {
	// QueryAudit builds query params into path, use catch-all handler
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, []*models.AuditEvent{{ID: "ev1"}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := New(Config{BaseURL: srv.URL})
	events, err := c.QueryAudit(context.Background(), AuditQueryParams{Since: "2024-01-01", Until: "2024-12-31", EventType: "login", Limit: 10})
	require.NoError(t, err)
	assert.Len(t, events, 1)
}

func TestQueryAuditNoParams(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, []*models.AuditEvent{})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := New(Config{BaseURL: srv.URL})
	events, err := c.QueryAudit(context.Background(), AuditQueryParams{})
	require.NoError(t, err)
	assert.Empty(t, events)
}

func TestListEdgeNodes(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/edges", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, []*models.EdgeNode{{ID: "e1"}})
		})
	})
	nodes, err := c.ListEdgeNodes(context.Background())
	require.NoError(t, err)
	assert.Len(t, nodes, 1)
}

func TestGetEdgeNode(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/edges/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.EdgeNode{ID: chi.URLParam(r, "id")})
		})
	})
	node, err := c.GetEdgeNode(context.Background(), "e1")
	require.NoError(t, err)
	assert.Equal(t, "e1", node.ID)
}

func TestRegisterEdgeNode(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/edges", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.EdgeNode{ID: "e1", Name: "edge1"})
		})
	})
	node, err := c.RegisterEdgeNode(context.Background(), EdgeNodeRegisterRequest{Name: "edge1"})
	require.NoError(t, err)
	assert.Equal(t, "e1", node.ID)
}

func TestUnregisterEdgeNode(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Delete("/api/v1/edges/{id}", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	err := c.UnregisterEdgeNode(context.Background(), "e1")
	require.NoError(t, err)
}

func TestLogin(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, LoginResponse{Token: "jwt-token", ExpiresAt: time.Now().Add(time.Hour)})
		})
	})
	resp, err := c.Login(context.Background(), "user@test.com", "password")
	require.NoError(t, err)
	assert.Equal(t, "jwt-token", resp.Token)
	assert.Equal(t, "jwt-token", c.token)
}

func TestLogout(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	err := c.Logout(context.Background())
	require.NoError(t, err)
}

func TestStartCRKCeremony(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/crk/ceremony/start", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, CeremonyResponse{ID: "cer1", Status: "started", Threshold: 2})
		})
	})
	resp, err := c.StartCRKCeremony(context.Background(), "org1", 3, 2)
	require.NoError(t, err)
	assert.Equal(t, "cer1", resp.ID)
	assert.Equal(t, 2, resp.Threshold)
}

func TestAddCRKShare(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/crk/ceremony/{id}/share", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, CeremonyResponse{ID: chi.URLParam(r, "id"), Collected: 1})
		})
	})
	resp, err := c.AddCRKShare(context.Background(), "cer1", models.CRKShare{})
	require.NoError(t, err)
	assert.Equal(t, 1, resp.Collected)
}

func TestCompleteCRKCeremony(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/crk/ceremony/{id}/complete", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, CeremonyResponse{ID: chi.URLParam(r, "id"), Status: "completed"})
		})
	})
	resp, err := c.CompleteCRKCeremony(context.Background(), "cer1")
	require.NoError(t, err)
	assert.Equal(t, "completed", resp.Status)
}

func TestCancelCRKCeremony(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Delete("/api/v1/crk/ceremony/{id}", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	err := c.CancelCRKCeremony(context.Background(), "cer1")
	require.NoError(t, err)
}

func TestHealth(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, HealthResponse{Status: "healthy", Version: "1.0"})
		})
	})
	resp, err := c.Health(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "healthy", resp.Status)
}

func TestCreateAdmin(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/identities/admins", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, CreateAdminResponse{
				Admin:           &models.AdminIdentity{ID: "admin1", Email: "a@b.com"},
				EnrollmentToken: "tok-123",
			})
		})
	})
	resp, err := c.CreateAdmin(context.Background(), CreateAdminRequest{Email: "a@b.com", Name: "Admin", CRKSignature: []byte("sig")})
	require.NoError(t, err)
	assert.Equal(t, "admin1", resp.Admin.ID)
	assert.Equal(t, "tok-123", resp.EnrollmentToken)
}

func TestListAdmins(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/identities/admins", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, listAdminsResponse{Admins: []*models.AdminIdentity{{ID: "a1"}}})
		})
	})
	admins, err := c.ListAdmins(context.Background())
	require.NoError(t, err)
	assert.Len(t, admins, 1)
}

func TestGetAdmin(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/identities/admins/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.AdminIdentity{ID: chi.URLParam(r, "id")})
		})
	})
	admin, err := c.GetAdmin(context.Background(), "admin1")
	require.NoError(t, err)
	assert.Equal(t, "admin1", admin.ID)
}

func TestUpdateAdmin(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Put("/api/v1/identities/admins/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.AdminIdentity{ID: chi.URLParam(r, "id"), Name: "Updated"})
		})
	})
	admin, err := c.UpdateAdmin(context.Background(), "admin1", UpdateAdminRequest{Name: "Updated"})
	require.NoError(t, err)
	assert.Equal(t, "Updated", admin.Name)
}

func TestDeleteAdmin(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Delete("/api/v1/identities/admins/{id}", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	err := c.DeleteAdmin(context.Background(), "admin1")
	require.NoError(t, err)
}

func TestEnableMFA(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/identities/admins/{id}/mfa/enable", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, EnableMFAResponse{Secret: "JBSWY3DPEHPK3PXP", QRCodeURL: "otpauth://..."})
		})
	})
	resp, err := c.EnableMFA(context.Background(), "admin1")
	require.NoError(t, err)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", resp.Secret)
}

func TestVerifyMFA(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/identities/admins/{id}/mfa/verify", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	err := c.VerifyMFA(context.Background(), "admin1", VerifyMFARequest{Code: "123456"})
	require.NoError(t, err)
}

func TestCreateUserFromSSO(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/identities/users/sso", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.UserIdentity{ID: "user1", Email: "u@b.com"})
		})
	})
	user, err := c.CreateUserFromSSO(context.Background(), CreateUserSSORequest{Email: "u@b.com"})
	require.NoError(t, err)
	assert.Equal(t, "user1", user.ID)
}

func TestListUsers(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/identities/users", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, listUsersResponse{Users: []*models.UserIdentity{{ID: "u1"}}})
		})
	})
	users, err := c.ListUsers(context.Background())
	require.NoError(t, err)
	assert.Len(t, users, 1)
}

func TestGetUser(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/identities/users/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.UserIdentity{ID: chi.URLParam(r, "id")})
		})
	})
	user, err := c.GetUser(context.Background(), "user1")
	require.NoError(t, err)
	assert.Equal(t, "user1", user.ID)
}

func TestDeleteUser(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Delete("/api/v1/identities/users/{id}", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	err := c.DeleteUser(context.Background(), "user1")
	require.NoError(t, err)
}

func TestCreateService(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/identities/services", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.ServiceIdentity{ID: "svc1", Name: "my-service"})
		})
	})
	svc, err := c.CreateService(context.Background(), CreateServiceRequest{Name: "my-service"})
	require.NoError(t, err)
	assert.Equal(t, "svc1", svc.ID)
}

func TestListServices(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/identities/services", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, listServicesResponse{Services: []*models.ServiceIdentity{{ID: "s1"}}})
		})
	})
	svcs, err := c.ListServices(context.Background())
	require.NoError(t, err)
	assert.Len(t, svcs, 1)
}

func TestGetService(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/identities/services/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.ServiceIdentity{ID: chi.URLParam(r, "id")})
		})
	})
	svc, err := c.GetService(context.Background(), "svc1")
	require.NoError(t, err)
	assert.Equal(t, "svc1", svc.ID)
}

func TestDeleteService(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Delete("/api/v1/identities/services/{id}", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	err := c.DeleteService(context.Background(), "svc1")
	require.NoError(t, err)
}

func TestEnrollDevice(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/identities/devices", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.DeviceIdentity{ID: "dev1", DeviceName: "my-device"})
		})
	})
	dev, err := c.EnrollDevice(context.Background(), EnrollDeviceRequest{DeviceName: "my-device"})
	require.NoError(t, err)
	assert.Equal(t, "dev1", dev.ID)
}

func TestListDevices(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/identities/devices", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, listDevicesResponse{Devices: []*models.DeviceIdentity{{ID: "d1"}}})
		})
	})
	devs, err := c.ListDevices(context.Background())
	require.NoError(t, err)
	assert.Len(t, devs, 1)
}

func TestGetDevice(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/identities/devices/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.DeviceIdentity{ID: chi.URLParam(r, "id")})
		})
	})
	dev, err := c.GetDevice(context.Background(), "dev1")
	require.NoError(t, err)
	assert.Equal(t, "dev1", dev.ID)
}

func TestRevokeDevice(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/identities/devices/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	err := c.RevokeDevice(context.Background(), "dev1")
	require.NoError(t, err)
}

func TestCreateGroup(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/identities/groups", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.IdentityGroup{ID: "grp1", Name: "admins"})
		})
	})
	grp, err := c.CreateGroup(context.Background(), CreateGroupRequest{Name: "admins"})
	require.NoError(t, err)
	assert.Equal(t, "grp1", grp.ID)
}

func TestListGroups(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/identities/groups", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, listGroupsResponse{Groups: []*models.IdentityGroup{{ID: "g1"}}})
		})
	})
	grps, err := c.ListGroups(context.Background())
	require.NoError(t, err)
	assert.Len(t, grps, 1)
}

func TestGetGroup(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/identities/groups/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.IdentityGroup{ID: chi.URLParam(r, "id")})
		})
	})
	grp, err := c.GetGroup(context.Background(), "grp1")
	require.NoError(t, err)
	assert.Equal(t, "grp1", grp.ID)
}

func TestAddGroupMember(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/identities/groups/{id}/members", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	err := c.AddGroupMember(context.Background(), "grp1", AddGroupMemberRequest{IdentityID: "admin1"})
	require.NoError(t, err)
}

func TestRemoveGroupMember(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Delete("/api/v1/identities/groups/{id}/members/{identityId}", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	err := c.RemoveGroupMember(context.Background(), "grp1", "admin1")
	require.NoError(t, err)
}

func TestCreateRole(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/identities/roles", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.Role{ID: "role1", Name: "editor"})
		})
	})
	role, err := c.CreateRole(context.Background(), CreateRoleRequest{Name: "editor"})
	require.NoError(t, err)
	assert.Equal(t, "role1", role.ID)
}

func TestListRoles(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/identities/roles", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, listRolesResponse{Roles: []*models.Role{{ID: "r1"}}})
		})
	})
	roles, err := c.ListRoles(context.Background())
	require.NoError(t, err)
	assert.Len(t, roles, 1)
}

func TestGetRole(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/identities/roles/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.Role{ID: chi.URLParam(r, "id")})
		})
	})
	role, err := c.GetRole(context.Background(), "role1")
	require.NoError(t, err)
	assert.Equal(t, "role1", role.ID)
}

func TestAssignRole(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/identities/roles/{id}/assign", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	err := c.AssignRole(context.Background(), "role1", AssignRoleRequest{IdentityID: "admin1"})
	require.NoError(t, err)
}

func TestUnassignRole(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Delete("/api/v1/identities/roles/{id}/assignments/{identityId}", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	err := c.UnassignRole(context.Background(), "role1", "admin1")
	require.NoError(t, err)
}

func TestClientErrorHandling(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/workspaces/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusNotFound, ErrorResponse{Error: "workspace not found"})
		})
	})
	_, err := c.GetWorkspace(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workspace not found")
}

func TestClientNetworkError(t *testing.T) {
	c := New(Config{BaseURL: "http://localhost:1", Timeout: 100 * time.Millisecond})
	_, err := c.Health(context.Background())
	assert.Error(t, err)
}

// ============================================================================
// Tests for new client methods
// ============================================================================

func TestDeleteWorkspace(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Delete("/api/v1/workspaces/{id}", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
	})
	err := c.DeleteWorkspace(context.Background(), "ws1", DeleteWorkspaceRequest{})
	require.NoError(t, err)
}

func TestArchiveWorkspace(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/workspaces/{id}/archive", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "ws1", chi.URLParam(r, "id"))
			w.WriteHeader(http.StatusNoContent)
		})
	})
	err := c.ArchiveWorkspace(context.Background(), "ws1", ArchiveWorkspaceRequest{})
	require.NoError(t, err)
}

func TestInitFederation(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/federation/init", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, InitFederationResponse{OrgID: "org1", CSR: []byte("csr-data")})
		})
	})
	resp, err := c.InitFederation(context.Background(), InitFederationRequest{OrgID: "org1"})
	require.NoError(t, err)
	assert.Equal(t, "org1", resp.OrgID)
	assert.Equal(t, []byte("csr-data"), resp.CSR)
}

func TestEstablishFederation(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/federation/establish", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.Federation{ID: "fed1", PartnerOrgID: "partner1", Status: "active"})
		})
	})
	fed, err := c.EstablishFederation(context.Background(), EstablishFederationRequest{PartnerOrgID: "partner1", PartnerURL: "https://partner.example.com"})
	require.NoError(t, err)
	assert.Equal(t, "fed1", fed.ID)
	assert.Equal(t, "partner1", fed.PartnerOrgID)
}

func TestRevokeFederation(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Delete("/api/v1/federation/{partnerId}", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "partner1", chi.URLParam(r, "partnerId"))
			w.WriteHeader(http.StatusNoContent)
		})
	})
	err := c.RevokeFederation(context.Background(), "partner1", RevokeFederationRequest{NotifyPartner: true})
	require.NoError(t, err)
}

func TestFederationHealth(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/federation/health", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, FederationHealthResponse{
				Results: []FederationHealthResult{{PartnerOrgID: "p1", Healthy: true}},
			})
		})
	})
	resp, err := c.FederationHealth(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	assert.Equal(t, "p1", resp.Results[0].PartnerOrgID)
	assert.True(t, resp.Results[0].Healthy)
}

func TestImportFederationCertificate(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/federation/certificate/import", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
	})
	err := c.ImportFederationCertificate(context.Background(), ImportFederationCertificateRequest{
		PartnerOrgID: "partner1",
		Certificate:  []byte("cert-data"),
	})
	require.NoError(t, err)
}

func TestCreatePolicy(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/policies", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.Policy{ID: "pol1", Name: "test-policy"})
		})
	})
	pol, err := c.CreatePolicy(context.Background(), CreatePolicyRequest{Name: "test-policy", Workspace: "ws1", Rego: "package test"})
	require.NoError(t, err)
	assert.Equal(t, "pol1", pol.ID)
	assert.Equal(t, "test-policy", pol.Name)
}

func TestGetPolicy(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/policies/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.Policy{ID: chi.URLParam(r, "id"), Name: "my-policy"})
		})
	})
	pol, err := c.GetPolicy(context.Background(), "pol1")
	require.NoError(t, err)
	assert.Equal(t, "pol1", pol.ID)
}

func TestUpdatePolicy(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Put("/api/v1/policies/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.Policy{ID: chi.URLParam(r, "id"), Version: 2})
		})
	})
	pol, err := c.UpdatePolicy(context.Background(), "pol1", UpdatePolicyRequest{Rego: "package updated"})
	require.NoError(t, err)
	assert.Equal(t, 2, pol.Version)
}

func TestDeletePolicy(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Delete("/api/v1/policies/{id}", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
	})
	err := c.DeletePolicy(context.Background(), "pol1", DeletePolicyRequest{})
	require.NoError(t, err)
}

func TestGetPoliciesForWorkspace(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/policies/workspace/{workspaceId}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, PoliciesForWorkspaceResponse{
				Policies: []*models.Policy{{ID: "p1"}, {ID: "p2"}},
				Count:    2,
			})
		})
	})
	resp, err := c.GetPoliciesForWorkspace(context.Background(), "ws1")
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Count)
	assert.Len(t, resp.Policies, 2)
}

func TestEvaluatePolicy(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/policies/evaluate", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, EvaluatePolicyResponse{Allowed: true, PolicyID: "pol1"})
		})
	})
	resp, err := c.EvaluatePolicy(context.Background(), EvaluatePolicyRequest{
		Actor: "admin", Role: "super_admin", Operation: "encrypt", Workspace: "ws1",
	})
	require.NoError(t, err)
	assert.True(t, resp.Allowed)
	assert.Equal(t, "pol1", resp.PolicyID)
}

func TestValidatePolicy(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/policies/validate", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, ValidatePolicyResponse{Valid: true})
		})
	})
	resp, err := c.ValidatePolicy(context.Background(), ValidatePolicyRequest{Rego: "package test"})
	require.NoError(t, err)
	assert.True(t, resp.Valid)
}

func TestValidatePolicyInvalid(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/policies/validate", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, ValidatePolicyResponse{Valid: false, Error: "syntax error"})
		})
	})
	resp, err := c.ValidatePolicy(context.Background(), ValidatePolicyRequest{Rego: "bad rego"})
	require.NoError(t, err)
	assert.False(t, resp.Valid)
	assert.Equal(t, "syntax error", resp.Error)
}

func TestGetAuditEvent(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/audit/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.AuditEvent{ID: chi.URLParam(r, "id"), Actor: "admin"})
		})
	})
	ev, err := c.GetAuditEvent(context.Background(), "ev1")
	require.NoError(t, err)
	assert.Equal(t, "ev1", ev.ID)
	assert.Equal(t, "admin", ev.Actor)
}

func TestExportAudit(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/audit/export", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":"ev1"}]`))
		})
	})
	data, err := c.ExportAudit(context.Background(), ExportAuditRequest{Format: "json"})
	require.NoError(t, err)
	assert.Contains(t, string(data), "ev1")
}

func TestGetAuditStats(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, AuditStatsResponse{TotalEvents: 100, SuccessCount: 90, ErrorCount: 10})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := New(Config{BaseURL: srv.URL})
	stats, err := c.GetAuditStats(context.Background(), "2024-01-01T00:00:00Z")
	require.NoError(t, err)
	assert.Equal(t, int64(100), stats.TotalEvents)
	assert.Equal(t, int64(90), stats.SuccessCount)
}

func TestGetAuditStatsNoSince(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, AuditStatsResponse{TotalEvents: 50})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := New(Config{BaseURL: srv.URL})
	stats, err := c.GetAuditStats(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, int64(50), stats.TotalEvents)
}

func TestVerifyAuditIntegrity(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/audit/verify", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, VerifyAuditIntegrityResponse{Valid: true, Since: "2024-01-01", Until: "2024-12-31"})
		})
	})
	resp, err := c.VerifyAuditIntegrity(context.Background(), VerifyAuditIntegrityRequest{Since: "2024-01-01", Until: "2024-12-31"})
	require.NoError(t, err)
	assert.True(t, resp.Valid)
}

func TestGetEdgeHealth(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/edges/{id}/health", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, EdgeHealthResponse{Healthy: true, Version: "1.15.0", ClusterNodes: 3})
		})
	})
	health, err := c.GetEdgeHealth(context.Background(), "e1")
	require.NoError(t, err)
	assert.True(t, health.Healthy)
	assert.Equal(t, "1.15.0", health.Version)
	assert.Equal(t, 3, health.ClusterNodes)
}

func TestSyncEdgePolicies(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/edges/{id}/sync/policies", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "e1", chi.URLParam(r, "id"))
			w.WriteHeader(http.StatusNoContent)
		})
	})
	err := c.SyncEdgePolicies(context.Background(), "e1")
	require.NoError(t, err)
}

func TestSyncEdgeKeys(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/edges/{id}/sync/keys", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "e1", chi.URLParam(r, "id"))
			w.WriteHeader(http.StatusNoContent)
		})
	})
	err := c.SyncEdgeKeys(context.Background(), "e1", SyncEdgeKeysRequest{WorkspaceID: "ws1"})
	require.NoError(t, err)
}

func TestGetEdgeSyncStatus(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/edges/{id}/sync/status", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, EdgeSyncStatusResponse{PoliciesSynced: 5, KeysSynced: 10, SyncInProgress: false})
		})
	})
	status, err := c.GetEdgeSyncStatus(context.Background(), "e1")
	require.NoError(t, err)
	assert.Equal(t, 5, status.PoliciesSynced)
	assert.Equal(t, 10, status.KeysSynced)
	assert.False(t, status.SyncInProgress)
}

func TestRotateCRK(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/crk/rotate", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, CeremonyResponse{ID: "cer1", Status: "started", Threshold: 3})
		})
	})
	resp, err := c.RotateCRK(context.Background(), RotateCRKRequest{Threshold: 3})
	require.NoError(t, err)
	assert.Equal(t, "cer1", resp.ID)
	assert.Equal(t, "started", resp.Status)
	assert.Equal(t, 3, resp.Threshold)
}

func TestEncryptWithContext(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/workspaces/{id}/encrypt", func(w http.ResponseWriter, r *http.Request) {
			var req EncryptRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			assert.NotNil(t, req.Context)
			assert.Equal(t, "value1", req.Context["key1"])
			writeJSONResponse(w, http.StatusOK, EncryptResponse{Ciphertext: []byte("encrypted")})
		})
	})
	ct, err := c.EncryptWithContext(context.Background(), "ws1", []byte("hello"), map[string]string{"key1": "value1"})
	require.NoError(t, err)
	assert.Equal(t, []byte("encrypted"), ct)
}

func TestDecryptWithContext(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/workspaces/{id}/decrypt", func(w http.ResponseWriter, r *http.Request) {
			var req DecryptRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			assert.NotNil(t, req.Context)
			assert.Equal(t, "value1", req.Context["key1"])
			writeJSONResponse(w, http.StatusOK, DecryptResponse{Data: []byte("decrypted")})
		})
	})
	pt, err := c.DecryptWithContext(context.Background(), "ws1", []byte("cipher"), map[string]string{"key1": "value1"})
	require.NoError(t, err)
	assert.Equal(t, []byte("decrypted"), pt)
}

func TestRequestRaw(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/raw", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/csv")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("id,name\n1,test\n"))
		})
	})
	data, err := c.requestRaw(context.Background(), http.MethodPost, "/api/v1/raw", nil)
	require.NoError(t, err)
	assert.Equal(t, "id,name\n1,test\n", string(data))
}

func TestRequestRawError(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/raw", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusBadRequest, ErrorResponse{Error: "bad request"})
		})
	})
	_, err := c.requestRaw(context.Background(), http.MethodPost, "/api/v1/raw", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad request")
}

// ============================================================================
// Certificate API Tests
// ============================================================================

func TestIssueCertificate(t *testing.T) {
	// IssueCertificate builds query params into path, use catch-all handler
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusCreated, CertificateResponse{
			SerialNumber: "aa:bb:cc",
			Certificate:  "-----BEGIN CERTIFICATE-----",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := New(Config{BaseURL: srv.URL})
	cert, err := c.IssueCertificate(context.Background(), "default", IssueCertificateRequest{
		CommonName: "test.example.com",
		TTL:        "8760h",
	})
	require.NoError(t, err)
	assert.Equal(t, "aa:bb:cc", cert.SerialNumber)
}

func TestRevokeCertificate(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/certificates/revoke", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
	})
	err := c.RevokeCertificate(context.Background(), "aa:bb:cc")
	require.NoError(t, err)
}

func TestReadCertificate(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/certificates/{serial}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, CertificateResponse{
				SerialNumber: chi.URLParam(r, "serial"),
			})
		})
	})
	cert, err := c.ReadCertificate(context.Background(), "aa:bb:cc")
	require.NoError(t, err)
	assert.Equal(t, "aa:bb:cc", cert.SerialNumber)
}

func TestListCertificates(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/certificates", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, CertificateListResponse{
				Certificates: []string{"aa:bb:cc", "dd:ee:ff"},
				Count:        2,
			})
		})
	})
	result, err := c.ListCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, result.Count)
	assert.Len(t, result.Certificates, 2)
}

func TestGetCAChain(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/certificates/ca-chain", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, CAChainResponse{CAChain: "-----BEGIN CERTIFICATE-----"})
		})
	})
	result, err := c.GetCAChain(context.Background())
	require.NoError(t, err)
	assert.Contains(t, result.CAChain, "BEGIN CERTIFICATE")
}

func TestTidyCertificates(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/certificates/tidy", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, map[string]string{"message": "tidy started"})
		})
	})
	err := c.TidyCertificates(context.Background(), "72h")
	require.NoError(t, err)
}

// ============================================================================
// Workspace Export/Import Tests
// ============================================================================

func TestExportWorkspace(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/workspaces/{id}/export", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, WorkspaceBundleResponse{
				Workspace:  &models.Workspace{ID: chi.URLParam(r, "id"), Name: "test"},
				ExportedBy: "org1",
				Checksum:   "abc123",
			})
		})
	})
	bundle, err := c.ExportWorkspace(context.Background(), "ws1")
	require.NoError(t, err)
	assert.Equal(t, "ws1", bundle.Workspace.ID)
	assert.Equal(t, "abc123", bundle.Checksum)
}

func TestImportWorkspace(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/workspaces/import", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusCreated, models.Workspace{ID: "ws-new", Name: "imported"})
		})
	})
	ws, err := c.ImportWorkspace(context.Background(), &WorkspaceBundleResponse{
		Workspace: &models.Workspace{Name: "imported"},
		Checksum:  "abc123",
	})
	require.NoError(t, err)
	assert.Equal(t, "ws-new", ws.ID)
}

// ============================================================================
// Service Credential Rotation Tests
// ============================================================================

func TestRotateServiceCredentials(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/identities/services/{id}/rotate", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.ServiceIdentity{
				ID:        chi.URLParam(r, "id"),
				Name:      "my-service",
				VaultRole: "my-service-v1234",
			})
		})
	})
	svc, err := c.RotateServiceCredentials(context.Background(), "svc1")
	require.NoError(t, err)
	assert.Equal(t, "svc1", svc.ID)
	assert.Contains(t, svc.VaultRole, "my-service")
}

// ============================================================================
// Emergency Access Tests
// ============================================================================

func TestRequestEmergencyAccess(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/emergency-access/request", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusCreated, models.EmergencyAccessRequest{
				ID:     "ea1",
				Status: models.EmergencyAccessPending,
				Reason: "urgent",
			})
		})
	})
	req, err := c.RequestEmergencyAccess(context.Background(), EmergencyAccessRequestPayload{
		Reason: "urgent",
	})
	require.NoError(t, err)
	assert.Equal(t, "ea1", req.ID)
	assert.Equal(t, models.EmergencyAccessPending, req.Status)
}

func TestApproveEmergencyAccess(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/emergency-access/{id}/approve", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "ea1", chi.URLParam(r, "id"))
			w.WriteHeader(http.StatusNoContent)
		})
	})
	err := c.ApproveEmergencyAccess(context.Background(), "ea1")
	require.NoError(t, err)
}

func TestDenyEmergencyAccess(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/emergency-access/{id}/deny", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
	})
	err := c.DenyEmergencyAccess(context.Background(), "ea1")
	require.NoError(t, err)
}

func TestCompleteEmergencyAccess(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/emergency-access/{id}/complete", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
	})
	err := c.CompleteEmergencyAccess(context.Background(), "ea1")
	require.NoError(t, err)
}

func TestVerifyEmergencyAccess(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/emergency-access/{id}/verify", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
	})
	err := c.VerifyEmergencyAccess(context.Background(), "ea1", []byte("sig-data"))
	require.NoError(t, err)
}

func TestListEmergencyAccess(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/emergency-access", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, EmergencyAccessListResponse{
				Requests: []*models.EmergencyAccessRequest{
					{ID: "ea1", Status: models.EmergencyAccessPending},
				},
				Count: 1,
			})
		})
	})
	result, err := c.ListEmergencyAccess(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, 1, result.Count)
}

func TestGetEmergencyAccess(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/emergency-access/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, models.EmergencyAccessRequest{
				ID:     chi.URLParam(r, "id"),
				Status: models.EmergencyAccessApproved,
			})
		})
	})
	req, err := c.GetEmergencyAccess(context.Background(), "ea1")
	require.NoError(t, err)
	assert.Equal(t, "ea1", req.ID)
}

// ============================================================================
// Account Recovery Tests
// ============================================================================

func TestInitiateRecovery(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/account-recovery/initiate", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusCreated, models.AccountRecovery{
				ID:     "rec1",
				Status: models.AccountRecoveryPending,
			})
		})
	})
	rec, err := c.InitiateRecovery(context.Background(), InitiateRecoveryRequest{
		AdminID: "admin1",
		Reason:  "locked out",
	})
	require.NoError(t, err)
	assert.Equal(t, "rec1", rec.ID)
}

func TestCollectRecoveryShare(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/account-recovery/{id}/share", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
	})
	err := c.CollectRecoveryShare(context.Background(), "rec1")
	require.NoError(t, err)
}

func TestCompleteRecovery(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/account-recovery/{id}/complete", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
	})
	err := c.CompleteRecovery(context.Background(), "rec1")
	require.NoError(t, err)
}

// ============================================================================
// Compliance Tests
// ============================================================================

func TestGenerateComplianceSummary(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/compliance/reports/summary", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"id":   "report1",
				"type": "summary",
			})
		})
	})
	report, err := c.GenerateComplianceSummary(context.Background(), ComplianceReportRequest{
		Since: "2025-01-01T00:00:00Z",
		Until: "2025-12-31T23:59:59Z",
	})
	require.NoError(t, err)
	assert.Equal(t, "report1", report.ID)
	assert.Equal(t, "summary", report.Type)
}

func TestGenerateGDPRDSAR(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/compliance/reports/gdpr-dsar", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"id":   "report2",
				"type": "gdpr-dsar",
			})
		})
	})
	report, err := c.GenerateGDPRDSAR(context.Background(), DSARRequest{
		SubjectID: "user123",
	})
	require.NoError(t, err)
	assert.Equal(t, "report2", report.ID)
}

func TestGenerateAccessReview(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/compliance/reports/access-review", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"id":   "report3",
				"type": "access-review",
			})
		})
	})
	report, err := c.GenerateAccessReview(context.Background(), ComplianceReportRequest{})
	require.NoError(t, err)
	assert.Equal(t, "report3", report.ID)
}

// ============================================================================
// Rotation Policy Tests
// ============================================================================

func TestSetRotationPolicy(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Put("/api/v1/workspaces/{id}/rotation-policy", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, RotationPolicy{
				WorkspaceID: chi.URLParam(r, "id"),
				MaxAge:      "720h",
				Enabled:     true,
			})
		})
	})
	policy, err := c.SetRotationPolicy(context.Background(), "ws1", SetRotationPolicyRequest{
		MaxAge:  "720h",
		Enabled: true,
	})
	require.NoError(t, err)
	assert.Equal(t, "ws1", policy.WorkspaceID)
	assert.Equal(t, "720h", policy.MaxAge)
	assert.True(t, policy.Enabled)
}

func TestGetRotationPolicy(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/workspaces/{id}/rotation-policy", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, RotationPolicy{
				WorkspaceID: chi.URLParam(r, "id"),
				MaxAge:      "720h",
				Enabled:     true,
			})
		})
	})
	policy, err := c.GetRotationPolicy(context.Background(), "ws1")
	require.NoError(t, err)
	assert.Equal(t, "ws1", policy.WorkspaceID)
}

func TestDeleteRotationPolicy(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Delete("/api/v1/workspaces/{id}/rotation-policy", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
	})
	err := c.DeleteRotationPolicy(context.Background(), "ws1")
	require.NoError(t, err)
}

func TestListRotationPolicies(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/rotation-policies", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, RotationPolicyListResponse{
				Policies: []*RotationPolicy{
					{WorkspaceID: "ws1", MaxAge: "720h", Enabled: true},
				},
				Count: 1,
			})
		})
	})
	result, err := c.ListRotationPolicies(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, result.Count)
	assert.Equal(t, "ws1", result.Policies[0].WorkspaceID)
}

// ============================================================================
// Metrics and Activity Log Tests
// ============================================================================

func TestGetMetrics(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/metrics", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("# HELP go_goroutines Number of goroutines\n"))
		})
	})
	data, err := c.GetMetrics(context.Background())
	require.NoError(t, err)
	assert.Contains(t, data, "go_goroutines")
}

func TestGetActivityLog(t *testing.T) {
	// GetActivityLog builds query params into path, use catch-all handler
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, []*models.AuditEvent{
			{ID: "ev1", Actor: "actor1"},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := New(Config{BaseURL: srv.URL})
	events, err := c.GetActivityLog(context.Background(), "actor1", AuditQueryParams{Limit: 10})
	require.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, "ev1", events[0].ID)
}

// ============================================================================
// Direct Messaging Tests
// ============================================================================

func TestSendMessage(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/messages", func(w http.ResponseWriter, r *http.Request) {
			var req SendMessageRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			writeJSONResponse(w, http.StatusCreated, models.DirectMessage{
				ID:             "msg-1",
				SenderOrgID:    "org1",
				SenderID:       "user-a",
				RecipientOrgID: req.RecipientOrgID,
				RecipientID:    req.RecipientID,
				Subject:        req.Subject,
				Status:         models.DirectMessageStatusDelivered,
				Direction:      "sent",
			})
		})
	})
	msg, err := c.SendMessage(context.Background(), SendMessageRequest{
		RecipientOrgID: "org2",
		RecipientID:    "user-b",
		Subject:        "Hello",
		Body:           []byte("hi there"),
	})
	require.NoError(t, err)
	assert.Equal(t, "msg-1", msg.ID)
	assert.Equal(t, "Hello", msg.Subject)
	assert.Equal(t, models.DirectMessageStatusDelivered, msg.Status)
}

func TestSendMessageError(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/messages", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusBadRequest, ErrorResponse{Error: "subject is required"})
		})
	})
	_, err := c.SendMessage(context.Background(), SendMessageRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject is required")
}

func TestListMessages(t *testing.T) {
	// ListMessages builds query params into path, use catch-all handler
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, MessageListResponse{
			Messages: []*models.DirectMessage{
				{ID: "msg-1", Subject: "Inbox msg", Direction: "received"},
			},
			Count: 1,
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := New(Config{BaseURL: srv.URL})
	resp, err := c.ListMessages(context.Background(), 20, 5)
	require.NoError(t, err)
	assert.Equal(t, 1, resp.Count)
	assert.Equal(t, "msg-1", resp.Messages[0].ID)
}

func TestListSentMessages(t *testing.T) {
	// ListSentMessages builds query params into path, use catch-all handler
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, MessageListResponse{
			Messages: []*models.DirectMessage{
				{ID: "msg-2", Subject: "Sent msg", Direction: "sent"},
			},
			Count: 1,
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := New(Config{BaseURL: srv.URL})
	resp, err := c.ListSentMessages(context.Background(), 50, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, resp.Count)
	assert.Equal(t, "sent", resp.Messages[0].Direction)
}

func TestReadMessage(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/messages/{id}", func(w http.ResponseWriter, r *http.Request) {
			id := chi.URLParam(r, "id")
			writeJSONResponse(w, http.StatusOK, models.DirectMessage{
				ID:      id,
				Subject: "Read me",
				Body:    []byte("decrypted content"),
				Status:  models.DirectMessageStatusRead,
			})
		})
	})
	msg, err := c.ReadMessage(context.Background(), "msg-123")
	require.NoError(t, err)
	assert.Equal(t, "msg-123", msg.ID)
	assert.Equal(t, "decrypted content", string(msg.Body))
	assert.Equal(t, models.DirectMessageStatusRead, msg.Status)
}

func TestReadMessageNotFound(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/messages/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusNotFound, ErrorResponse{Error: "not found"})
		})
	})
	_, err := c.ReadMessage(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestDeleteMessage(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Delete("/api/v1/messages/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, map[string]string{"status": "deleted"})
		})
	})
	err := c.DeleteMessage(context.Background(), "msg-456")
	require.NoError(t, err)
}

func TestDeleteMessageNotFound(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Delete("/api/v1/messages/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusNotFound, ErrorResponse{Error: "not found"})
		})
	})
	err := c.DeleteMessage(context.Background(), "nonexistent")
	require.Error(t, err)
}

// ==========================================================================
// Generation Ceremony Client Tests
// ==========================================================================

func TestStartGenerationCeremony(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/crk/generate-ceremony/start", func(w http.ResponseWriter, r *http.Request) {
			var req StartGenerationCeremonyRequest
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			assert.Equal(t, "org-1", req.OrgID)
			assert.Equal(t, 5, req.TotalShares)
			assert.Equal(t, 3, req.Threshold)
			writeJSONResponse(w, http.StatusOK, GenerationCeremonyResponse{
				ID:          "cer-1",
				OrgID:       "org-1",
				TotalShares: 5,
				Threshold:   3,
				Status:      "pending",
			})
		})
	})
	resp, err := c.StartGenerationCeremony(context.Background(), "org-1", 5, 3)
	require.NoError(t, err)
	assert.Equal(t, "cer-1", resp.ID)
	assert.Equal(t, "pending", resp.Status)
	assert.Equal(t, 5, resp.TotalShares)
	assert.Equal(t, 3, resp.Threshold)
}

func TestStartGenerationCeremonyError(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/crk/generate-ceremony/start", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusBadRequest, ErrorResponse{Error: "invalid threshold"})
		})
	})
	_, err := c.StartGenerationCeremony(context.Background(), "org-1", 3, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid threshold")
}

func TestSeedGenerationShare(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/crk/generate-ceremony/{id}/seed", func(w http.ResponseWriter, r *http.Request) {
			id := chi.URLParam(r, "id")
			assert.Equal(t, "cer-1", id)
			var req SeedGenerationShareRequest
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			assert.Equal(t, 1, req.Index)
			assert.NotEmpty(t, req.EncryptionKey)
			assert.NotEmpty(t, req.Salt)
			writeJSONResponse(w, http.StatusOK, map[string]string{"status": "ok"})
		})
	})
	err := c.SeedGenerationShare(context.Background(), "cer-1", SeedGenerationShareRequest{
		Index:         1,
		EncryptionKey: []byte("test-key-32-bytes-long-for-aes!!"),
		Salt:          []byte("16-byte-salt!!!!"),
		KDFParams: struct {
			Time    uint32 `json:"time"`
			Memory  uint32 `json:"memory"`
			Threads uint8  `json:"threads"`
		}{Time: 3, Memory: 65536, Threads: 4},
		CustodianName: "alice",
	})
	require.NoError(t, err)
}

func TestCompleteGenerationCeremony(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/crk/generate-ceremony/{id}/complete", func(w http.ResponseWriter, r *http.Request) {
			id := chi.URLParam(r, "id")
			assert.Equal(t, "cer-1", id)
			writeJSONResponse(w, http.StatusOK, GenerationCeremonyResponse{
				ID:     "cer-1",
				Status: "completed",
				CRK:    &models.CRK{ID: "crk-1", OrgID: "org-1"},
				EncryptedShares: []models.EncryptedCRKShare{
					{ID: "es-1", Index: 1, EncryptedData: []byte("enc1"), Salt: []byte("salt1")},
				},
			})
		})
	})
	resp, err := c.CompleteGenerationCeremony(context.Background(), "cer-1")
	require.NoError(t, err)
	assert.Equal(t, "completed", resp.Status)
	assert.NotNil(t, resp.CRK)
	assert.Len(t, resp.EncryptedShares, 1)
}

func TestGetGenerationCeremony(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/crk/generate-ceremony/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, GenerationCeremonyResponse{
				ID:     "cer-1",
				Status: "pending",
			})
		})
	})
	resp, err := c.GetGenerationCeremony(context.Background(), "cer-1")
	require.NoError(t, err)
	assert.Equal(t, "cer-1", resp.ID)
	assert.Equal(t, "pending", resp.Status)
}

func TestGetGenerationCeremonyNotFound(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/crk/generate-ceremony/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusNotFound, ErrorResponse{Error: "not found"})
		})
	})
	_, err := c.GetGenerationCeremony(context.Background(), "nonexistent")
	require.Error(t, err)
}

func TestCancelGenerationCeremony(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Delete("/api/v1/crk/generate-ceremony/{id}", func(w http.ResponseWriter, r *http.Request) {
			id := chi.URLParam(r, "id")
			assert.Equal(t, "cer-1", id)
			writeJSONResponse(w, http.StatusOK, map[string]string{"status": "cancelled"})
		})
	})
	err := c.CancelGenerationCeremony(context.Background(), "cer-1")
	require.NoError(t, err)
}

func TestGetEncryptedShare(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/crk/shares/{crkId}/{index}", func(w http.ResponseWriter, r *http.Request) {
			crkID := chi.URLParam(r, "crkId")
			assert.Equal(t, "crk-1", crkID)
			writeJSONResponse(w, http.StatusOK, models.EncryptedCRKShare{
				ID:            "es-1",
				CRKID:         "crk-1",
				Index:         1,
				EncryptedData: []byte("encrypted"),
				Salt:          []byte("salt"),
				KDFTime:       3,
				KDFMemory:     65536,
				KDFThreads:    4,
			})
		})
	})
	share, err := c.GetEncryptedShare(context.Background(), "crk-1", 1)
	require.NoError(t, err)
	assert.Equal(t, "crk-1", share.CRKID)
	assert.Equal(t, 1, share.Index)
	assert.NotEmpty(t, share.EncryptedData)
}

func TestGetEncryptedShareNotFound(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/crk/shares/{crkId}/{index}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusNotFound, ErrorResponse{Error: "share not found"})
		})
	})
	_, err := c.GetEncryptedShare(context.Background(), "nonexistent", 99)
	require.Error(t, err)
}

// =============================================================================
// Backup API Tests
// =============================================================================

func TestCreateBackup(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/backups", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusCreated, models.Backup{
				ID:    "backup-1",
				OrgID: "test-org",
				Type:  "full",
			})
		})
	})
	b, err := c.CreateBackup(context.Background(), CreateBackupRequest{
		Type:         "full",
		CRKSignature: []byte("sig"),
	})
	require.NoError(t, err)
	assert.Equal(t, "backup-1", b.ID)
	assert.Equal(t, "full", b.Type)
}

func TestCreateBackupError(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/backups", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusBadRequest, ErrorResponse{Error: "crk_signature required"})
		})
	})
	_, err := c.CreateBackup(context.Background(), CreateBackupRequest{Type: "full"})
	require.Error(t, err)
}

func TestListBackups(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/backups", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, BackupListResponse{
				Backups: []*models.Backup{
					{ID: "b1", OrgID: "test-org", Type: "full"},
					{ID: "b2", OrgID: "test-org", Type: "incremental"},
				},
				Count: 2,
			})
		})
	})
	resp, err := c.ListBackups(context.Background())
	require.NoError(t, err)
	assert.Len(t, resp.Backups, 2)
	assert.Equal(t, 2, resp.Count)
}

func TestGetBackup(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/backups/{id}", func(w http.ResponseWriter, r *http.Request) {
			id := chi.URLParam(r, "id")
			assert.Equal(t, "backup-1", id)
			writeJSONResponse(w, http.StatusOK, models.Backup{
				ID:    "backup-1",
				OrgID: "test-org",
				Type:  "full",
			})
		})
	})
	b, err := c.GetBackup(context.Background(), "backup-1")
	require.NoError(t, err)
	assert.Equal(t, "backup-1", b.ID)
}

func TestGetBackupNotFound(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Get("/api/v1/backups/{id}", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusNotFound, ErrorResponse{Error: "backup not found"})
		})
	})
	_, err := c.GetBackup(context.Background(), "nonexistent")
	require.Error(t, err)
}

func TestRestoreBackup(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/backups/{id}/restore", func(w http.ResponseWriter, r *http.Request) {
			id := chi.URLParam(r, "id")
			assert.Equal(t, "backup-1", id)
			w.WriteHeader(http.StatusNoContent)
		})
	})
	err := c.RestoreBackup(context.Background(), "backup-1", RestoreBackupRequest{
		CRKSignature: []byte("sig"),
	})
	require.NoError(t, err)
}

func TestRestoreBackupError(t *testing.T) {
	_, c := mockServer(t, func(r chi.Router) {
		r.Post("/api/v1/backups/{id}/restore", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusBadRequest, ErrorResponse{Error: "cannot restore backup from a different organization"})
		})
	})
	err := c.RestoreBackup(context.Background(), "backup-1", RestoreBackupRequest{
		CRKSignature: []byte("sig"),
	})
	require.Error(t, err)
}
