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
			writeJSONResponse(w, http.StatusOK, models.AdminIdentity{ID: "admin1", Email: "a@b.com"})
		})
	})
	admin, err := c.CreateAdmin(context.Background(), CreateAdminRequest{Email: "a@b.com", Name: "Admin"})
	require.NoError(t, err)
	assert.Equal(t, "admin1", admin.ID)
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
