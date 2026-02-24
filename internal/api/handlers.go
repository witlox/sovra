// Package api handles API gateway functionality.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

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
	apierrors "github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/pkg/vault"
)

// =============================================================================
// Common Helpers
// =============================================================================

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// readJSON reads and validates JSON request body.
func readJSON(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}
	defer func() { _ = r.Body.Close() }()
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}
	return nil
}

// handleError writes appropriate error response based on error type.
func handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, apierrors.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
	case errors.Is(err, apierrors.ErrUnauthorized):
		writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error())
	case errors.Is(err, apierrors.ErrForbidden):
		writeJSONError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
	case errors.Is(err, apierrors.ErrInvalidInput):
		writeJSONError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
	case errors.Is(err, apierrors.ErrConflict):
		writeJSONError(w, http.StatusConflict, "CONFLICT", err.Error())
	case errors.Is(err, apierrors.ErrPolicyViolation):
		writeJSONError(w, http.StatusForbidden, "POLICY_VIOLATION", err.Error())
	case errors.Is(err, apierrors.ErrCRKThresholdNotMet):
		writeJSONError(w, http.StatusBadRequest, "CRK_THRESHOLD_NOT_MET", err.Error())
	case errors.Is(err, apierrors.ErrFederationFailed):
		writeJSONError(w, http.StatusBadGateway, "FEDERATION_FAILED", err.Error())
	case errors.Is(err, apierrors.ErrEdgeNodeUnreachable):
		writeJSONError(w, http.StatusServiceUnavailable, "EDGE_UNREACHABLE", err.Error())
	case errors.Is(err, apierrors.ErrServiceUnavailable):
		writeJSONError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", err.Error())
	default:
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal server error")
	}
}

// getOrgID extracts organization ID from context.
func getOrgID(r *http.Request) string {
	if orgID, ok := r.Context().Value(ContextKeyOrgID).(string); ok {
		return orgID
	}
	return ""
}

// getPaginationParams extracts limit and offset from query params.
func getPaginationParams(r *http.Request) (limit, offset int) {
	limit = 50
	offset = 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	return
}

// =============================================================================
// Workspace Handler
// =============================================================================

// WorkspaceHandler handles workspace API requests.
type WorkspaceHandler struct {
	service workspace.Service
}

// NewWorkspaceHandler creates a new workspace handler.
func NewWorkspaceHandler(service workspace.Service) *WorkspaceHandler {
	return &WorkspaceHandler{service: service}
}

// CreateWorkspaceRequest represents workspace creation request.
type CreateWorkspaceRequest struct {
	Name           string                `json:"name"`
	Participants   []string              `json:"participants,omitempty"` // Deprecated: use GroupID
	GroupID        string                `json:"group_id,omitempty"`
	Classification models.Classification `json:"classification"`
	Mode           models.WorkspaceMode  `json:"mode"`
	Purpose        string                `json:"purpose"`
	CRKSignature   []byte                `json:"crk_signature"`
}

// Create handles POST /api/v1/workspaces.
func (h *WorkspaceHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateWorkspaceRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.Name == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "name is required")
		return
	}

	ws, err := h.service.Create(r.Context(), workspace.CreateRequest{
		Name:           req.Name,
		Participants:   req.Participants,
		GroupID:        req.GroupID,
		Classification: req.Classification,
		Mode:           req.Mode,
		Purpose:        req.Purpose,
		CRKSignature:   req.CRKSignature,
	})
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, ws)
}

// List handles GET /api/v1/workspaces.
func (h *WorkspaceHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r)
	limit, offset := getPaginationParams(r)

	workspaces, err := h.service.List(r.Context(), orgID, limit, offset)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"workspaces": workspaces,
		"count":      len(workspaces),
	})
}

// Get handles GET /api/v1/workspaces/{id}.
func (h *WorkspaceHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace id is required")
		return
	}

	ws, err := h.service.Get(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, ws)
}

// UpdateWorkspaceRequest represents workspace update request.
type UpdateWorkspaceRequest struct {
	Purpose        string                `json:"purpose,omitempty"`
	Classification models.Classification `json:"classification,omitempty"`
	Mode           models.WorkspaceMode  `json:"mode,omitempty"`
	Signature      []byte                `json:"signature"`
}

// Update handles PUT /api/v1/workspaces/{id}.
func (h *WorkspaceHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace id is required")
		return
	}

	var req UpdateWorkspaceRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	ws, err := h.service.Update(r.Context(), id, workspace.UpdateRequest{
		Purpose:        req.Purpose,
		Classification: req.Classification,
		Mode:           req.Mode,
		CRKSignature:   req.Signature,
	})
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, ws)
}

// RotateDEKRequest represents a DEK rotation request.
type RotateDEKRequest struct {
	Signature []byte `json:"signature"`
}

// RotateDEK handles POST /api/v1/workspaces/{id}/rotate-dek.
func (h *WorkspaceHandler) RotateDEK(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace id is required")
		return
	}

	var req RotateDEKRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if err := h.service.RotateDEK(r.Context(), id, req.Signature); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ExtendExpirationRequest represents an expiration extension request.
type ExtendExpirationRequest struct {
	ExpiresAt time.Time `json:"expires_at"`
	Signature []byte    `json:"signature"`
}

// ExtendExpiration handles POST /api/v1/workspaces/{id}/extend.
func (h *WorkspaceHandler) ExtendExpiration(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace id is required")
		return
	}

	var req ExtendExpirationRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.ExpiresAt.IsZero() {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "expires_at is required")
		return
	}

	if err := h.service.ExtendExpiration(r.Context(), id, req.ExpiresAt, req.Signature); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// InviteParticipantRequest represents a participant invitation request.
type InviteParticipantRequest struct {
	OrgID     string `json:"org_id"`
	Signature []byte `json:"signature"`
}

// InviteParticipant handles POST /api/v1/workspaces/{id}/invite.
func (h *WorkspaceHandler) InviteParticipant(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace id is required")
		return
	}

	var req InviteParticipantRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.OrgID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "org_id is required")
		return
	}

	invitation, err := h.service.InviteParticipant(r.Context(), id, req.OrgID, req.Signature)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, invitation)
}

// AcceptInvitationRequest represents an invitation acceptance request.
type AcceptInvitationRequest struct {
	OrgID     string `json:"org_id"`
	GroupID   string `json:"group_id,omitempty"`
	Signature []byte `json:"signature"`
}

// AcceptInvitation handles POST /api/v1/workspaces/{id}/accept-invitation.
func (h *WorkspaceHandler) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace id is required")
		return
	}

	var req AcceptInvitationRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.OrgID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "org_id is required")
		return
	}

	if err := h.service.AcceptInvitation(r.Context(), id, req.OrgID, req.Signature); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// DeclineInvitationRequest represents an invitation decline request.
type DeclineInvitationRequest struct {
	OrgID string `json:"org_id"`
}

// DeclineInvitation handles POST /api/v1/workspaces/{id}/decline-invitation.
func (h *WorkspaceHandler) DeclineInvitation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace id is required")
		return
	}

	var req DeclineInvitationRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.OrgID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "org_id is required")
		return
	}

	if err := h.service.DeclineInvitation(r.Context(), id, req.OrgID); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Delete handles DELETE /api/v1/workspaces/{id}.
func (h *WorkspaceHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace id is required")
		return
	}

	var req struct {
		Signatures map[string][]byte `json:"signatures"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if err := h.service.Delete(r.Context(), id, req.Signatures); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// EncryptRequest represents an encryption request.
type EncryptRequest struct {
	Plaintext []byte            `json:"plaintext"`
	Context   map[string]string `json:"context,omitempty"`
}

// EncryptResponse represents an encryption response.
type EncryptResponse struct {
	Ciphertext []byte `json:"ciphertext"`
}

// Encrypt handles POST /api/v1/workspaces/{id}/encrypt.
func (h *WorkspaceHandler) Encrypt(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace id is required")
		return
	}

	var req EncryptRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if len(req.Plaintext) == 0 {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "plaintext is required")
		return
	}

	ciphertext, err := h.service.Encrypt(r.Context(), id, req.Plaintext)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, EncryptResponse{Ciphertext: ciphertext})
}

// DecryptRequest represents a decryption request.
type DecryptRequest struct {
	Ciphertext []byte            `json:"ciphertext"`
	Context    map[string]string `json:"context,omitempty"`
}

// DecryptResponse represents a decryption response.
type DecryptResponse struct {
	Plaintext []byte `json:"plaintext"`
}

// Decrypt handles POST /api/v1/workspaces/{id}/decrypt.
func (h *WorkspaceHandler) Decrypt(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace id is required")
		return
	}

	var req DecryptRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if len(req.Ciphertext) == 0 {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "ciphertext is required")
		return
	}

	plaintext, err := h.service.Decrypt(r.Context(), id, req.Ciphertext)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, DecryptResponse{Plaintext: plaintext})
}

// Archive handles POST /api/v1/workspaces/{id}/archive.
func (h *WorkspaceHandler) Archive(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace id is required")
		return
	}

	var req struct {
		Signature []byte `json:"signature"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if err := h.service.Archive(r.Context(), id, req.Signature); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Federation Handler
// =============================================================================

// FederationHandler handles federation API requests.
type FederationHandler struct {
	service federation.Service
}

// NewFederationHandler creates a new federation handler.
func NewFederationHandler(service federation.Service) *FederationHandler {
	return &FederationHandler{service: service}
}

// InitFederationRequest represents federation initialization request.
type InitFederationRequest struct {
	OrgID        string `json:"org_id"`
	CRKSignature []byte `json:"crk_signature"`
}

// Init handles POST /api/v1/federation/init.
func (h *FederationHandler) Init(w http.ResponseWriter, r *http.Request) {
	var req InitFederationRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	orgID := req.OrgID
	if orgID == "" {
		orgID = getOrgID(r)
	}

	resp, err := h.service.Init(r.Context(), federation.InitRequest{
		OrgID:        orgID,
		CRKSignature: req.CRKSignature,
	})
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// EstablishFederationRequest represents federation establishment request.
type EstablishFederationRequest struct {
	PartnerOrgID string `json:"partner_org_id"`
	PartnerURL   string `json:"partner_url"`
	PartnerCert  []byte `json:"partner_cert"`
	PartnerCSR   []byte `json:"partner_csr"`
	CRKSignature []byte `json:"crk_signature"`
}

// Establish handles POST /api/v1/federation/establish.
func (h *FederationHandler) Establish(w http.ResponseWriter, r *http.Request) {
	var req EstablishFederationRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.PartnerOrgID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "partner_org_id is required")
		return
	}

	fed, err := h.service.Establish(r.Context(), federation.EstablishRequest{
		PartnerOrgID: req.PartnerOrgID,
		PartnerURL:   req.PartnerURL,
		PartnerCert:  req.PartnerCert,
		PartnerCSR:   req.PartnerCSR,
		CRKSignature: req.CRKSignature,
	})
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, fed)
}

// List handles GET /api/v1/federation.
func (h *FederationHandler) List(w http.ResponseWriter, r *http.Request) {
	federations, err := h.service.List(r.Context())
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"federations": federations,
		"count":       len(federations),
	})
}

// Status handles GET /api/v1/federation/{partnerId}.
func (h *FederationHandler) Status(w http.ResponseWriter, r *http.Request) {
	partnerID := chi.URLParam(r, "partnerId")
	if partnerID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "partner id is required")
		return
	}

	fed, err := h.service.Status(r.Context(), partnerID)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, fed)
}

// RevokeFederationRequest represents federation revocation request.
type RevokeFederationRequest struct {
	Signature     []byte `json:"signature"`
	NotifyPartner bool   `json:"notify_partner"`
	RevokeCerts   bool   `json:"revoke_certs"`
}

// Revoke handles DELETE /api/v1/federation/{partnerId}.
func (h *FederationHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	partnerID := chi.URLParam(r, "partnerId")
	if partnerID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "partner id is required")
		return
	}

	var req RevokeFederationRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if err := h.service.Revoke(r.Context(), federation.RevocationRequest{
		PartnerOrgID:  partnerID,
		Signature:     req.Signature,
		NotifyPartner: req.NotifyPartner,
		RevokeCerts:   req.RevokeCerts,
	}); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// HealthCheck handles GET /api/v1/federation/health.
func (h *FederationHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	results, err := h.service.HealthCheck(r.Context())
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"results": results,
	})
}

// ImportCertificateRequest represents certificate import request.
type ImportCertificateRequest struct {
	PartnerOrgID string `json:"partner_org_id"`
	Certificate  []byte `json:"certificate"`
	Signature    []byte `json:"signature"`
}

// ImportCertificate handles POST /api/v1/federation/certificate/import.
func (h *FederationHandler) ImportCertificate(w http.ResponseWriter, r *http.Request) {
	var req ImportCertificateRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.PartnerOrgID == "" || len(req.Certificate) == 0 {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "partner_org_id and certificate are required")
		return
	}

	if err := h.service.ImportCertificate(r.Context(), req.PartnerOrgID, req.Certificate, req.Signature); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RenewCertificateRequest represents federation certificate renewal request.
type RenewCertificateRequest struct {
	Signature []byte `json:"signature"`
}

// RenewCertificate handles POST /api/v1/federation/{partnerId}/renew-cert.
func (h *FederationHandler) RenewCertificate(w http.ResponseWriter, r *http.Request) {
	partnerID := chi.URLParam(r, "partnerId")
	if partnerID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "partner id is required")
		return
	}

	var req RenewCertificateRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	cert, err := h.service.RotateCertificate(r.Context(), partnerID, req.Signature)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"certificate": cert,
		"partner_id":  partnerID,
	})
}

// =============================================================================
// Policy Handler
// =============================================================================

// PolicyHandler handles policy API requests.
type PolicyHandler struct {
	service policy.Service
}

// NewPolicyHandler creates a new policy handler.
func NewPolicyHandler(service policy.Service) *PolicyHandler {
	return &PolicyHandler{service: service}
}

// CreatePolicyRequest represents policy creation request.
type CreatePolicyRequest struct {
	Name         string `json:"name"`
	Workspace    string `json:"workspace"`
	Rego         string `json:"rego"`
	CRKSignature []byte `json:"crk_signature"`
}

// Create handles POST /api/v1/policies.
func (h *PolicyHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreatePolicyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.Name == "" || req.Rego == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "name and rego are required")
		return
	}

	pol, err := h.service.Create(r.Context(), policy.CreateRequest{
		Name:         req.Name,
		Workspace:    req.Workspace,
		Rego:         req.Rego,
		CRKSignature: req.CRKSignature,
	})
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, pol)
}

// Get handles GET /api/v1/policies/{id}.
func (h *PolicyHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "policy id is required")
		return
	}

	pol, err := h.service.Get(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, pol)
}

// UpdatePolicyRequest represents policy update request.
type UpdatePolicyRequest struct {
	Rego      string `json:"rego"`
	Signature []byte `json:"signature"`
}

// Update handles PUT /api/v1/policies/{id}.
func (h *PolicyHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "policy id is required")
		return
	}

	var req UpdatePolicyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.Rego == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "rego is required")
		return
	}

	pol, err := h.service.Update(r.Context(), id, req.Rego, req.Signature)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, pol)
}

// Delete handles DELETE /api/v1/policies/{id}.
func (h *PolicyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "policy id is required")
		return
	}

	var req struct {
		Signature []byte `json:"signature"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if err := h.service.Delete(r.Context(), id, req.Signature); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetForWorkspace handles GET /api/v1/policies/workspace/{workspaceId}.
func (h *PolicyHandler) GetForWorkspace(w http.ResponseWriter, r *http.Request) {
	workspaceID := chi.URLParam(r, "workspaceId")
	if workspaceID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace id is required")
		return
	}

	policies, err := h.service.GetForWorkspace(r.Context(), workspaceID)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"policies": policies,
		"count":    len(policies),
	})
}

// EvaluatePolicyRequest represents policy evaluation request.
type EvaluatePolicyRequest struct {
	Actor     string         `json:"actor"`
	Role      string         `json:"role"`
	Operation string         `json:"operation"`
	Workspace string         `json:"workspace"`
	Purpose   string         `json:"purpose"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// Evaluate handles POST /api/v1/policies/evaluate.
func (h *PolicyHandler) Evaluate(w http.ResponseWriter, r *http.Request) {
	var req EvaluatePolicyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	result, err := h.service.Evaluate(r.Context(), models.PolicyInput{
		Actor:     req.Actor,
		Role:      req.Role,
		Operation: req.Operation,
		Workspace: req.Workspace,
		Purpose:   req.Purpose,
		Time:      time.Now(),
		Metadata:  req.Metadata,
	})
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// ValidatePolicyRequest represents policy validation request.
type ValidatePolicyRequest struct {
	Rego string `json:"rego"`
}

// Validate handles POST /api/v1/policies/validate.
func (h *PolicyHandler) Validate(w http.ResponseWriter, r *http.Request) {
	var req ValidatePolicyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.Rego == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "rego is required")
		return
	}

	if err := h.service.Validate(r.Context(), req.Rego); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"valid": true})
}

// =============================================================================
// Audit Handler
// =============================================================================

// AuditHandler handles audit API requests.
type AuditHandler struct {
	service audit.Service
}

// NewAuditHandler creates a new audit handler.
func NewAuditHandler(service audit.Service) *AuditHandler {
	return &AuditHandler{service: service}
}

// Query handles GET /api/v1/audit.
func (h *AuditHandler) Query(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	limit, offset := getPaginationParams(r)

	var since, until time.Time
	if s := query.Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}
	if u := query.Get("until"); u != "" {
		if t, err := time.Parse(time.RFC3339, u); err == nil {
			until = t
		}
	}

	events, err := h.service.Query(r.Context(), audit.QueryParams{
		OrgID:     query.Get("org_id"),
		Workspace: query.Get("workspace"),
		EventType: models.AuditEventType(query.Get("event_type")),
		Actor:     query.Get("actor"),
		Since:     since,
		Until:     until,
		Limit:     limit,
		Offset:    offset,
	})
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"count":  len(events),
	})
}

// Get handles GET /api/v1/audit/{id}.
func (h *AuditHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "audit event id is required")
		return
	}

	event, err := h.service.Get(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, event)
}

// ExportAuditRequest represents audit export request.
type ExportAuditRequest struct {
	OrgID     string             `json:"org_id"`
	Workspace string             `json:"workspace"`
	EventType string             `json:"event_type"`
	Since     string             `json:"since"`
	Until     string             `json:"until"`
	Format    audit.ExportFormat `json:"format"`
}

// Export handles POST /api/v1/audit/export.
func (h *AuditHandler) Export(w http.ResponseWriter, r *http.Request) {
	var req ExportAuditRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	var since, until time.Time
	if req.Since != "" {
		if t, err := time.Parse(time.RFC3339, req.Since); err == nil {
			since = t
		}
	}
	if req.Until != "" {
		if t, err := time.Parse(time.RFC3339, req.Until); err == nil {
			until = t
		}
	}

	format := req.Format
	if format == "" {
		format = audit.ExportFormatJSON
	}

	data, err := h.service.Export(r.Context(), audit.ExportRequest{
		Query: audit.QueryParams{
			OrgID:     req.OrgID,
			Workspace: req.Workspace,
			EventType: models.AuditEventType(req.EventType),
			Since:     since,
			Until:     until,
		},
		Format: format,
	})
	if err != nil {
		handleError(w, err)
		return
	}

	contentType := "application/json"
	if format == audit.ExportFormatCSV {
		contentType = "text/csv"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename=audit-export."+string(format))
	_, _ = w.Write(data)
}

// GetStats handles GET /api/v1/audit/stats.
func (h *AuditHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	var since time.Time
	if s := query.Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}
	if since.IsZero() {
		since = time.Now().Add(-24 * time.Hour)
	}

	stats, err := h.service.GetStats(r.Context(), since)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

// VerifyIntegrityRequest represents integrity verification request.
type VerifyIntegrityRequest struct {
	Since string `json:"since"`
	Until string `json:"until"`
}

// VerifyIntegrity handles POST /api/v1/audit/verify.
func (h *AuditHandler) VerifyIntegrity(w http.ResponseWriter, r *http.Request) {
	var req VerifyIntegrityRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	var since, until time.Time
	if req.Since != "" {
		if t, err := time.Parse(time.RFC3339, req.Since); err == nil {
			since = t
		}
	}
	if req.Until != "" {
		if t, err := time.Parse(time.RFC3339, req.Until); err == nil {
			until = t
		}
	}

	valid, err := h.service.VerifyIntegrity(r.Context(), since, until)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"valid": valid,
		"since": since.Format(time.RFC3339),
		"until": until.Format(time.RFC3339),
	})
}

// =============================================================================
// Edge Handler
// =============================================================================

// EdgeHandler handles edge node API requests.
type EdgeHandler struct {
	service edge.Service
}

// NewEdgeHandler creates a new edge handler.
func NewEdgeHandler(service edge.Service) *EdgeHandler {
	return &EdgeHandler{service: service}
}

// RegisterEdgeRequest represents edge node registration request.
type RegisterEdgeRequest struct {
	Name           string                `json:"name"`
	VaultAddress   string                `json:"vault_address"`
	VaultToken     string                `json:"vault_token"`
	VaultCACert    string                `json:"vault_ca_cert"`
	Classification models.Classification `json:"classification"`
	Region         string                `json:"region"`
	Tags           map[string]string     `json:"tags"`
}

// Register handles POST /api/v1/edges.
func (h *EdgeHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterEdgeRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.Name == "" || req.VaultAddress == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "name and vault_address are required")
		return
	}

	orgID := getOrgID(r)
	node, err := h.service.Register(r.Context(), orgID, &edge.NodeConfig{
		Name:           req.Name,
		VaultAddress:   req.VaultAddress,
		VaultToken:     req.VaultToken,
		VaultCACert:    req.VaultCACert,
		Classification: req.Classification,
		Region:         req.Region,
		Tags:           req.Tags,
	})
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, node)
}

// List handles GET /api/v1/edges.
func (h *EdgeHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r)
	nodes, err := h.service.List(r.Context(), orgID)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"edges": nodes,
		"count": len(nodes),
	})
}

// Get handles GET /api/v1/edges/{id}.
func (h *EdgeHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "edge id is required")
		return
	}

	node, err := h.service.Get(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, node)
}

// Unregister handles DELETE /api/v1/edges/{id}.
func (h *EdgeHandler) Unregister(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "edge id is required")
		return
	}

	if err := h.service.Unregister(r.Context(), id); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// HealthCheck handles GET /api/v1/edges/{id}/health.
func (h *EdgeHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "edge id is required")
		return
	}

	status, err := h.service.HealthCheck(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// SyncPoliciesRequest represents policy sync request.
type SyncPoliciesRequest struct {
	Policies []*models.Policy `json:"policies"`
}

// SyncPolicies handles POST /api/v1/edges/{id}/sync/policies.
func (h *EdgeHandler) SyncPolicies(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "edge id is required")
		return
	}

	var req SyncPoliciesRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if err := h.service.SyncPolicies(r.Context(), id, req.Policies); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SyncWorkspaceKeysRequest represents workspace keys sync request.
type SyncWorkspaceKeysRequest struct {
	WorkspaceID string `json:"workspace_id"`
	WrappedDEK  []byte `json:"wrapped_dek"`
}

// SyncWorkspaceKeys handles POST /api/v1/edges/{id}/sync/keys.
func (h *EdgeHandler) SyncWorkspaceKeys(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "edge id is required")
		return
	}

	var req SyncWorkspaceKeysRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.WorkspaceID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace_id is required")
		return
	}

	if err := h.service.SyncWorkspaceKeys(r.Context(), id, req.WorkspaceID, req.WrappedDEK); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetSyncStatus handles GET /api/v1/edges/{id}/sync/status.
func (h *EdgeHandler) GetSyncStatus(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "edge id is required")
		return
	}

	status, err := h.service.GetSyncStatus(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// =============================================================================
// CRK Handler
// =============================================================================

// CRKHandler handles CRK (Customer Root Key) API requests.
type CRKHandler struct {
	manager  crk.Manager
	ceremony crk.CeremonyManager
}

// NewCRKHandler creates a new CRK handler.
func NewCRKHandler(manager crk.Manager, ceremony crk.CeremonyManager) *CRKHandler {
	return &CRKHandler{manager: manager, ceremony: ceremony}
}

// GenerateCRKRequest represents CRK generation request.
type GenerateCRKRequest struct {
	OrgID       string `json:"org_id"`
	TotalShares int    `json:"total_shares"`
	Threshold   int    `json:"threshold"`
}

// Generate handles POST /api/v1/crk/generate.
func (h *CRKHandler) Generate(w http.ResponseWriter, r *http.Request) {
	var req GenerateCRKRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	orgID := req.OrgID
	if orgID == "" {
		orgID = getOrgID(r)
	}

	if req.TotalShares < 1 || req.Threshold < 1 || req.Threshold > req.TotalShares {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid shares configuration")
		return
	}

	result, err := h.manager.Generate(orgID, req.TotalShares, req.Threshold)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, result)
}

// SignCRKRequest represents CRK signing request.
type SignCRKRequest struct {
	Shares    []models.CRKShare `json:"shares"`
	PublicKey []byte            `json:"public_key"`
	Data      []byte            `json:"data"`
}

// Sign handles POST /api/v1/crk/sign.
func (h *CRKHandler) Sign(w http.ResponseWriter, r *http.Request) {
	var req SignCRKRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if len(req.Shares) == 0 || len(req.Data) == 0 {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "shares and data are required")
		return
	}

	signature, err := h.manager.Sign(req.Shares, req.PublicKey, req.Data)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"signature": signature,
	})
}

// VerifyCRKRequest represents CRK verification request.
type VerifyCRKRequest struct {
	PublicKey []byte `json:"public_key"`
	Data      []byte `json:"data"`
	Signature []byte `json:"signature"`
}

// Verify handles POST /api/v1/crk/verify.
func (h *CRKHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var req VerifyCRKRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if len(req.PublicKey) == 0 || len(req.Data) == 0 || len(req.Signature) == 0 {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "public_key, data, and signature are required")
		return
	}

	valid, err := h.manager.Verify(req.PublicKey, req.Data, req.Signature)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"valid": valid,
	})
}

// StartCeremonyRequest represents ceremony start request.
type StartCeremonyRequest struct {
	OrgID     string `json:"org_id"`
	Operation string `json:"operation"`
	Threshold int    `json:"threshold"`
}

// StartCeremony handles POST /api/v1/crk/ceremony/start.
func (h *CRKHandler) StartCeremony(w http.ResponseWriter, r *http.Request) {
	if h.ceremony == nil {
		writeJSONError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "ceremony manager not configured")
		return
	}

	var req StartCeremonyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	orgID := req.OrgID
	if orgID == "" {
		orgID = getOrgID(r)
	}

	ceremony, err := h.ceremony.StartCeremony(orgID, req.Operation, req.Threshold)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, ceremony)
}

// AddShareRequest represents add share request.
type AddShareRequest struct {
	Share models.CRKShare `json:"share"`
}

// AddShare handles POST /api/v1/crk/ceremony/{id}/share.
func (h *CRKHandler) AddShare(w http.ResponseWriter, r *http.Request) {
	if h.ceremony == nil {
		writeJSONError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "ceremony manager not configured")
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "ceremony id is required")
		return
	}

	var req AddShareRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if err := h.ceremony.AddShare(id, req.Share); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// CompleteCeremonyRequest represents ceremony completion request.
type CompleteCeremonyRequest struct {
	Witness string `json:"witness"`
}

// CompleteCeremony handles POST /api/v1/crk/ceremony/{id}/complete.
func (h *CRKHandler) CompleteCeremony(w http.ResponseWriter, r *http.Request) {
	if h.ceremony == nil {
		writeJSONError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "ceremony manager not configured")
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "ceremony id is required")
		return
	}

	var req CompleteCeremonyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	result, err := h.ceremony.CompleteCeremony(id, req.Witness)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"result": result,
	})
}

// RotateCRKRequest represents a CRK rotation request.
type RotateCRKRequest struct {
	OrgID     string `json:"org_id"`
	Threshold int    `json:"threshold"`
}

// RotateCRK handles POST /api/v1/crk/rotate.
func (h *CRKHandler) RotateCRK(w http.ResponseWriter, r *http.Request) {
	if h.ceremony == nil {
		writeJSONError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "ceremony manager not configured")
		return
	}

	var req RotateCRKRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	orgID := req.OrgID
	if orgID == "" {
		orgID = getOrgID(r)
	}

	threshold := req.Threshold
	if threshold < 1 {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "threshold must be at least 1")
		return
	}

	ceremony, err := h.ceremony.StartCeremony(orgID, "rotate", threshold)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, ceremony)
}

// CancelCeremony handles DELETE /api/v1/crk/ceremony/{id}.
func (h *CRKHandler) CancelCeremony(w http.ResponseWriter, r *http.Request) {
	if h.ceremony == nil {
		writeJSONError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "ceremony manager not configured")
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "ceremony id is required")
		return
	}

	if err := h.ceremony.CancelCeremony(id); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Generation Ceremony Handler (Password-Protected Shares)
// =============================================================================

// GenerationCeremonyHandler handles generation ceremony API requests.
type GenerationCeremonyHandler struct {
	genCeremony crk.GenerationCeremonyManager
}

// NewGenerationCeremonyHandler creates a new generation ceremony handler.
func NewGenerationCeremonyHandler(genCeremony crk.GenerationCeremonyManager) *GenerationCeremonyHandler {
	return &GenerationCeremonyHandler{genCeremony: genCeremony}
}

// StartGenerationCeremonyRequest represents a generation ceremony start request.
type StartGenerationCeremonyRequest struct {
	OrgID       string `json:"org_id"`
	TotalShares int    `json:"total_shares"`
	Threshold   int    `json:"threshold"`
}

// Start handles POST /api/v1/crk/generate-ceremony/start.
func (h *GenerationCeremonyHandler) Start(w http.ResponseWriter, r *http.Request) {
	var req StartGenerationCeremonyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	orgID := req.OrgID
	if orgID == "" {
		orgID = getOrgID(r)
	}

	if req.TotalShares < 2 || req.Threshold < 1 || req.Threshold > req.TotalShares {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid shares configuration")
		return
	}

	ceremony, err := h.genCeremony.StartGenerationCeremony(orgID, req.TotalShares, req.Threshold)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, ceremony)
}

// SeedShareRequest represents a seed share request.
type SeedShareRequest struct {
	Index         int           `json:"index"`
	EncryptionKey []byte        `json:"encryption_key"`
	Salt          []byte        `json:"salt"`
	KDFParams     crk.KDFParams `json:"kdf_params"`
	CustodianName string        `json:"custodian_name"`
}

// Seed handles POST /api/v1/crk/generate-ceremony/{id}/seed.
func (h *GenerationCeremonyHandler) Seed(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "ceremony id is required")
		return
	}

	var req SeedShareRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.Index < 1 || len(req.EncryptionKey) == 0 || len(req.Salt) == 0 {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "index, encryption_key, and salt are required")
		return
	}

	if err := h.genCeremony.SeedShare(id, req.Index, req.EncryptionKey, req.Salt, req.KDFParams, req.CustodianName); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Complete handles POST /api/v1/crk/generate-ceremony/{id}/complete.
func (h *GenerationCeremonyHandler) Complete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "ceremony id is required")
		return
	}

	ceremony, err := h.genCeremony.CompleteGenerationCeremony(id)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, ceremony)
}

// Status handles GET /api/v1/crk/generate-ceremony/{id}.
func (h *GenerationCeremonyHandler) Status(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "ceremony id is required")
		return
	}

	ceremony, err := h.genCeremony.GetGenerationCeremony(id)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, ceremony)
}

// Cancel handles DELETE /api/v1/crk/generate-ceremony/{id}.
func (h *GenerationCeremonyHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "ceremony id is required")
		return
	}

	if err := h.genCeremony.CancelGenerationCeremony(id); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetEncryptedShare handles GET /api/v1/crk/shares/{crkId}/{index}.
func (h *GenerationCeremonyHandler) GetEncryptedShare(w http.ResponseWriter, r *http.Request) {
	crkID := chi.URLParam(r, "crkId")
	indexStr := chi.URLParam(r, "index")

	if crkID == "" || indexStr == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "crk_id and index are required")
		return
	}

	index, err := strconv.Atoi(indexStr)
	if err != nil || index < 1 {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid share index")
		return
	}

	share, err := h.genCeremony.GetEncryptedShare(crkID, index)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, share)
}

// =============================================================================
// Identity Handler
// =============================================================================

// IdentityHandler handles identity management API requests.
type IdentityHandler struct {
	manager *identity.Manager
}

// NewIdentityHandler creates a new identity handler.
func NewIdentityHandler(manager *identity.Manager) *IdentityHandler {
	return &IdentityHandler{manager: manager}
}

// --- Admin Request Types ---

// CreateAdminRequest represents an admin creation request.
type CreateAdminRequest struct {
	Email        string             `json:"email"`
	Name         string             `json:"name"`
	Role         models.AdminRole   `json:"role"`
	CRKSignature []byte             `json:"crk_signature"`
	SSOProvider  models.SSOProvider `json:"sso_provider,omitempty"`
	SSOSubject   string             `json:"sso_subject,omitempty"`
}

// BootstrapAdminRequest represents a bootstrap admin creation request.
type BootstrapAdminRequest struct {
	OrgID        string           `json:"org_id"`
	Email        string           `json:"email"`
	Name         string           `json:"name"`
	Role         models.AdminRole `json:"role"`
	CRKSignature []byte           `json:"crk_signature"`
}

// EnrollAdminRequest represents an admin enrollment request.
type EnrollAdminRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	TOTPCode        string `json:"totp_code"`
}

// RenewAdminCertRequest represents a certificate renewal request.
type RenewAdminCertRequest struct {
	TOTPCode string `json:"totp_code"`
}

// UpdateAdminRequest represents an admin update request.
type UpdateAdminRequest struct {
	Email  string           `json:"email,omitempty"`
	Name   string           `json:"name,omitempty"`
	Role   models.AdminRole `json:"role,omitempty"`
	Active *bool            `json:"active,omitempty"`
}

// VerifyMFARequest represents an MFA verification request.
type VerifyMFARequest struct {
	TOTPCode string `json:"totp_code"`
}

// --- User Request Types ---

// CreateUserFromSSORequest represents a user creation from SSO request.
type CreateUserFromSSORequest struct {
	Provider models.SSOProvider `json:"provider"`
	Subject  string             `json:"subject"`
	Email    string             `json:"email"`
	Name     string             `json:"name"`
	Groups   []string           `json:"groups,omitempty"`
}

// --- Service Request Types ---

// CreateServiceRequest represents a service identity creation request.
type CreateServiceRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	AuthMethod  models.AuthMethod `json:"auth_method"`
}

// --- Device Request Types ---

// EnrollDeviceRequest represents a device enrollment request.
type EnrollDeviceRequest struct {
	DeviceName string    `json:"device_name"`
	DeviceType string    `json:"device_type,omitempty"`
	CertSerial string    `json:"cert_serial"`
	CertExpiry time.Time `json:"cert_expiry"`
}

// --- Group Request Types ---

// CreateGroupRequest represents a group creation request.
type CreateGroupRequest struct {
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	IDPGroupID    string   `json:"idp_group_id,omitempty"`
	VaultPolicies []string `json:"vault_policies,omitempty"`
}

// UpdateGroupRequest represents a group update request.
type UpdateGroupRequest struct {
	Name          string   `json:"name,omitempty"`
	Description   string   `json:"description,omitempty"`
	IDPGroupID    *string  `json:"idp_group_id,omitempty"`
	VaultPolicies []string `json:"vault_policies,omitempty"`
}

// AddGroupMemberRequest represents a request to add a member to a group.
type AddGroupMemberRequest struct {
	IdentityID   string              `json:"identity_id"`
	IdentityType models.IdentityType `json:"identity_type"`
}

// --- Role Request Types ---

// CreateRoleRequest represents a role creation request.
type CreateRoleRequest struct {
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	Permissions []models.Permission `json:"permissions"`
}

// AssignRoleRequest represents a role assignment request.
type AssignRoleRequest struct {
	IdentityID   string              `json:"identity_id"`
	IdentityType models.IdentityType `json:"identity_type"`
	AssignedBy   string              `json:"assigned_by"`
}

// =============================================================================
// Admin Handlers
// =============================================================================

// CreateAdmin handles POST /api/v1/identities/admins.
func (h *IdentityHandler) CreateAdmin(w http.ResponseWriter, r *http.Request) {
	var req CreateAdminRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.Email == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "email is required")
		return
	}
	if req.Name == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "name is required")
		return
	}
	if len(req.CRKSignature) == 0 {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "crk_signature is required")
		return
	}

	// Extract caller admin ID from context (set by AdminCertMiddleware)
	callerAdminID, ok := r.Context().Value(ContextKeyAdminID).(string)
	if !ok || callerAdminID == "" {
		writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "admin certificate authentication required")
		return
	}

	orgID := getOrgID(r)
	var opts *identity.CreateAdminOptions
	if req.SSOProvider != "" || req.SSOSubject != "" {
		opts = &identity.CreateAdminOptions{
			SSOProvider: req.SSOProvider,
			SSOSubject:  req.SSOSubject,
		}
	}
	admin, enrollmentToken, err := h.manager.CreateAdmin(r.Context(), orgID, callerAdminID, req.Email, req.Name, req.Role, req.CRKSignature, opts)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"admin":            admin,
		"enrollment_token": enrollmentToken,
	})
}

// BootstrapAdmin handles POST /api/v1/bootstrap/admin.
func (h *IdentityHandler) BootstrapAdmin(w http.ResponseWriter, r *http.Request) {
	var req BootstrapAdminRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.OrgID == "" || req.Email == "" || req.Name == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "org_id, email and name are required")
		return
	}
	if len(req.CRKSignature) == 0 {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "crk_signature is required")
		return
	}

	admin, enrollmentToken, err := h.manager.BootstrapAdmin(r.Context(), req.OrgID, req.Email, req.Name, req.Role, req.CRKSignature)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"admin":            admin,
		"enrollment_token": enrollmentToken,
	})
}

// GetEnrollmentSetup handles GET /api/v1/enrollment/admins/{id}/setup.
func (h *IdentityHandler) GetEnrollmentSetup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "admin id is required")
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "token is required")
		return
	}

	provisioningURL, err := h.manager.GetEnrollmentSetup(r.Context(), id, token)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"provisioning_url": provisioningURL,
	})
}

// EnrollAdmin handles POST /api/v1/enrollment/admins/{id}.
func (h *IdentityHandler) EnrollAdmin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "admin id is required")
		return
	}

	var req EnrollAdminRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.EnrollmentToken == "" || req.TOTPCode == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "enrollment_token and totp_code are required")
		return
	}

	admin, certResult, err := h.manager.EnrollAdmin(r.Context(), id, req.EnrollmentToken, req.TOTPCode)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"admin":       admin,
		"certificate": certResult.Certificate,
		"private_key": certResult.CertKey,
		"serial":      certResult.SerialNumber,
		"expiration":  certResult.Expiration,
	})
}

// RenewAdminCertificate handles POST /api/v1/identities/admins/{id}/certificate/renew.
func (h *IdentityHandler) RenewAdminCertificate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "admin id is required")
		return
	}

	var req RenewAdminCertRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.TOTPCode == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "totp_code is required")
		return
	}

	certResult, err := h.manager.RenewAdminCertificate(r.Context(), id, req.TOTPCode)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"certificate": certResult.Certificate,
		"private_key": certResult.CertKey,
		"serial":      certResult.SerialNumber,
		"expiration":  certResult.Expiration,
	})
}

// ListAdmins handles GET /api/v1/identities/admins.
func (h *IdentityHandler) ListAdmins(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r)

	admins, err := h.manager.ListAdmins(r.Context(), orgID)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"admins": admins,
		"count":  len(admins),
	})
}

// GetAdmin handles GET /api/v1/identities/admins/{id}.
func (h *IdentityHandler) GetAdmin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "admin id is required")
		return
	}

	admin, err := h.manager.GetAdmin(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, admin)
}

// UpdateAdmin handles PUT /api/v1/identities/admins/{id}.
func (h *IdentityHandler) UpdateAdmin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "admin id is required")
		return
	}

	var req UpdateAdminRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	admin, err := h.manager.GetAdmin(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	if req.Email != "" {
		admin.Email = req.Email
	}
	if req.Name != "" {
		admin.Name = req.Name
	}
	if req.Role != "" {
		admin.Role = req.Role
	}
	if req.Active != nil {
		admin.Active = *req.Active
	}

	if err := h.manager.UpdateAdmin(r.Context(), admin); err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, admin)
}

// DeleteAdmin handles DELETE /api/v1/identities/admins/{id}.
func (h *IdentityHandler) DeleteAdmin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "admin id is required")
		return
	}

	if err := h.manager.DeleteAdmin(r.Context(), id); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// EnableMFA handles POST /api/v1/identities/admins/{id}/mfa/enable.
func (h *IdentityHandler) EnableMFA(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "admin id is required")
		return
	}

	provisioningURL, err := h.manager.EnableMFA(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"provisioning_url": provisioningURL,
	})
}

// VerifyMFA handles POST /api/v1/identities/admins/{id}/mfa/verify.
func (h *IdentityHandler) VerifyMFA(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "admin id is required")
		return
	}

	var req VerifyMFARequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.TOTPCode == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "totp_code is required")
		return
	}

	if err := h.manager.VerifyMFA(r.Context(), id, req.TOTPCode); err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"verified": true,
	})
}

// =============================================================================
// User Handlers
// =============================================================================

// CreateUserFromSSO handles POST /api/v1/identities/users/sso.
func (h *IdentityHandler) CreateUserFromSSO(w http.ResponseWriter, r *http.Request) {
	var req CreateUserFromSSORequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.Provider == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "provider is required")
		return
	}
	if req.Subject == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "subject is required")
		return
	}
	if req.Email == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "email is required")
		return
	}

	orgID := getOrgID(r)
	user, err := h.manager.CreateUserFromSSO(r.Context(), orgID, req.Provider, req.Subject, req.Email, req.Name, req.Groups)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, user)
}

// ListUsers handles GET /api/v1/identities/users.
func (h *IdentityHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r)

	users, err := h.manager.ListUsers(r.Context(), orgID)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"users": users,
		"count": len(users),
	})
}

// GetUser handles GET /api/v1/identities/users/{id}.
func (h *IdentityHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "user id is required")
		return
	}

	user, err := h.manager.GetUser(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, user)
}

// DeleteUser handles DELETE /api/v1/identities/users/{id}.
func (h *IdentityHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "user id is required")
		return
	}

	if err := h.manager.DeleteUser(r.Context(), id); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Service Handlers
// =============================================================================

// CreateService handles POST /api/v1/identities/services.
func (h *IdentityHandler) CreateService(w http.ResponseWriter, r *http.Request) {
	var req CreateServiceRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.Name == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "name is required")
		return
	}

	orgID := getOrgID(r)
	service, err := h.manager.CreateService(r.Context(), orgID, req.Name, req.Description, req.AuthMethod)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, service)
}

// ListServices handles GET /api/v1/identities/services.
func (h *IdentityHandler) ListServices(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r)

	services, err := h.manager.ListServices(r.Context(), orgID)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"services": services,
		"count":    len(services),
	})
}

// GetService handles GET /api/v1/identities/services/{id}.
func (h *IdentityHandler) GetService(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "service id is required")
		return
	}

	service, err := h.manager.GetService(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, service)
}

// DeleteService handles DELETE /api/v1/identities/services/{id}.
func (h *IdentityHandler) DeleteService(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "service id is required")
		return
	}

	if err := h.manager.DeleteService(r.Context(), id); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Device Handlers
// =============================================================================

// EnrollDevice handles POST /api/v1/identities/devices.
func (h *IdentityHandler) EnrollDevice(w http.ResponseWriter, r *http.Request) {
	var req EnrollDeviceRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.DeviceName == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "device_name is required")
		return
	}
	if req.CertSerial == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "cert_serial is required")
		return
	}

	orgID := getOrgID(r)
	device, err := h.manager.EnrollDevice(r.Context(), orgID, req.DeviceName, req.DeviceType, req.CertSerial, req.CertExpiry)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, device)
}

// ListDevices handles GET /api/v1/identities/devices.
func (h *IdentityHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r)

	devices, err := h.manager.ListDevices(r.Context(), orgID)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"devices": devices,
		"count":   len(devices),
	})
}

// GetDevice handles GET /api/v1/identities/devices/{id}.
func (h *IdentityHandler) GetDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "device id is required")
		return
	}

	device, err := h.manager.GetDevice(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, device)
}

// RevokeDevice handles POST /api/v1/identities/devices/{id}/revoke.
func (h *IdentityHandler) RevokeDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "device id is required")
		return
	}

	if err := h.manager.RevokeDevice(r.Context(), id); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Group Handlers
// =============================================================================

// CreateGroup handles POST /api/v1/identities/groups.
func (h *IdentityHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	var req CreateGroupRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.Name == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "name is required")
		return
	}

	orgID := getOrgID(r)
	group, err := h.manager.CreateGroup(r.Context(), orgID, req.Name, req.Description, req.VaultPolicies, req.IDPGroupID)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, group)
}

// UpdateGroup handles PUT /api/v1/identities/groups/{id}.
func (h *IdentityHandler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")
	if groupID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "group id is required")
		return
	}

	var req UpdateGroupRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	group, err := h.manager.UpdateGroup(r.Context(), groupID, req.Name, req.Description, req.VaultPolicies, req.IDPGroupID)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, group)
}

// ListGroups handles GET /api/v1/identities/groups.
func (h *IdentityHandler) ListGroups(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r)

	groups, err := h.manager.ListGroups(r.Context(), orgID)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"groups": groups,
		"count":  len(groups),
	})
}

// GetGroup handles GET /api/v1/identities/groups/{id}.
func (h *IdentityHandler) GetGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "group id is required")
		return
	}

	group, err := h.manager.GetGroup(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, group)
}

// AddGroupMember handles POST /api/v1/identities/groups/{id}/members.
func (h *IdentityHandler) AddGroupMember(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "group id is required")
		return
	}

	var req AddGroupMemberRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.IdentityID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "identity_id is required")
		return
	}
	if req.IdentityType == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "identity_type is required")
		return
	}

	if err := h.manager.AddToGroup(r.Context(), id, req.IdentityID, req.IdentityType); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RemoveGroupMember handles DELETE /api/v1/identities/groups/{id}/members/{identityId}.
func (h *IdentityHandler) RemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "group id is required")
		return
	}

	identityID := chi.URLParam(r, "identityId")
	if identityID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "identity id is required")
		return
	}

	if err := h.manager.RemoveFromGroup(r.Context(), id, identityID); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Group Join Request Handlers
// =============================================================================

// RequestGroupJoinRequest represents a request to join a group.
type RequestGroupJoinRequest struct {
	Justification string `json:"justification,omitempty"`
}

// RequestGroupJoin handles POST /api/v1/identities/groups/{id}/join-requests.
func (h *IdentityHandler) RequestGroupJoin(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")
	if groupID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "group id is required")
		return
	}

	var req RequestGroupJoinRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	callerAdminID, _ := r.Context().Value(ContextKeyAdminID).(string)
	orgID := getOrgID(r)

	joinReq, err := h.manager.RequestGroupJoin(r.Context(), groupID, callerAdminID, orgID, req.Justification)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, joinReq)
}

// ListGroupJoinRequests handles GET /api/v1/identities/groups/{id}/join-requests.
func (h *IdentityHandler) ListGroupJoinRequests(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")
	if groupID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "group id is required")
		return
	}

	requests, err := h.manager.ListPendingJoinRequests(r.Context(), groupID)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"requests": requests,
		"count":    len(requests),
	})
}

// ApproveJoinRequest handles POST /api/v1/identities/groups/{id}/join-requests/{requestId}/approve.
func (h *IdentityHandler) ApproveJoinRequest(w http.ResponseWriter, r *http.Request) {
	requestID := chi.URLParam(r, "requestId")
	if requestID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "request id is required")
		return
	}

	reviewerID, _ := r.Context().Value(ContextKeyAdminID).(string)

	if err := h.manager.ApproveJoinRequest(r.Context(), requestID, reviewerID); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// DenyJoinRequest handles POST /api/v1/identities/groups/{id}/join-requests/{requestId}/deny.
func (h *IdentityHandler) DenyJoinRequest(w http.ResponseWriter, r *http.Request) {
	requestID := chi.URLParam(r, "requestId")
	if requestID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "request id is required")
		return
	}

	reviewerID, _ := r.Context().Value(ContextKeyAdminID).(string)

	if err := h.manager.DenyJoinRequest(r.Context(), requestID, reviewerID); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Workspace Access Request Handler
// =============================================================================

// WorkspaceAccessRequestHandler handles workspace access requests.
type WorkspaceAccessRequestHandler struct {
	identityManager *identity.Manager
	bindingRepo     workspace.GroupBindingRepository
}

// NewWorkspaceAccessRequestHandler creates a new workspace access request handler.
func NewWorkspaceAccessRequestHandler(im *identity.Manager, bindingRepo workspace.GroupBindingRepository) *WorkspaceAccessRequestHandler {
	return &WorkspaceAccessRequestHandler{identityManager: im, bindingRepo: bindingRepo}
}

// RequestWorkspaceAccessRequest represents a request to access a workspace.
type RequestWorkspaceAccessRequest struct {
	Justification string `json:"justification,omitempty"`
}

// RequestAccess handles POST /api/v1/workspaces/{id}/request-access.
// Convenience endpoint: resolves the workspace's bound group and creates a join request.
func (h *WorkspaceAccessRequestHandler) RequestAccess(w http.ResponseWriter, r *http.Request) {
	wsID := chi.URLParam(r, "id")
	if wsID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace id is required")
		return
	}

	var req RequestWorkspaceAccessRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	callerAdminID, _ := r.Context().Value(ContextKeyAdminID).(string)
	orgID := getOrgID(r)

	// Look up the workspace-group binding for the caller's org
	binding, err := h.bindingRepo.GetBinding(r.Context(), wsID, orgID)
	if err != nil {
		handleError(w, err)
		return
	}
	if binding == nil {
		writeJSONError(w, http.StatusBadRequest, "NO_BOUND_GROUP", "workspace has no bound identity group for this organization")
		return
	}

	joinReq, err := h.identityManager.RequestGroupJoin(r.Context(), binding.GroupID, callerAdminID, orgID, req.Justification)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, joinReq)
}

// =============================================================================
// Role Handlers
// =============================================================================

// CreateRole handles POST /api/v1/identities/roles.
func (h *IdentityHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	var req CreateRoleRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.Name == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "name is required")
		return
	}

	orgID := getOrgID(r)
	role, err := h.manager.CreateRole(r.Context(), orgID, req.Name, req.Description, req.Permissions)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, role)
}

// ListRoles handles GET /api/v1/identities/roles.
func (h *IdentityHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r)

	roles, err := h.manager.ListRoles(r.Context(), orgID)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"roles": roles,
		"count": len(roles),
	})
}

// GetRole handles GET /api/v1/identities/roles/{id}.
func (h *IdentityHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "role id is required")
		return
	}

	role, err := h.manager.GetRole(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, role)
}

// AssignRole handles POST /api/v1/identities/roles/{id}/assign.
func (h *IdentityHandler) AssignRole(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "role id is required")
		return
	}

	var req AssignRoleRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.IdentityID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "identity_id is required")
		return
	}
	if req.IdentityType == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "identity_type is required")
		return
	}
	if req.AssignedBy == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "assigned_by is required")
		return
	}

	if err := h.manager.AssignRole(r.Context(), id, req.IdentityID, req.IdentityType, req.AssignedBy); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// UnassignRole handles DELETE /api/v1/identities/roles/{id}/assignments/{identityId}.
func (h *IdentityHandler) UnassignRole(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "role id is required")
		return
	}

	identityID := chi.URLParam(r, "identityId")
	if identityID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "identity id is required")
		return
	}

	if err := h.manager.UnassignRole(r.Context(), id, identityID); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RotateServiceCredentials handles POST /api/v1/identities/services/{id}/rotate.
func (h *IdentityHandler) RotateServiceCredentials(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "service id is required")
		return
	}

	svc, err := h.manager.RotateServiceCredentials(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, svc)
}

// =============================================================================
// Workspace Export/Import Handlers
// =============================================================================

// ExportWorkspaceRequest represents an export request.
type ExportWorkspaceRequest struct {
	Signature []byte `json:"signature"`
}

// Export handles POST /api/v1/workspaces/{id}/export.
func (h *WorkspaceHandler) Export(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace id is required")
		return
	}

	var req ExportWorkspaceRequest
	// Export may be called without a body for non-CRK workspaces
	_ = readJSON(r, &req)

	bundle, err := h.service.ExportWorkspace(r.Context(), id, req.Signature)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, bundle)
}

// ImportWorkspaceRequest wraps a workspace bundle with an optional CRK signature.
type ImportWorkspaceRequest struct {
	workspace.WorkspaceBundle
	Signature []byte `json:"signature"`
}

// Import handles POST /api/v1/workspaces/import.
func (h *WorkspaceHandler) Import(w http.ResponseWriter, r *http.Request) {
	var req ImportWorkspaceRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	ws, err := h.service.ImportWorkspace(r.Context(), &req.WorkspaceBundle, req.Signature)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, ws)
}

// =============================================================================
// Certificate Handler
// =============================================================================

// CertificateHandler handles certificate management API requests.
type CertificateHandler struct {
	pki *vault.PKIClient
}

// NewCertificateHandler creates a new certificate handler.
func NewCertificateHandler(pki *vault.PKIClient) *CertificateHandler {
	return &CertificateHandler{pki: pki}
}

// IssueCertificateRequest represents a certificate issuance request.
type IssueCertificateRequest struct {
	CommonName string   `json:"common_name"`
	AltNames   []string `json:"alt_names,omitempty"`
	TTL        string   `json:"ttl,omitempty"`
}

// Issue handles POST /api/v1/certificates/issue.
func (h *CertificateHandler) Issue(w http.ResponseWriter, r *http.Request) {
	role := r.URL.Query().Get("role")
	if role == "" {
		role = "default"
	}

	var req IssueCertificateRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.CommonName == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "common_name is required")
		return
	}

	certReq := &vault.CertificateRequest{
		CommonName: req.CommonName,
		AltNames:   req.AltNames,
	}
	if req.TTL != "" {
		if d, err := time.ParseDuration(req.TTL); err == nil {
			certReq.TTL = d
		}
	}

	cert, err := h.pki.IssueCertificate(r.Context(), role, certReq)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, cert)
}

// RevokeCertificateRequest represents a certificate revocation request.
type RevokeCertificateRequest struct {
	SerialNumber string `json:"serial_number"`
}

// Revoke handles POST /api/v1/certificates/revoke.
func (h *CertificateHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	var req RevokeCertificateRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.SerialNumber == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "serial_number is required")
		return
	}

	if err := h.pki.RevokeCertificate(r.Context(), req.SerialNumber); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Read handles GET /api/v1/certificates/{serial}.
func (h *CertificateHandler) Read(w http.ResponseWriter, r *http.Request) {
	serial := chi.URLParam(r, "serial")
	if serial == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "serial is required")
		return
	}

	cert, err := h.pki.ReadCertificate(r.Context(), serial)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, cert)
}

// List handles GET /api/v1/certificates.
func (h *CertificateHandler) List(w http.ResponseWriter, r *http.Request) {
	serials, err := h.pki.ListCertificates(r.Context())
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"certificates": serials,
		"count":        len(serials),
	})
}

// GetCAChain handles GET /api/v1/certificates/ca-chain.
func (h *CertificateHandler) GetCAChain(w http.ResponseWriter, r *http.Request) {
	chain, err := h.pki.GetCAChain(r.Context())
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ca_chain": chain,
	})
}

// TidyCertificatesRequest represents a tidy certificates request.
type TidyCertificatesRequest struct {
	SafetyBuffer string `json:"safety_buffer,omitempty"`
}

// Tidy handles POST /api/v1/certificates/tidy.
func (h *CertificateHandler) Tidy(w http.ResponseWriter, r *http.Request) {
	var req TidyCertificatesRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	var safetyBuffer time.Duration
	if req.SafetyBuffer != "" {
		if d, err := time.ParseDuration(req.SafetyBuffer); err == nil {
			safetyBuffer = d
		}
	}

	if err := h.pki.TidyCertificates(r.Context(), true, true, safetyBuffer); err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "tidy operation started",
	})
}

// =============================================================================
// Emergency Access Handler
// =============================================================================

// EmergencyAccessHandler handles emergency access API requests.
type EmergencyAccessHandler struct {
	mgr *identity.EmergencyAccessManager
}

// NewEmergencyAccessHandler creates a new emergency access handler.
func NewEmergencyAccessHandler(mgr *identity.EmergencyAccessManager) *EmergencyAccessHandler {
	return &EmergencyAccessHandler{mgr: mgr}
}

// EmergencyAccessRequestPayload represents an emergency access request payload.
type EmergencyAccessRequestPayload struct {
	OrgID  string `json:"org_id"`
	Reason string `json:"reason"`
}

// Request handles POST /api/v1/emergency-access/request.
func (h *EmergencyAccessHandler) Request(w http.ResponseWriter, r *http.Request) {
	var req EmergencyAccessRequestPayload
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	orgID := req.OrgID
	if orgID == "" {
		orgID = getOrgID(r)
	}

	if req.Reason == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "reason is required")
		return
	}

	result, err := h.mgr.RequestEmergencyAccess(r.Context(), orgID, getOrgID(r), req.Reason)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, result)
}

// Approve handles POST /api/v1/emergency-access/{id}/approve.
func (h *EmergencyAccessHandler) Approve(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "request id is required")
		return
	}

	approverID := getOrgID(r)
	if err := h.mgr.ApproveEmergencyAccess(r.Context(), id, approverID); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Deny handles POST /api/v1/emergency-access/{id}/deny.
func (h *EmergencyAccessHandler) Deny(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "request id is required")
		return
	}

	deniedBy := getOrgID(r)
	if err := h.mgr.DenyEmergencyAccess(r.Context(), id, deniedBy); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Complete handles POST /api/v1/emergency-access/{id}/complete.
func (h *EmergencyAccessHandler) Complete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "request id is required")
		return
	}

	if err := h.mgr.CompleteEmergencyAccess(r.Context(), id); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// VerifyEmergencyAccessRequest represents a CRK verification request for emergency access.
type VerifyEmergencyAccessRequest struct {
	Signature []byte `json:"signature"`
}

// Verify handles POST /api/v1/emergency-access/{id}/verify.
func (h *EmergencyAccessHandler) Verify(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "request id is required")
		return
	}

	var req VerifyEmergencyAccessRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if len(req.Signature) == 0 {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "signature is required")
		return
	}

	if err := h.mgr.VerifyEmergencyAccessWithCRK(r.Context(), id, req.Signature); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListEmergencyAccess handles GET /api/v1/emergency-access.
func (h *EmergencyAccessHandler) ListEmergencyAccess(w http.ResponseWriter, r *http.Request) {
	orgID := r.URL.Query().Get("org_id")
	if orgID == "" {
		orgID = getOrgID(r)
	}

	requests, err := h.mgr.ListRequests(r.Context(), orgID)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"requests": requests,
		"count":    len(requests),
	})
}

// GetEmergencyAccess handles GET /api/v1/emergency-access/{id}.
func (h *EmergencyAccessHandler) GetEmergencyAccess(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "request id is required")
		return
	}

	req, err := h.mgr.GetRequest(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, req)
}

// =============================================================================
// Account Recovery Handler
// =============================================================================

// AccountRecoveryHandler handles account recovery API requests.
type AccountRecoveryHandler struct {
	mgr *identity.AccountRecoveryManager
}

// NewAccountRecoveryHandler creates a new account recovery handler.
func NewAccountRecoveryHandler(mgr *identity.AccountRecoveryManager) *AccountRecoveryHandler {
	return &AccountRecoveryHandler{mgr: mgr}
}

// InitiateRecoveryRequest represents an account recovery initiation request.
type InitiateRecoveryRequest struct {
	AdminID      string `json:"admin_id"`
	RecoveryType string `json:"recovery_type"`
	Reason       string `json:"reason"`
}

// Initiate handles POST /api/v1/account-recovery/initiate.
func (h *AccountRecoveryHandler) Initiate(w http.ResponseWriter, r *http.Request) {
	var req InitiateRecoveryRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	orgID := getOrgID(r)
	recovery, err := h.mgr.InitiateRecovery(r.Context(), orgID, req.AdminID, req.RecoveryType, req.Reason)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, recovery)
}

// CollectShare handles POST /api/v1/account-recovery/{id}/share.
func (h *AccountRecoveryHandler) CollectShare(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "recovery id is required")
		return
	}

	if err := h.mgr.CollectShare(r.Context(), id); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// CompleteRecovery handles POST /api/v1/account-recovery/{id}/complete.
func (h *AccountRecoveryHandler) CompleteRecovery(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "recovery id is required")
		return
	}

	if err := h.mgr.CompleteRecovery(r.Context(), id); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Compliance Handler
// =============================================================================

// ComplianceHandler handles compliance report API requests.
type ComplianceHandler struct {
	gen *compliance.ReportGenerator
}

// NewComplianceHandler creates a new compliance handler.
func NewComplianceHandler(gen *compliance.ReportGenerator) *ComplianceHandler {
	return &ComplianceHandler{gen: gen}
}

// ComplianceReportRequest represents a compliance report generation request.
type ComplianceReportRequest struct {
	OrgID string `json:"org_id,omitempty"`
	Since string `json:"since,omitempty"`
	Until string `json:"until,omitempty"`
}

// GenerateSummary handles POST /api/v1/compliance/reports/summary.
func (h *ComplianceHandler) GenerateSummary(w http.ResponseWriter, r *http.Request) {
	var req ComplianceReportRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	orgID := req.OrgID
	if orgID == "" {
		orgID = getOrgID(r)
	}

	period := parsePeriod(req.Since, req.Until)
	report, err := h.gen.GenerateSummary(r.Context(), orgID, period)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, report)
}

// DSARRequest represents a GDPR DSAR request.
type DSARRequest struct {
	OrgID     string `json:"org_id,omitempty"`
	SubjectID string `json:"subject_id"`
}

// GenerateDSAR handles POST /api/v1/compliance/reports/gdpr-dsar.
func (h *ComplianceHandler) GenerateDSAR(w http.ResponseWriter, r *http.Request) {
	var req DSARRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.SubjectID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "subject_id is required")
		return
	}

	orgID := req.OrgID
	if orgID == "" {
		orgID = getOrgID(r)
	}

	report, err := h.gen.GenerateGDPRDSAR(r.Context(), orgID, req.SubjectID)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, report)
}

// GenerateAccessReview handles POST /api/v1/compliance/reports/access-review.
func (h *ComplianceHandler) GenerateAccessReview(w http.ResponseWriter, r *http.Request) {
	var req ComplianceReportRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	orgID := req.OrgID
	if orgID == "" {
		orgID = getOrgID(r)
	}

	period := parsePeriod(req.Since, req.Until)
	report, err := h.gen.GenerateAccessReview(r.Context(), orgID, period)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, report)
}

func parsePeriod(since, until string) compliance.ReportPeriod {
	var period compliance.ReportPeriod
	if since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			period.Since = t
		}
	}
	if until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			period.Until = t
		}
	}
	if period.Since.IsZero() {
		period.Since = time.Now().Add(-30 * 24 * time.Hour)
	}
	if period.Until.IsZero() {
		period.Until = time.Now()
	}
	return period
}

// =============================================================================
// Rotation Policy Handler
// =============================================================================

// RotationPolicyHandler handles rotation policy API requests.
type RotationPolicyHandler struct {
	sched *rotation.Scheduler
}

// NewRotationPolicyHandler creates a new rotation policy handler.
func NewRotationPolicyHandler(sched *rotation.Scheduler) *RotationPolicyHandler {
	return &RotationPolicyHandler{sched: sched}
}

// SetRotationPolicyRequest represents a rotation policy set request.
type SetRotationPolicyRequest struct {
	MaxAge  string `json:"max_age"`
	Enabled bool   `json:"enabled"`
}

// Set handles PUT /api/v1/workspaces/{id}/rotation-policy.
func (h *RotationPolicyHandler) Set(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace id is required")
		return
	}

	var req SetRotationPolicyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	maxAge, err := time.ParseDuration(req.MaxAge)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid max_age duration")
		return
	}

	policy := &rotation.Policy{
		WorkspaceID: id,
		MaxAge:      maxAge,
		Enabled:     req.Enabled,
	}

	h.sched.SetPolicy(id, policy)
	writeJSON(w, http.StatusOK, policy)
}

// Get handles GET /api/v1/workspaces/{id}/rotation-policy.
func (h *RotationPolicyHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace id is required")
		return
	}

	policy := h.sched.GetPolicy(id)
	if policy == nil {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "no rotation policy for workspace")
		return
	}

	writeJSON(w, http.StatusOK, policy)
}

// Delete handles DELETE /api/v1/workspaces/{id}/rotation-policy.
func (h *RotationPolicyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace id is required")
		return
	}

	h.sched.RemovePolicy(id)
	w.WriteHeader(http.StatusNoContent)
}

// ListPolicies handles GET /api/v1/rotation-policies.
func (h *RotationPolicyHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	policies := h.sched.ListPolicies()
	writeJSON(w, http.StatusOK, map[string]any{
		"policies": policies,
		"count":    len(policies),
	})
}

// =============================================================================
// Backup Handler
// =============================================================================

// BackupHandler handles backup API requests.
type BackupHandler struct {
	service backup.Service
}

// NewBackupHandler creates a new backup handler.
func NewBackupHandler(service backup.Service) *BackupHandler {
	return &BackupHandler{service: service}
}

// CreateBackupRequest represents a backup creation request.
type CreateBackupRequest struct {
	Type         string `json:"type"`
	CRKSignature []byte `json:"crk_signature"`
}

// Create handles POST /api/v1/backups.
func (h *BackupHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateBackupRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.Type == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "type is required")
		return
	}

	if len(req.CRKSignature) == 0 {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "crk_signature is required for backup operations")
		return
	}

	orgID := getOrgID(r)
	b, err := h.service.Create(r.Context(), orgID, req.Type, "api", req.CRKSignature)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, b)
}

// List handles GET /api/v1/backups.
func (h *BackupHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r)
	backups, err := h.service.List(r.Context(), orgID)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"backups": backups,
		"count":   len(backups),
	})
}

// Get handles GET /api/v1/backups/{id}.
func (h *BackupHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "backup id is required")
		return
	}

	b, err := h.service.Get(r.Context(), id)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, b)
}

// RestoreBackupRequest represents a restore request.
type RestoreBackupRequest struct {
	CRKSignature []byte `json:"crk_signature"`
}

// Restore handles POST /api/v1/backups/{id}/restore.
func (h *BackupHandler) Restore(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "backup id is required")
		return
	}

	var req RestoreBackupRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if len(req.CRKSignature) == 0 {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "crk_signature is required for restore operations")
		return
	}

	if err := h.service.Restore(r.Context(), id, getOrgID(r), req.CRKSignature); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Activity Handler
// =============================================================================

// ActivityHandler handles user activity API requests.
type ActivityHandler struct {
	auditSvc audit.Service
}

// NewActivityHandler creates a new activity handler.
func NewActivityHandler(auditSvc audit.Service) *ActivityHandler {
	return &ActivityHandler{auditSvc: auditSvc}
}

// List handles GET /api/v1/activity — returns caller's own activity.
func (h *ActivityHandler) List(w http.ResponseWriter, r *http.Request) {
	// Auto-fill actor from context (set by auth middleware)
	actor := ""
	if a, ok := r.Context().Value(ContextKeyAdminID).(string); ok && a != "" {
		actor = a
	}
	if actor == "" {
		actor = r.URL.Query().Get("actor")
	}
	if actor == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "could not determine caller identity")
		return
	}

	limit, offset := getPaginationParams(r)

	var since, until time.Time
	if s := r.URL.Query().Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}
	if u := r.URL.Query().Get("until"); u != "" {
		if t, err := time.Parse(time.RFC3339, u); err == nil {
			until = t
		}
	}

	events, err := h.auditSvc.Query(r.Context(), audit.QueryParams{
		Actor:  actor,
		Since:  since,
		Until:  until,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"count":  len(events),
		"actor":  actor,
	})
}

// Export handles POST /api/v1/activity/export — exports caller's activity.
func (h *ActivityHandler) Export(w http.ResponseWriter, r *http.Request) {
	actor := ""
	if a, ok := r.Context().Value(ContextKeyAdminID).(string); ok && a != "" {
		actor = a
	}
	if actor == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "could not determine caller identity")
		return
	}

	var req ExportAuditRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	var since, until time.Time
	if req.Since != "" {
		if t, err := time.Parse(time.RFC3339, req.Since); err == nil {
			since = t
		}
	}
	if req.Until != "" {
		if t, err := time.Parse(time.RFC3339, req.Until); err == nil {
			until = t
		}
	}

	format := req.Format
	if format == "" {
		format = audit.ExportFormatJSON
	}

	data, err := h.auditSvc.Export(r.Context(), audit.ExportRequest{
		Query: audit.QueryParams{
			Actor: actor,
			Since: since,
			Until: until,
		},
		Format: format,
	})
	if err != nil {
		handleError(w, err)
		return
	}

	contentType := "application/json"
	if format == audit.ExportFormatCSV {
		contentType = "text/csv"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename=activity-export."+string(format))
	_, _ = w.Write(data) //nolint:gosec // G705: export data is server-generated audit content, not user-tainted
}

// =============================================================================
// Direct Message Handler
// =============================================================================

// DirectMessageHandler handles direct messaging endpoints.
type DirectMessageHandler struct {
	service messaging.Service
}

// NewDirectMessageHandler creates a new DirectMessageHandler.
func NewDirectMessageHandler(service messaging.Service) *DirectMessageHandler {
	return &DirectMessageHandler{service: service}
}

// Send handles POST /api/v1/messages.
func (h *DirectMessageHandler) Send(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RecipientOrgID string `json:"recipient_org_id"`
		RecipientID    string `json:"recipient_id"`
		Subject        string `json:"subject"`
		Body           []byte `json:"body"`
		ConversationID string `json:"conversation_id,omitempty"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
		return
	}

	orgID := getOrgID(r)
	callerID := getCallerID(r)
	if orgID == "" || callerID == "" {
		writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}

	msg, err := h.service.Send(r.Context(), messaging.SendRequest{
		SenderOrgID:    orgID,
		SenderID:       callerID,
		RecipientOrgID: req.RecipientOrgID,
		RecipientID:    req.RecipientID,
		Subject:        req.Subject,
		Body:           req.Body,
		ConversationID: req.ConversationID,
	})
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, msg)
}

// ListInbox handles GET /api/v1/messages.
func (h *DirectMessageHandler) ListInbox(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r)
	callerID := getCallerID(r)
	if orgID == "" || callerID == "" {
		writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}

	limit, offset := getPaginationParams(r)
	msgs, err := h.service.ListInbox(r.Context(), orgID, callerID, limit, offset)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"messages": msgs,
		"count":    len(msgs),
	})
}

// ListSent handles GET /api/v1/messages/sent.
func (h *DirectMessageHandler) ListSent(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r)
	callerID := getCallerID(r)
	if orgID == "" || callerID == "" {
		writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}

	limit, offset := getPaginationParams(r)
	msgs, err := h.service.ListSent(r.Context(), orgID, callerID, limit, offset)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"messages": msgs,
		"count":    len(msgs),
	})
}

// Read handles GET /api/v1/messages/{id}.
func (h *DirectMessageHandler) Read(w http.ResponseWriter, r *http.Request) {
	msgID := chi.URLParam(r, "id")
	orgID := getOrgID(r)
	callerID := getCallerID(r)
	if orgID == "" || callerID == "" {
		writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}

	msg, err := h.service.Read(r.Context(), orgID, callerID, msgID)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, msg)
}

// Delete handles DELETE /api/v1/messages/{id}.
func (h *DirectMessageHandler) Delete(w http.ResponseWriter, r *http.Request) {
	msgID := chi.URLParam(r, "id")
	orgID := getOrgID(r)
	callerID := getCallerID(r)
	if orgID == "" || callerID == "" {
		writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}

	if err := h.service.Delete(r.Context(), orgID, callerID, msgID); err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// Deliver handles POST /api/v1/messages/deliver (federation inbound).
func (h *DirectMessageHandler) Deliver(w http.ResponseWriter, r *http.Request) {
	// Verify federation certificate is present
	if r.Context().Value(ContextKeyCert) == nil {
		writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "federation certificate required")
		return
	}

	var req messaging.DeliverRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
		return
	}

	msgID, err := h.service.Deliver(r.Context(), req)
	if err != nil {
		handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"message_id": msgID})
}

// getCallerID extracts the caller's identity from context (admin or user).
func getCallerID(r *http.Request) string {
	if adminID, ok := r.Context().Value(ContextKeyAdminID).(string); ok && adminID != "" {
		return adminID
	}
	if userID, ok := r.Context().Value(ContextKeyUserID).(string); ok && userID != "" {
		return userID
	}
	return ""
}
