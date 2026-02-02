// Package api handles API gateway functionality.
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/sovra-project/sovra/internal/audit"
	"github.com/sovra-project/sovra/internal/crk"
	"github.com/sovra-project/sovra/internal/edge"
	"github.com/sovra-project/sovra/internal/federation"
	"github.com/sovra-project/sovra/internal/policy"
	"github.com/sovra-project/sovra/internal/workspace"
	apierrors "github.com/sovra-project/sovra/pkg/errors"
	"github.com/sovra-project/sovra/pkg/models"
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
		return err
	}
	defer func() { _ = r.Body.Close() }()
	return json.Unmarshal(body, v)
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
	Participants   []string              `json:"participants"`
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
	Purpose   string `json:"purpose,omitempty"`
	Signature []byte `json:"signature"`
}

// Update handles PUT /api/v1/workspaces/{id}.
func (h *WorkspaceHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace id is required")
		return
	}

	// For now, update is handled via archive - workspace updates are limited
	writeJSONError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "workspace update not implemented")
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
	Plaintext []byte `json:"plaintext"`
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
	Ciphertext []byte `json:"ciphertext"`
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

// AddParticipantRequest represents request to add a participant.
type AddParticipantRequest struct {
	OrgID     string `json:"org_id"`
	Signature []byte `json:"signature"`
}

// AddParticipant handles POST /api/v1/workspaces/{id}/participants.
func (h *WorkspaceHandler) AddParticipant(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace id is required")
		return
	}

	var req AddParticipantRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.OrgID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "org_id is required")
		return
	}

	if err := h.service.AddParticipant(r.Context(), id, req.OrgID, req.Signature); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RemoveParticipant handles DELETE /api/v1/workspaces/{id}/participants/{orgId}.
func (h *WorkspaceHandler) RemoveParticipant(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	orgID := chi.URLParam(r, "orgId")
	if id == "" || orgID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "workspace id and org id are required")
		return
	}

	var req struct {
		Signature []byte `json:"signature"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if err := h.service.RemoveParticipant(r.Context(), id, orgID, req.Signature); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
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
