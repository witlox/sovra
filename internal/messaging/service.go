// Package messaging implements store-and-forward direct messaging between federated users.
package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/witlox/sovra/pkg/errors"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/pkg/vault"
)

const (
	maxSubjectLength = 256
	maxBodySize      = 64 * 1024 // 64 KB
)

// Repository defines message persistence operations.
type Repository interface {
	Create(ctx context.Context, msg *models.DirectMessage) error
	Get(ctx context.Context, id string) (*models.DirectMessage, error)
	ListInbox(ctx context.Context, orgID, recipientID string, limit, offset int) ([]*models.DirectMessage, error)
	ListSent(ctx context.Context, orgID, senderID string, limit, offset int) ([]*models.DirectMessage, error)
	ListByConversation(ctx context.Context, conversationID string, limit, offset int) ([]*models.DirectMessage, error)
	MarkDelivered(ctx context.Context, id string) error
	MarkRead(ctx context.Context, id string) error
	MarkFailed(ctx context.Context, id, errorDetail string) error
	Delete(ctx context.Context, id string) error
}

// FederationRelay abstracts federation message relay.
type FederationRelay interface {
	RelayMessage(ctx context.Context, partnerOrgID string, payload []byte) ([]byte, error)
	IsFederationActive(ctx context.Context, partnerOrgID string) (bool, error)
}

// Encryptor handles encryption/decryption of message bodies via Vault transit.
type Encryptor interface {
	Encrypt(ctx context.Context, orgID string, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, orgID string, ciphertext []byte) ([]byte, error)
}

// IdentityResolver checks whether a user identity exists.
type IdentityResolver interface {
	IdentityExists(ctx context.Context, identityID string) (bool, error)
}

// AuditService logs audit events.
type AuditService interface {
	Log(ctx context.Context, event *models.AuditEvent) error
}

// Service is the messaging service interface.
type Service interface {
	Send(ctx context.Context, req SendRequest) (*models.DirectMessage, error)
	Deliver(ctx context.Context, req DeliverRequest) (string, error)
	Read(ctx context.Context, callerOrgID, callerID, messageID string) (*models.DirectMessage, error)
	ListInbox(ctx context.Context, orgID, userID string, limit, offset int) ([]*models.DirectMessage, error)
	ListSent(ctx context.Context, orgID, userID string, limit, offset int) ([]*models.DirectMessage, error)
	Delete(ctx context.Context, callerOrgID, callerID, messageID string) error
}

// SendRequest represents a message send request.
type SendRequest struct {
	SenderOrgID    string
	SenderID       string
	RecipientOrgID string
	RecipientID    string
	Subject        string
	Body           []byte
	ConversationID string // optional; auto-generated if empty
}

// DeliverRequest represents an inbound message from a federation partner.
type DeliverRequest struct {
	SenderOrgID    string `json:"sender_org_id"`
	SenderID       string `json:"sender_id"`
	RecipientOrgID string `json:"recipient_org_id"`
	RecipientID    string `json:"recipient_id"`
	Subject        string `json:"subject"`
	Body           []byte `json:"body"`
	ConversationID string `json:"conversation_id"`
}

// serviceImpl implements Service.
type serviceImpl struct {
	repo       Repository
	federation FederationRelay
	encryptor  Encryptor
	resolver   IdentityResolver
	audit      AuditService
}

// NewService creates a new messaging service.
func NewService(repo Repository, federation FederationRelay, encryptor Encryptor, resolver IdentityResolver, audit AuditService) Service {
	return &serviceImpl{
		repo:       repo,
		federation: federation,
		encryptor:  encryptor,
		resolver:   resolver,
		audit:      audit,
	}
}

// Send sends a direct message. Cross-org messages are relayed via federation; same-org messages are stored locally.
func (s *serviceImpl) Send(ctx context.Context, req SendRequest) (*models.DirectMessage, error) {
	if len(req.Subject) > maxSubjectLength {
		return nil, fmt.Errorf("subject exceeds %d characters: %w", maxSubjectLength, errors.ErrInvalidInput)
	}
	if len(req.Body) > maxBodySize {
		return nil, fmt.Errorf("body exceeds %d bytes: %w", maxBodySize, errors.ErrInvalidInput)
	}
	if req.Subject == "" {
		return nil, fmt.Errorf("subject is required: %w", errors.ErrInvalidInput)
	}
	if len(req.Body) == 0 {
		return nil, fmt.Errorf("body is required: %w", errors.ErrInvalidInput)
	}

	conversationID := req.ConversationID
	if conversationID == "" {
		conversationID = uuid.New().String()
	}

	now := time.Now()
	sameOrg := req.SenderOrgID == req.RecipientOrgID

	if !sameOrg {
		// Cross-org: check federation is active
		active, err := s.federation.IsFederationActive(ctx, req.RecipientOrgID)
		if err != nil {
			return nil, fmt.Errorf("check federation: %w", err)
		}
		if !active {
			return nil, fmt.Errorf("no active federation with org %s: %w", req.RecipientOrgID, errors.ErrFederationNotEstablished)
		}
	}

	// Encrypt body and store sender copy
	encBody, err := s.encryptor.Encrypt(ctx, req.SenderOrgID, req.Body)
	if err != nil {
		return nil, fmt.Errorf("encrypt message body: %w", err)
	}

	senderMsg := &models.DirectMessage{
		ID:             uuid.New().String(),
		ConversationID: conversationID,
		SenderOrgID:    req.SenderOrgID,
		SenderID:       req.SenderID,
		RecipientOrgID: req.RecipientOrgID,
		RecipientID:    req.RecipientID,
		Subject:        req.Subject,
		Body:           encBody,
		Status:         models.DirectMessageStatusPending,
		Direction:      "sent",
		CreatedAt:      now,
	}

	if err := s.repo.Create(ctx, senderMsg); err != nil {
		return nil, fmt.Errorf("store sender message: %w", err)
	}

	if sameOrg {
		// Same-org: store recipient copy directly
		recvBody, err := s.encryptor.Encrypt(ctx, req.RecipientOrgID, req.Body)
		if err != nil {
			return nil, fmt.Errorf("encrypt recipient body: %w", err)
		}

		recvMsg := &models.DirectMessage{
			ID:             uuid.New().String(),
			ConversationID: conversationID,
			SenderOrgID:    req.SenderOrgID,
			SenderID:       req.SenderID,
			RecipientOrgID: req.RecipientOrgID,
			RecipientID:    req.RecipientID,
			Subject:        req.Subject,
			Body:           recvBody,
			Status:         models.DirectMessageStatusDelivered,
			Direction:      "received",
			CreatedAt:      now,
			DeliveredAt:    &now,
		}

		if err := s.repo.Create(ctx, recvMsg); err != nil {
			return nil, fmt.Errorf("store recipient message: %w", err)
		}

		_ = s.repo.MarkDelivered(ctx, senderMsg.ID)
		senderMsg.Status = models.DirectMessageStatusDelivered
	} else {
		// Cross-org: relay plaintext to partner via federation mTLS
		payload, err := json.Marshal(DeliverRequest{
			SenderOrgID:    req.SenderOrgID,
			SenderID:       req.SenderID,
			RecipientOrgID: req.RecipientOrgID,
			RecipientID:    req.RecipientID,
			Subject:        req.Subject,
			Body:           req.Body,
			ConversationID: conversationID,
		})
		if err != nil {
			return nil, fmt.Errorf("marshal relay payload: %w", err)
		}

		if _, err := s.federation.RelayMessage(ctx, req.RecipientOrgID, payload); err != nil {
			errDetail := err.Error()
			_ = s.repo.MarkFailed(ctx, senderMsg.ID, errDetail)
			senderMsg.Status = models.DirectMessageStatusFailed
			senderMsg.ErrorDetail = errDetail
		} else {
			_ = s.repo.MarkDelivered(ctx, senderMsg.ID)
			senderMsg.Status = models.DirectMessageStatusDelivered
		}
	}

	// Audit
	if s.audit != nil {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: now,
			OrgID:     req.SenderOrgID,
			EventType: models.AuditEventTypeMessageSend,
			Actor:     req.SenderID,
			Result:    auditResult(senderMsg.Status),
			Metadata: map[string]any{
				"message_id":    senderMsg.ID,
				"recipient_org": req.RecipientOrgID,
				"recipient_id":  req.RecipientID,
				"same_org":      sameOrg,
			},
		})
	}

	return senderMsg, nil
}

// Deliver handles an inbound message from a federation partner.
func (s *serviceImpl) Deliver(ctx context.Context, req DeliverRequest) (string, error) {
	// Verify recipient exists locally
	exists, err := s.resolver.IdentityExists(ctx, req.RecipientID)
	if err != nil {
		return "", fmt.Errorf("resolve recipient identity: %w", err)
	}
	if !exists {
		return "", fmt.Errorf("recipient %s not found: %w", req.RecipientID, errors.ErrNotFound)
	}

	// Encrypt body with local org KEK
	encBody, err := s.encryptor.Encrypt(ctx, req.RecipientOrgID, req.Body)
	if err != nil {
		return "", fmt.Errorf("encrypt inbound body: %w", err)
	}

	now := time.Now()
	msg := &models.DirectMessage{
		ID:             uuid.New().String(),
		ConversationID: req.ConversationID,
		SenderOrgID:    req.SenderOrgID,
		SenderID:       req.SenderID,
		RecipientOrgID: req.RecipientOrgID,
		RecipientID:    req.RecipientID,
		Subject:        req.Subject,
		Body:           encBody,
		Status:         models.DirectMessageStatusDelivered,
		Direction:      "received",
		CreatedAt:      now,
		DeliveredAt:    &now,
	}

	if err := s.repo.Create(ctx, msg); err != nil {
		return "", fmt.Errorf("store inbound message: %w", err)
	}

	// Audit
	if s.audit != nil {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: now,
			OrgID:     req.RecipientOrgID,
			EventType: models.AuditEventTypeMessageDeliver,
			Actor:     "federation",
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"message_id":   msg.ID,
				"sender_org":   req.SenderOrgID,
				"sender_id":    req.SenderID,
				"recipient_id": req.RecipientID,
			},
		})
	}

	return msg.ID, nil
}

// Read fetches a message, verifies ownership, decrypts the body, and marks it as read if received.
func (s *serviceImpl) Read(ctx context.Context, callerOrgID, callerID, messageID string) (*models.DirectMessage, error) {
	msg, err := s.repo.Get(ctx, messageID)
	if err != nil {
		return nil, fmt.Errorf("get message: %w", err)
	}

	// Verify caller owns this message
	if !isMessageOwner(msg, callerOrgID, callerID) {
		return nil, fmt.Errorf("message access denied: %w", errors.ErrForbidden)
	}

	// Decrypt body using the appropriate org KEK
	orgID := callerOrgID
	plainBody, err := s.encryptor.Decrypt(ctx, orgID, msg.Body)
	if err != nil {
		return nil, fmt.Errorf("decrypt message body: %w", err)
	}
	msg.Body = plainBody

	// Mark as read if it's a received message
	if msg.Direction == "received" && msg.Status == models.DirectMessageStatusDelivered {
		_ = s.repo.MarkRead(ctx, messageID)
		now := time.Now()
		msg.Status = models.DirectMessageStatusRead
		msg.ReadAt = &now

		if s.audit != nil {
			_ = s.audit.Log(ctx, &models.AuditEvent{
				ID:        uuid.New().String(),
				Timestamp: now,
				OrgID:     callerOrgID,
				EventType: models.AuditEventTypeMessageRead,
				Actor:     callerID,
				Result:    models.AuditEventResultSuccess,
				Metadata: map[string]any{
					"message_id": messageID,
				},
			})
		}
	}

	return msg, nil
}

// ListInbox returns received messages for a user.
func (s *serviceImpl) ListInbox(ctx context.Context, orgID, userID string, limit, offset int) ([]*models.DirectMessage, error) {
	msgs, err := s.repo.ListInbox(ctx, orgID, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list inbox: %w", err)
	}
	return msgs, nil
}

// ListSent returns sent messages for a user.
func (s *serviceImpl) ListSent(ctx context.Context, orgID, userID string, limit, offset int) ([]*models.DirectMessage, error) {
	msgs, err := s.repo.ListSent(ctx, orgID, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list sent: %w", err)
	}
	return msgs, nil
}

// Delete removes a message after verifying ownership.
func (s *serviceImpl) Delete(ctx context.Context, callerOrgID, callerID, messageID string) error {
	msg, err := s.repo.Get(ctx, messageID)
	if err != nil {
		return fmt.Errorf("get message for delete: %w", err)
	}

	if !isMessageOwner(msg, callerOrgID, callerID) {
		return fmt.Errorf("message access denied: %w", errors.ErrForbidden)
	}

	if err := s.repo.Delete(ctx, messageID); err != nil {
		return fmt.Errorf("delete message: %w", err)
	}

	if s.audit != nil {
		_ = s.audit.Log(ctx, &models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			OrgID:     callerOrgID,
			EventType: models.AuditEventTypeMessageDelete,
			Actor:     callerID,
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"message_id": messageID,
			},
		})
	}

	return nil
}

func isMessageOwner(msg *models.DirectMessage, orgID, userID string) bool {
	if msg.Direction == "sent" {
		return msg.SenderOrgID == orgID && msg.SenderID == userID
	}
	return msg.RecipientOrgID == orgID && msg.RecipientID == userID
}

func auditResult(status models.DirectMessageStatus) models.AuditEventResult {
	if status == models.DirectMessageStatusFailed {
		return models.AuditEventResultError
	}
	return models.AuditEventResultSuccess
}

// VaultEncryptor implements Encryptor using Vault transit.
type VaultEncryptor struct {
	transit *vault.TransitClient
}

// NewVaultEncryptor creates an Encryptor backed by Vault transit.
func NewVaultEncryptor(transit *vault.TransitClient) *VaultEncryptor {
	return &VaultEncryptor{transit: transit}
}

// Encrypt encrypts plaintext using the org's KEK.
func (e *VaultEncryptor) Encrypt(ctx context.Context, orgID string, plaintext []byte) ([]byte, error) {
	keyName := fmt.Sprintf("org-kek-%s", orgID)
	ciphertext, err := e.transit.Encrypt(ctx, keyName, plaintext)
	if err != nil {
		return nil, fmt.Errorf("vault transit encrypt: %w", err)
	}
	return []byte(ciphertext), nil
}

// Decrypt decrypts ciphertext using the org's KEK.
func (e *VaultEncryptor) Decrypt(ctx context.Context, orgID string, ciphertext []byte) ([]byte, error) {
	keyName := fmt.Sprintf("org-kek-%s", orgID)
	plaintext, err := e.transit.Decrypt(ctx, keyName, string(ciphertext))
	if err != nil {
		return nil, fmt.Errorf("vault transit decrypt: %w", err)
	}
	return plaintext, nil
}

// IdentityManagerAdapter adapts identity.Manager to IdentityResolver.
type IdentityManagerAdapter struct {
	GetUserFn func(ctx context.Context, id string) (any, error)
}

// IdentityExists checks whether a user identity exists.
func (a *IdentityManagerAdapter) IdentityExists(ctx context.Context, identityID string) (bool, error) {
	result, err := a.GetUserFn(ctx, identityID)
	if err != nil {
		return false, fmt.Errorf("identity lookup: %w", err)
	}
	return result != nil, nil
}
