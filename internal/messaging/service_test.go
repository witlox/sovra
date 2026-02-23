package messaging_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/messaging"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/tests/mocks"
)

func newTestService() (messaging.Service, *mocks.DirectMessageRepository, *mocks.MockFederationRelay, *mocks.MockEncryptor, *mocks.MockIdentityResolver, *mocks.MockAuditService) {
	repo := mocks.NewDirectMessageRepository()
	relay := mocks.NewMockFederationRelay()
	enc := mocks.NewMockEncryptor()
	resolver := mocks.NewMockIdentityResolver()
	audit := mocks.NewMockAuditService()
	svc := messaging.NewService(repo, relay, enc, resolver, audit)
	return svc, repo, relay, enc, resolver, audit
}

// =============================================================================
// Send Tests
// =============================================================================

func TestSendSameOrg(t *testing.T) {
	svc, repo, _, _, _, audit := newTestService()
	ctx := context.Background()

	msg, err := svc.Send(ctx, messaging.SendRequest{
		SenderOrgID:    "org1",
		SenderID:       "user-a",
		RecipientOrgID: "org1",
		RecipientID:    "user-b",
		Subject:        "Hello",
		Body:           []byte("Hi there"),
	})

	require.NoError(t, err)
	assert.Equal(t, models.DirectMessageStatusDelivered, msg.Status)
	assert.Equal(t, "sent", msg.Direction)
	assert.NotEmpty(t, msg.ConversationID)

	// Should have created two copies (sent + received)
	inbox, err := repo.ListInbox(ctx, "org1", "user-b", 50, 0)
	require.NoError(t, err)
	assert.Len(t, inbox, 1)
	assert.Equal(t, "received", inbox[0].Direction)
	assert.Equal(t, models.DirectMessageStatusDelivered, inbox[0].Status)

	// Audit event should be logged
	assert.Len(t, audit.Events, 1)
	assert.Equal(t, models.AuditEventTypeMessageSend, audit.Events[0].EventType)
}

func TestSendCrossOrg(t *testing.T) {
	svc, _, relay, _, _, audit := newTestService()
	ctx := context.Background()

	msg, err := svc.Send(ctx, messaging.SendRequest{
		SenderOrgID:    "org1",
		SenderID:       "user-a",
		RecipientOrgID: "org2",
		RecipientID:    "user-b",
		Subject:        "Cross-org message",
		Body:           []byte("Confidential data"),
	})

	require.NoError(t, err)
	assert.Equal(t, models.DirectMessageStatusDelivered, msg.Status)

	// Federation relay should have been called
	assert.Len(t, relay.RelayedPayloads, 1)
	assert.Contains(t, string(relay.RelayedPayloads[0]), "Cross-org message")

	assert.Len(t, audit.Events, 1)
}

func TestSendCrossOrgFederationInactive(t *testing.T) {
	svc, _, relay, _, _, _ := newTestService()
	relay.Active = false
	ctx := context.Background()

	_, err := svc.Send(ctx, messaging.SendRequest{
		SenderOrgID:    "org1",
		SenderID:       "user-a",
		RecipientOrgID: "org2",
		RecipientID:    "user-b",
		Subject:        "Should fail",
		Body:           []byte("data"),
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no active federation")
}

func TestSendCrossOrgRelayFails(t *testing.T) {
	svc, repo, relay, _, _, _ := newTestService()
	relay.RelayErr = fmt.Errorf("partner unreachable")
	ctx := context.Background()

	msg, err := svc.Send(ctx, messaging.SendRequest{
		SenderOrgID:    "org1",
		SenderID:       "user-a",
		RecipientOrgID: "org2",
		RecipientID:    "user-b",
		Subject:        "Relay failure",
		Body:           []byte("data"),
	})

	require.NoError(t, err) // Send itself doesn't error, but marks as failed
	assert.Equal(t, models.DirectMessageStatusFailed, msg.Status)
	assert.Contains(t, msg.ErrorDetail, "partner unreachable")

	// The sender copy should be stored with failed status
	stored, err := repo.Get(ctx, msg.ID)
	require.NoError(t, err)
	assert.Equal(t, models.DirectMessageStatusFailed, stored.Status)
}

func TestSendAutoGeneratesConversationID(t *testing.T) {
	svc, _, _, _, _, _ := newTestService()
	ctx := context.Background()

	msg, err := svc.Send(ctx, messaging.SendRequest{
		SenderOrgID:    "org1",
		SenderID:       "user-a",
		RecipientOrgID: "org1",
		RecipientID:    "user-b",
		Subject:        "Hello",
		Body:           []byte("data"),
	})

	require.NoError(t, err)
	assert.NotEmpty(t, msg.ConversationID)
}

func TestSendExplicitConversationID(t *testing.T) {
	svc, _, _, _, _, _ := newTestService()
	ctx := context.Background()

	msg, err := svc.Send(ctx, messaging.SendRequest{
		SenderOrgID:    "org1",
		SenderID:       "user-a",
		RecipientOrgID: "org1",
		RecipientID:    "user-b",
		Subject:        "Hello",
		Body:           []byte("data"),
		ConversationID: "conv-123",
	})

	require.NoError(t, err)
	assert.Equal(t, "conv-123", msg.ConversationID)
}

// =============================================================================
// Validation Tests
// =============================================================================

func TestSendSubjectTooLong(t *testing.T) {
	svc, _, _, _, _, _ := newTestService()
	ctx := context.Background()

	longSubject := strings.Repeat("a", 257)
	_, err := svc.Send(ctx, messaging.SendRequest{
		SenderOrgID:    "org1",
		SenderID:       "user-a",
		RecipientOrgID: "org1",
		RecipientID:    "user-b",
		Subject:        longSubject,
		Body:           []byte("data"),
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject exceeds")
}

func TestSendBodyTooLarge(t *testing.T) {
	svc, _, _, _, _, _ := newTestService()
	ctx := context.Background()

	largeBody := make([]byte, 65*1024) // 65KB > 64KB limit
	_, err := svc.Send(ctx, messaging.SendRequest{
		SenderOrgID:    "org1",
		SenderID:       "user-a",
		RecipientOrgID: "org1",
		RecipientID:    "user-b",
		Subject:        "Too big",
		Body:           largeBody,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "body exceeds")
}

func TestSendEmptySubject(t *testing.T) {
	svc, _, _, _, _, _ := newTestService()
	ctx := context.Background()

	_, err := svc.Send(ctx, messaging.SendRequest{
		SenderOrgID:    "org1",
		SenderID:       "user-a",
		RecipientOrgID: "org1",
		RecipientID:    "user-b",
		Subject:        "",
		Body:           []byte("data"),
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject is required")
}

func TestSendEmptyBody(t *testing.T) {
	svc, _, _, _, _, _ := newTestService()
	ctx := context.Background()

	_, err := svc.Send(ctx, messaging.SendRequest{
		SenderOrgID:    "org1",
		SenderID:       "user-a",
		RecipientOrgID: "org1",
		RecipientID:    "user-b",
		Subject:        "No body",
		Body:           nil,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "body is required")
}

// =============================================================================
// Deliver Tests
// =============================================================================

func TestDeliverInbound(t *testing.T) {
	svc, repo, _, _, _, audit := newTestService()
	ctx := context.Background()

	msgID, err := svc.Deliver(ctx, messaging.DeliverRequest{
		SenderOrgID:    "org-remote",
		SenderID:       "remote-user",
		RecipientOrgID: "org1",
		RecipientID:    "local-user",
		Subject:        "Inbound message",
		Body:           []byte("Hello from remote"),
		ConversationID: "conv-456",
	})

	require.NoError(t, err)
	assert.NotEmpty(t, msgID)

	// Message should be stored as received/delivered
	msg, err := repo.Get(ctx, msgID)
	require.NoError(t, err)
	assert.Equal(t, "received", msg.Direction)
	assert.Equal(t, models.DirectMessageStatusDelivered, msg.Status)
	assert.Equal(t, "conv-456", msg.ConversationID)
	assert.NotNil(t, msg.DeliveredAt)

	// Body should be encrypted
	assert.Contains(t, string(msg.Body), "enc:org1:")

	// Audit event
	assert.Len(t, audit.Events, 1)
	assert.Equal(t, models.AuditEventTypeMessageDeliver, audit.Events[0].EventType)
}

func TestDeliverRecipientNotFound(t *testing.T) {
	svc, _, _, _, resolver, _ := newTestService()
	resolver.Exists = false
	ctx := context.Background()

	_, err := svc.Deliver(ctx, messaging.DeliverRequest{
		SenderOrgID:    "org-remote",
		SenderID:       "remote-user",
		RecipientOrgID: "org1",
		RecipientID:    "unknown-user",
		Subject:        "To nobody",
		Body:           []byte("data"),
		ConversationID: "conv-789",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// =============================================================================
// Read Tests
// =============================================================================

func TestReadDecryptsAndMarksAsRead(t *testing.T) {
	svc, _, _, _, _, audit := newTestService()
	ctx := context.Background()

	// First send a same-org message to get a received copy
	sent, err := svc.Send(ctx, messaging.SendRequest{
		SenderOrgID:    "org1",
		SenderID:       "user-a",
		RecipientOrgID: "org1",
		RecipientID:    "user-b",
		Subject:        "Read test",
		Body:           []byte("message content"),
	})
	require.NoError(t, err)

	// Get the received message ID from inbox
	inbox, err := svc.ListInbox(ctx, "org1", "user-b", 50, 0)
	require.NoError(t, err)
	require.Len(t, inbox, 1)
	recvMsgID := inbox[0].ID

	// Clear audit from send
	audit.Events = nil

	// Read as recipient
	msg, err := svc.Read(ctx, "org1", "user-b", recvMsgID)
	require.NoError(t, err)
	assert.Equal(t, "message content", string(msg.Body))
	assert.Equal(t, models.DirectMessageStatusRead, msg.Status)
	assert.NotNil(t, msg.ReadAt)

	// Should have audit event for read
	assert.Len(t, audit.Events, 1)
	assert.Equal(t, models.AuditEventTypeMessageRead, audit.Events[0].EventType)

	// Sender can also read their own sent copy
	_, err = svc.Read(ctx, "org1", "user-a", sent.ID)
	require.NoError(t, err)
}

func TestReadForbiddenForNonOwner(t *testing.T) {
	svc, _, _, _, _, _ := newTestService()
	ctx := context.Background()

	// Send a message
	sent, err := svc.Send(ctx, messaging.SendRequest{
		SenderOrgID:    "org1",
		SenderID:       "user-a",
		RecipientOrgID: "org1",
		RecipientID:    "user-b",
		Subject:        "Private",
		Body:           []byte("secret"),
	})
	require.NoError(t, err)

	// Try to read as an unrelated user
	_, err = svc.Read(ctx, "org1", "user-c", sent.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

func TestReadNotFound(t *testing.T) {
	svc, _, _, _, _, _ := newTestService()
	ctx := context.Background()

	_, err := svc.Read(ctx, "org1", "user-a", "nonexistent-id")
	require.Error(t, err)
}

// =============================================================================
// List Tests
// =============================================================================

func TestListInbox(t *testing.T) {
	svc, _, _, _, _, _ := newTestService()
	ctx := context.Background()

	// Send 3 messages to user-b
	for i := 0; i < 3; i++ {
		_, err := svc.Send(ctx, messaging.SendRequest{
			SenderOrgID:    "org1",
			SenderID:       "user-a",
			RecipientOrgID: "org1",
			RecipientID:    "user-b",
			Subject:        fmt.Sprintf("Message %d", i),
			Body:           []byte("data"),
		})
		require.NoError(t, err)
	}

	inbox, err := svc.ListInbox(ctx, "org1", "user-b", 50, 0)
	require.NoError(t, err)
	assert.Len(t, inbox, 3)
}

func TestListSent(t *testing.T) {
	svc, _, _, _, _, _ := newTestService()
	ctx := context.Background()

	// Send 2 messages from user-a
	for i := 0; i < 2; i++ {
		_, err := svc.Send(ctx, messaging.SendRequest{
			SenderOrgID:    "org1",
			SenderID:       "user-a",
			RecipientOrgID: "org1",
			RecipientID:    "user-b",
			Subject:        fmt.Sprintf("Sent %d", i),
			Body:           []byte("data"),
		})
		require.NoError(t, err)
	}

	sent, err := svc.ListSent(ctx, "org1", "user-a", 50, 0)
	require.NoError(t, err)
	assert.Len(t, sent, 2)
}

func TestListInboxEmpty(t *testing.T) {
	svc, _, _, _, _, _ := newTestService()
	ctx := context.Background()

	inbox, err := svc.ListInbox(ctx, "org1", "user-c", 50, 0)
	require.NoError(t, err)
	assert.Empty(t, inbox)
}

// =============================================================================
// Delete Tests
// =============================================================================

func TestDeleteOwnMessage(t *testing.T) {
	svc, repo, _, _, _, audit := newTestService()
	ctx := context.Background()

	msg, err := svc.Send(ctx, messaging.SendRequest{
		SenderOrgID:    "org1",
		SenderID:       "user-a",
		RecipientOrgID: "org1",
		RecipientID:    "user-b",
		Subject:        "Delete me",
		Body:           []byte("data"),
	})
	require.NoError(t, err)

	audit.Events = nil

	err = svc.Delete(ctx, "org1", "user-a", msg.ID)
	require.NoError(t, err)

	// Verify deleted
	_, err = repo.Get(ctx, msg.ID)
	require.Error(t, err)

	// Audit event
	assert.Len(t, audit.Events, 1)
	assert.Equal(t, models.AuditEventTypeMessageDelete, audit.Events[0].EventType)
}

func TestDeleteForbiddenForNonOwner(t *testing.T) {
	svc, _, _, _, _, _ := newTestService()
	ctx := context.Background()

	msg, err := svc.Send(ctx, messaging.SendRequest{
		SenderOrgID:    "org1",
		SenderID:       "user-a",
		RecipientOrgID: "org1",
		RecipientID:    "user-b",
		Subject:        "Don't delete",
		Body:           []byte("data"),
	})
	require.NoError(t, err)

	err = svc.Delete(ctx, "org1", "user-c", msg.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

func TestDeleteNotFound(t *testing.T) {
	svc, _, _, _, _, _ := newTestService()
	ctx := context.Background()

	err := svc.Delete(ctx, "org1", "user-a", "nonexistent-id")
	require.Error(t, err)
}

// =============================================================================
// Encryption Error Tests
// =============================================================================

func TestSendEncryptionFailure(t *testing.T) {
	svc, _, _, enc, _, _ := newTestService()
	enc.FailNext = true
	ctx := context.Background()

	_, err := svc.Send(ctx, messaging.SendRequest{
		SenderOrgID:    "org1",
		SenderID:       "user-a",
		RecipientOrgID: "org1",
		RecipientID:    "user-b",
		Subject:        "Encrypt fail",
		Body:           []byte("data"),
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "encrypt")
}

func TestDeliverEncryptionFailure(t *testing.T) {
	svc, _, _, enc, _, _ := newTestService()
	enc.FailNext = true
	ctx := context.Background()

	_, err := svc.Deliver(ctx, messaging.DeliverRequest{
		SenderOrgID:    "org-remote",
		SenderID:       "remote-user",
		RecipientOrgID: "org1",
		RecipientID:    "local-user",
		Subject:        "Encrypt fail",
		Body:           []byte("data"),
		ConversationID: "conv-1",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "encrypt")
}
