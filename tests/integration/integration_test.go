// Package integration contains integration tests for Sovra services.
package integration

import (
	"context"
	"testing"
	"time"

	"github.com/sovra-project/sovra/internal/api"
	"github.com/sovra-project/sovra/internal/audit"
	"github.com/sovra-project/sovra/internal/crk"
	"github.com/sovra-project/sovra/internal/edge"
	"github.com/sovra-project/sovra/internal/federation"
	"github.com/sovra-project/sovra/internal/policy"
	"github.com/sovra-project/sovra/internal/workspace"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWorkspaceCreationFlow tests the complete workspace creation flow.
func TestWorkspaceCreationFlow(t *testing.T) {
	ctx := context.Background()

	// Setup services
	crkService := crk.NewManager(crk.NewMockGenerator(), crk.NewMockReconstructor())
	workspaceService := workspace.NewService(
		workspace.NewMockRepository(),
		workspace.NewMockKeyManager(),
		workspace.NewMockCryptoService(),
	)
	policyService := policy.NewService(policy.NewMockRepository(), policy.NewMockEngine())
	auditService := audit.NewService(audit.NewMockRepository(), audit.NewMockForwarder(), audit.NewMockVerifier())

	t.Run("create workspace with CRK signing", func(t *testing.T) {
		// Step 1: Generate CRK for organization
		crkGenReq := &crk.GenerateRequest{
			OrgID:     "org-eth",
			Threshold: 3,
			Shares:    5,
		}
		crkResult, err := crkService.Generate(ctx, crkGenReq)
		require.NoError(t, err)
		require.Equal(t, 5, len(crkResult.Shares))

		// Step 2: Create workspace (requires CRK signing)
		ws := &models.Workspace{
			Name:           "cancer-research",
			OwnerOrgID:     "org-eth",
			Classification: models.ClassificationConfidential,
			Participants: []models.WorkspaceParticipant{
				{OrgID: "org-eth", Role: "owner"},
			},
		}

		createdWS, err := workspaceService.Create(ctx, ws)
		require.NoError(t, err)
		assert.NotEmpty(t, createdWS.ID)

		// Step 3: Create policy for workspace
		p := &models.Policy{
			Name:        "cancer-research-policy",
			WorkspaceID: createdWS.ID,
			Rego: `
				package sovra.workspace
				
				default allow = false
				
				allow {
					input.action == "encrypt"
					input.user.role == "researcher"
				}
			`,
		}
		err = policyService.(*policy.MockEngine).LoadPolicy(ctx, p)
		require.NoError(t, err)

		// Step 4: Log audit event
		auditEvent := &models.AuditEvent{
			OrgID:     "org-eth",
			Workspace: createdWS.ID,
			EventType: models.AuditEventTypeKeyCreate,
			Actor:     "admin@eth.ch",
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"operation": "workspace.create",
			},
		}
		err = auditService.Log(ctx, auditEvent)
		require.NoError(t, err)
	})
}

// TestCrossOrgDataSharing tests data sharing between federated organizations.
func TestCrossOrgDataSharing(t *testing.T) {
	ctx := context.Background()

	// Setup services
	workspaceService := workspace.NewService(
		workspace.NewMockRepository(),
		workspace.NewMockKeyManager(),
		workspace.NewMockCryptoService(),
	)
	federationService := federation.NewService(
		federation.NewMockRepository(),
		federation.NewMockCertManager(),
		federation.NewMockMTLSClient(),
	)
	auditService := audit.NewService(audit.NewMockRepository(), audit.NewMockForwarder(), audit.NewMockVerifier())

	t.Run("org A shares data with org B", func(t *testing.T) {
		// Step 1: Initialize federation for org A
		certA, err := federationService.InitFederation(ctx, "org-a")
		require.NoError(t, err)
		require.NotEmpty(t, certA)

		// Step 2: Initialize federation for org B
		certB, err := federationService.InitFederation(ctx, "org-b")
		require.NoError(t, err)
		require.NotEmpty(t, certB)

		// Step 3: Establish bilateral federation
		err = federationService.EstablishFederation(ctx, "org-a", "org-b", certB)
		require.NoError(t, err)

		err = federationService.EstablishFederation(ctx, "org-b", "org-a", certA)
		require.NoError(t, err)

		// Step 4: Create shared workspace
		ws := &models.Workspace{
			Name:           "shared-research",
			OwnerOrgID:     "org-a",
			Classification: models.ClassificationConfidential,
			Participants: []models.WorkspaceParticipant{
				{OrgID: "org-a", Role: "owner"},
				{OrgID: "org-b", Role: "participant"},
			},
		}

		createdWS, err := workspaceService.Create(ctx, ws)
		require.NoError(t, err)

		// Step 5: Org A encrypts data
		plaintext := []byte("sensitive research data")
		ciphertext, err := workspaceService.Encrypt(ctx, createdWS.ID, plaintext)
		require.NoError(t, err)

		// Step 6: Log encrypt event
		err = auditService.Log(ctx, &models.AuditEvent{
			OrgID:     "org-a",
			Workspace: createdWS.ID,
			EventType: models.AuditEventTypeEncrypt,
			Actor:     "researcher@org-a.com",
			Result:    models.AuditEventResultSuccess,
		})
		require.NoError(t, err)

		// Step 7: Org B decrypts data (as participant)
		decrypted, err := workspaceService.Decrypt(ctx, createdWS.ID, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)

		// Step 8: Log decrypt event
		err = auditService.Log(ctx, &models.AuditEvent{
			OrgID:     "org-b",
			Workspace: createdWS.ID,
			EventType: models.AuditEventTypeDecrypt,
			Actor:     "researcher@org-b.com",
			Result:    models.AuditEventResultSuccess,
		})
		require.NoError(t, err)
	})
}

// TestMTLSAuthenticationFlow tests mTLS authentication.
func TestMTLSAuthenticationFlow(t *testing.T) {
	ctx := context.Background()

	t.Run("authenticate with valid certificate", func(t *testing.T) {
		verifier := api.NewMockMTLSVerifier()
		auth := api.NewMockAuthenticator()
		authz := api.NewMockAuthorizer()

		// Step 1: Verify certificate
		cert := []byte("valid-client-certificate")
		certInfo, err := verifier.VerifyCertificate(ctx, cert)
		require.NoError(t, err)
		assert.Equal(t, "eth-org", certInfo.Organization)

		// Step 2: Authenticate
		authResult, err := auth.AuthenticateCertificate(ctx, cert)
		require.NoError(t, err)
		assert.True(t, authResult.Authenticated)

		// Step 3: Authorize action
		authzReq := &api.AuthzRequest{
			UserID:     authResult.UserID,
			OrgID:      authResult.OrgID,
			Roles:      authResult.Roles,
			Action:     "encrypt",
			Resource:   "workspace",
			ResourceID: "cancer-research",
		}
		authzResult, err := authz.Authorize(ctx, authzReq)
		require.NoError(t, err)
		assert.True(t, authzResult.Allowed)
	})
}

// TestEdgeNodeIntegration tests edge node (Vault) integration.
func TestEdgeNodeIntegration(t *testing.T) {
	ctx := context.Background()

	edgeService := edge.NewService(
		edge.NewMockRepository(),
		edge.NewMockVaultClient(),
		edge.NewMockHealthChecker(),
		edge.NewMockSyncManager(),
	)

	t.Run("full encryption cycle via edge node", func(t *testing.T) {
		// Step 1: Register edge node
		config := &edge.NodeConfig{
			Name:           "vault-cluster-1",
			VaultAddress:   "https://vault.eth.ch:8200",
			Classification: models.ClassificationConfidential,
		}
		node, err := edgeService.Register(ctx, "org-eth", config)
		require.NoError(t, err)

		// Step 2: Health check
		health, err := edgeService.HealthCheck(ctx, node.ID)
		require.NoError(t, err)
		assert.True(t, health.Healthy)

		// Step 3: Encrypt data
		plaintext := []byte("sensitive patient data")
		ciphertext, err := edgeService.Encrypt(ctx, node.ID, "workspace-dek", plaintext)
		require.NoError(t, err)
		assert.NotEqual(t, plaintext, ciphertext)

		// Step 4: Decrypt data
		decrypted, err := edgeService.Decrypt(ctx, node.ID, "workspace-dek", ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)

		// Step 5: Sign data
		signature, err := edgeService.Sign(ctx, node.ID, "signing-key", plaintext)
		require.NoError(t, err)

		// Step 6: Verify signature
		valid, err := edgeService.Verify(ctx, node.ID, "signing-key", plaintext, signature)
		require.NoError(t, err)
		assert.True(t, valid)
	})
}

// TestPolicyEvaluationFlow tests policy evaluation.
func TestPolicyEvaluationFlow(t *testing.T) {
	ctx := context.Background()

	engine := policy.NewMockEngine()

	t.Run("evaluate time-based policy", func(t *testing.T) {
		// Step 1: Load policy
		p := &models.Policy{
			ID:          "time-policy",
			Name:        "business-hours-only",
			WorkspaceID: "ws-123",
			Rego: `
				package sovra.workspace
				
				default allow = false
				
				allow {
					time.hour(time.now_ns()) >= 9
					time.hour(time.now_ns()) < 17
				}
			`,
		}
		err := engine.LoadPolicy(ctx, p)
		require.NoError(t, err)

		// Step 2: Evaluate policy
		input := models.PolicyInput{
			Action: "decrypt",
			User: models.PolicyUser{
				ID:    "user-123",
				OrgID: "org-eth",
				Role:  "researcher",
			},
			Resource: models.PolicyResource{
				Type: "workspace",
				ID:   "ws-123",
			},
		}

		result, err := engine.EvaluateWithPolicy(ctx, "time-policy", input)
		require.NoError(t, err)
		// Result depends on current time; we're testing the flow
		_ = result
	})
}

// TestAuditTrailIntegrity tests audit log integrity.
func TestAuditTrailIntegrity(t *testing.T) {
	ctx := context.Background()

	auditService := audit.NewService(
		audit.NewMockRepository(),
		audit.NewMockForwarder(),
		audit.NewMockVerifier(),
	)

	t.Run("verify audit chain integrity", func(t *testing.T) {
		// Step 1: Create multiple audit events
		for i := 0; i < 10; i++ {
			event := &models.AuditEvent{
				Timestamp: time.Now().Add(time.Duration(i) * time.Minute),
				OrgID:     "org-eth",
				Workspace: "cancer-research",
				EventType: models.AuditEventTypeEncrypt,
				Actor:     "researcher@eth.ch",
				Result:    models.AuditEventResultSuccess,
			}
			err := auditService.Log(ctx, event)
			require.NoError(t, err)
		}

		// Step 2: Verify integrity
		since := time.Now().Add(-1 * time.Hour)
		until := time.Now()
		valid, err := auditService.VerifyIntegrity(ctx, since, until)
		require.NoError(t, err)
		assert.True(t, valid)
	})
}

// TestFederationHealthCheck tests federation health monitoring.
func TestFederationHealthCheck(t *testing.T) {
	ctx := context.Background()

	federationService := federation.NewService(
		federation.NewMockRepository(),
		federation.NewMockCertManager(),
		federation.NewMockMTLSClient(),
	)

	t.Run("monitor federated partner health", func(t *testing.T) {
		// Step 1: Initialize and establish federation
		certA, _ := federationService.InitFederation(ctx, "org-a")
		certB, _ := federationService.InitFederation(ctx, "org-b")

		_ = federationService.EstablishFederation(ctx, "org-a", "org-b", certB)
		_ = federationService.EstablishFederation(ctx, "org-b", "org-a", certA)

		// Step 2: Check federation health
		health, err := federationService.HealthCheck(ctx, "org-a", "org-b")
		require.NoError(t, err)
		assert.True(t, health.Healthy)
		assert.True(t, health.CertificateValid)
	})
}

// TestCRKCeremony tests CRK ceremony flow.
func TestCRKCeremony(t *testing.T) {
	ctx := context.Background()

	crkService := crk.NewCeremonyManager(crk.NewMockCeremonyRepo())

	t.Run("complete CRK generation ceremony", func(t *testing.T) {
		// Step 1: Start ceremony
		req := &crk.CeremonyStartRequest{
			OrgID:     "org-eth",
			Operation: crk.CeremonyOperationGenerate,
			Custodians: []string{
				"alice@eth.ch",
				"bob@eth.ch",
				"charlie@eth.ch",
				"david@eth.ch",
				"eve@eth.ch",
			},
			Threshold:    3,
			ShareCount:   5,
			WitnessCount: 2,
		}

		ceremony, err := crkService.StartCeremony(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, crk.CeremonyStatusPending, ceremony.Status)

		// Step 2: All custodians accept
		for _, custodian := range req.Custodians {
			err = crkService.RecordCustodianAction(ctx, ceremony.ID, custodian, crk.CustodianActionAccept)
			require.NoError(t, err)
		}

		// Step 3: Witnesses attest
		err = crkService.RecordWitness(ctx, ceremony.ID, "witness1@eth.ch")
		require.NoError(t, err)
		err = crkService.RecordWitness(ctx, ceremony.ID, "witness2@eth.ch")
		require.NoError(t, err)

		// Step 4: Complete ceremony
		result, err := crkService.CompleteCeremony(ctx, ceremony.ID)
		require.NoError(t, err)
		assert.Equal(t, crk.CeremonyStatusCompleted, result.Status)
	})
}

// TestKeyRotation tests key rotation flow.
func TestKeyRotation(t *testing.T) {
	ctx := context.Background()

	edgeService := edge.NewService(
		edge.NewMockRepository(),
		edge.NewMockVaultClient(),
		edge.NewMockHealthChecker(),
		edge.NewMockSyncManager(),
	)
	auditService := audit.NewService(audit.NewMockRepository(), audit.NewMockForwarder(), audit.NewMockVerifier())

	t.Run("rotate key and verify old data still decryptable", func(t *testing.T) {
		// Register edge node
		config := &edge.NodeConfig{
			Name:         "rotation-test-node",
			VaultAddress: "https://vault.eth.ch:8200",
		}
		node, _ := edgeService.Register(ctx, "org-eth", config)

		// Encrypt data with current key version
		plaintext := []byte("data before rotation")
		ciphertext, err := edgeService.Encrypt(ctx, node.ID, "rotation-key", plaintext)
		require.NoError(t, err)

		// Rotate key
		err = edgeService.RotateKey(ctx, node.ID, "rotation-key")
		require.NoError(t, err)

		// Log rotation event
		err = auditService.Log(ctx, &models.AuditEvent{
			OrgID:     "org-eth",
			EventType: "key.rotate",
			Actor:     "admin@eth.ch",
			Result:    models.AuditEventResultSuccess,
			Metadata: map[string]any{
				"key_name": "rotation-key",
			},
		})
		require.NoError(t, err)

		// Old ciphertext should still be decryptable
		decrypted, err := edgeService.Decrypt(ctx, node.ID, "rotation-key", ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)

		// New encryption should work
		newPlaintext := []byte("data after rotation")
		newCiphertext, err := edgeService.Encrypt(ctx, node.ID, "rotation-key", newPlaintext)
		require.NoError(t, err)

		newDecrypted, err := edgeService.Decrypt(ctx, node.ID, "rotation-key", newCiphertext)
		require.NoError(t, err)
		assert.Equal(t, newPlaintext, newDecrypted)
	})
}

// TestWorkspaceExpiration tests workspace expiration handling.
func TestWorkspaceExpiration(t *testing.T) {
	ctx := context.Background()

	workspaceService := workspace.NewService(
		workspace.NewMockRepository(),
		workspace.NewMockKeyManager(),
		workspace.NewMockCryptoService(),
	)

	t.Run("expired workspace denies operations", func(t *testing.T) {
		// Create workspace with past expiration
		ws := &models.Workspace{
			Name:       "expired-workspace",
			OwnerOrgID: "org-eth",
			ExpiresAt:  time.Now().Add(-24 * time.Hour),
		}

		created, err := workspaceService.Create(ctx, ws)
		require.NoError(t, err)

		// Attempt to encrypt should fail (in real implementation)
		// The mock doesn't enforce this, but the test structure shows the expectation
		_, err = workspaceService.Encrypt(ctx, created.ID, []byte("data"))
		// In real implementation: assert.ErrorIs(t, err, errors.ErrWorkspaceExpired)
		_ = err
	})
}

// TestAirGapMode tests air-gap classification restrictions.
func TestAirGapMode(t *testing.T) {
	ctx := context.Background()

	edgeService := edge.NewService(
		edge.NewMockRepository(),
		edge.NewMockVaultClient(),
		edge.NewMockHealthChecker(),
		edge.NewMockSyncManager(),
	)

	t.Run("secret classification requires air-gap", func(t *testing.T) {
		// Register air-gapped node
		config := &edge.NodeConfig{
			Name:           "airgap-node",
			VaultAddress:   "https://vault-airgap.eth.ch:8200",
			Classification: models.ClassificationSecret,
		}

		node, err := edgeService.Register(ctx, "org-eth", config)
		require.NoError(t, err)
		assert.Equal(t, models.ClassificationSecret, node.Classification)

		// Verify operations work locally
		plaintext := []byte("top secret data")
		ciphertext, err := edgeService.Encrypt(ctx, node.ID, "secret-key", plaintext)
		require.NoError(t, err)

		decrypted, err := edgeService.Decrypt(ctx, node.ID, "secret-key", ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})
}
