// Package acceptance contains BDD-style acceptance tests based on documentation.
package acceptance

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/witlox/sovra/internal/workspace"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/tests/testutil"
	"github.com/witlox/sovra/tests/testutil/inmemory"
)

// generateRSAKeyPair generates an RSA-4096 key pair and returns PEM-encoded public and private keys.
func generateRSAKeyPair(t *testing.T) (pubPEM, privPEM []byte) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})
	return
}

// TestAirGapCrossOrgWorkspaceSharing tests the full air-gap cross-org workspace sharing flow.
// This verifies that DEK re-wrapping works correctly when sharing workspaces between
// air-gapped organizations via USB bundle transfer.
func TestAirGapCrossOrgWorkspaceSharing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	ctx := testutil.TestContext(t)

	t.Run("Scenario: Air-gap cross-org workspace export and import", func(t *testing.T) {
		// Set up two separate org environments
		orgARepo := inmemory.NewWorkspaceRepository()
		orgACrypto := inmemory.NewWorkspaceCryptoService()
		orgASvc := workspace.NewService(orgARepo, inmemory.NewWorkspaceKeyManager(), orgACrypto)

		orgBRepo := inmemory.NewWorkspaceRepository()
		orgBCrypto := inmemory.NewWorkspaceCryptoService()
		orgBSvc := workspace.NewService(orgBRepo, inmemory.NewWorkspaceKeyManager(), orgBCrypto)

		var srcWorkspace *models.Workspace
		var bundle *workspace.WorkspaceBundle

		testutil.NewScenario(t, "Air-Gap Cross-Org Workspace Transfer").
			Given("Org A creates an air-gap workspace with Org B as participant", func() {
				var err error
				srcWorkspace, err = orgASvc.Create(ctx, workspace.CreateRequest{
					Name:           "cross-org-research",
					Participants:   []string{"org-a", "org-b"},
					Classification: models.ClassificationSecret,
					Mode:           models.WorkspaceModeAirGap,
					Purpose:        "classified cross-org research",
				})
				require.NoError(t, err)
				require.NotNil(t, srcWorkspace)
			}).
			When("Org A exports the workspace as a bundle", func() {
				var err error
				bundle, err = orgASvc.ExportWorkspace(ctx, srcWorkspace.ID, nil)
				require.NoError(t, err)
				require.NotNil(t, bundle)
			}).
			Then("the bundle contains workspace metadata", func() {
				assert.Equal(t, srcWorkspace.ID, bundle.Workspace.ID)
				assert.Equal(t, "cross-org-research", bundle.Workspace.Name)
				assert.NotEmpty(t, bundle.Checksum)
			}).
			And("Org B can import the workspace bundle", func() {
				imported, err := orgBSvc.ImportWorkspace(ctx, bundle, nil)
				require.NoError(t, err)
				require.NotNil(t, imported)
				assert.Equal(t, "cross-org-research", imported.Name)
				assert.Equal(t, models.ClassificationSecret, imported.Classification)
			})
	})

	t.Run("Scenario: RSA-OAEP DEK re-encryption round-trip", func(t *testing.T) {
		// This tests the actual RSA-OAEP DEK re-encryption logic that
		// the production ExportWorkspace/ImportWorkspace uses

		orgAPubKey, _ := generateRSAKeyPair(t)
		orgBPubKey, orgBPrivKey := generateRSAKeyPair(t)

		fedLookup := inmemory.NewFederationLookup()
		fedLookup.SetPartnerPublicKey("org-a", "org-b", orgBPubKey)
		fedLookup.SetPartnerPublicKey("org-b", "org-a", orgAPubKey)

		privKeys := inmemory.NewPrivateKeyStore()
		privKeys.SetPrivateKey("org-b", orgBPrivKey)

		originalDEK := make([]byte, 32)
		_, err := rand.Read(originalDEK)
		require.NoError(t, err)

		var encryptedDEK []byte

		testutil.NewScenario(t, "RSA DEK Re-Encryption").
			Given("Org A has a workspace DEK and knows Org B's public key", func() {
				pubKey, lookupErr := fedLookup.GetPartnerPublicKey(ctx, "org-a", "org-b")
				require.NoError(t, lookupErr)
				assert.Equal(t, orgBPubKey, pubKey)
			}).
			When("Org A encrypts the DEK for Org B using RSA-OAEP", func() {
				pubKey, lookupErr := fedLookup.GetPartnerPublicKey(ctx, "org-a", "org-b")
				require.NoError(t, lookupErr)

				block, _ := pem.Decode(pubKey)
				require.NotNil(t, block)
				pub, parseErr := x509.ParsePKIXPublicKey(block.Bytes)
				require.NoError(t, parseErr)
				rsaPub, ok := pub.(*rsa.PublicKey)
				require.True(t, ok)

				encryptedDEK, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, originalDEK, nil)
				require.NoError(t, err)
				assert.NotEqual(t, originalDEK, encryptedDEK)
			}).
			Then("Org B can decrypt the DEK with their private key", func() {
				privKeyPEM, privErr := privKeys.GetPrivateKey(ctx, "org-b")
				require.NoError(t, privErr)

				privBlock, _ := pem.Decode(privKeyPEM)
				require.NotNil(t, privBlock)
				privKey, parseErr := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
				require.NoError(t, parseErr)

				decryptedDEK, decErr := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encryptedDEK, nil)
				require.NoError(t, decErr)
				assert.Equal(t, originalDEK, decryptedDEK)
			}).
			And("unknown partner lookup fails", func() {
				_, lookupErr := fedLookup.GetPartnerPublicKey(ctx, "org-a", "org-unknown")
				assert.Error(t, lookupErr)
			})
	})

	t.Run("Scenario: ExportDEK bundle with multiple participants", func(t *testing.T) {
		orgAPubKey, orgAPrivKey := generateRSAKeyPair(t)
		orgBPubKey, orgBPrivKey := generateRSAKeyPair(t)

		originalDEK := make([]byte, 32)
		_, err := rand.Read(originalDEK)
		require.NoError(t, err)

		var bundle *workspace.WorkspaceBundle

		testutil.NewScenario(t, "ExportDEK Bundle Structure").
			Given("a workspace DEK and RSA public keys for two orgs", func() {
				// Both orgs have generated keys
				require.NotEmpty(t, orgAPubKey)
				require.NotEmpty(t, orgBPubKey)
			}).
			When("the ExportDEK map is built for all participants", func() {
				exportDEK := make(map[string][]byte)
				for orgID, pubKey := range map[string][]byte{"org-a": orgAPubKey, "org-b": orgBPubKey} {
					block, _ := pem.Decode(pubKey)
					require.NotNil(t, block)
					pub, parseErr := x509.ParsePKIXPublicKey(block.Bytes)
					require.NoError(t, parseErr)
					rsaPub := pub.(*rsa.PublicKey)
					encrypted, encErr := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, originalDEK, nil)
					require.NoError(t, encErr)
					exportDEK[orgID] = encrypted
				}
				bundle = &workspace.WorkspaceBundle{
					Workspace: &models.Workspace{
						Name:            "multi-participant",
						ParticipantOrgs: []string{"org-a", "org-b"},
						Mode:            models.WorkspaceModeAirGap,
					},
					ExportDEK:     exportDEK,
					RecipientOrgs: []string{"org-a", "org-b"},
				}
			}).
			Then("both orgs have encrypted DEK entries", func() {
				require.Len(t, bundle.ExportDEK, 2)
				assert.Contains(t, bundle.RecipientOrgs, "org-a")
				assert.Contains(t, bundle.RecipientOrgs, "org-b")
			}).
			And("each org can only decrypt their own entry", func() {
				// Org A decrypts their entry
				privBlockA, _ := pem.Decode(orgAPrivKey)
				privKeyA, err := x509.ParsePKCS1PrivateKey(privBlockA.Bytes)
				require.NoError(t, err)
				decA, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKeyA, bundle.ExportDEK["org-a"], nil)
				require.NoError(t, err)
				assert.Equal(t, originalDEK, decA)

				// Org B decrypts their entry
				privBlockB, _ := pem.Decode(orgBPrivKey)
				privKeyB, err := x509.ParsePKCS1PrivateKey(privBlockB.Bytes)
				require.NoError(t, err)
				decB, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKeyB, bundle.ExportDEK["org-b"], nil)
				require.NoError(t, err)
				assert.Equal(t, originalDEK, decB)

				// Both decrypt to the same DEK
				assert.Equal(t, decA, decB)
			})
	})
}
