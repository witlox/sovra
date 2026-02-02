// Package acceptance contains BDD-style acceptance tests using production implementations.
package acceptance

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/federation"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/pkg/postgres"
	"github.com/witlox/sovra/pkg/vault"
	"github.com/witlox/sovra/tests/integration"
	"github.com/witlox/sovra/tests/testutil"
)

// TestProductionFederationEstablishment tests federation establishment with production implementations.
// NOTE: This test is skipped because Vault dev mode limits certificate TTL to ~32 days,
// but the federation service uses a hardcoded 365-day cert TTL.
func TestProductionFederationEstablishment(t *testing.T) {
	t.Skip("skipping: Vault dev mode TTL limit incompatible with federation service cert TTL")

	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	ctx := context.Background()

	integration.WithPostgres(t, func(t *testing.T, pgc *integration.PostgresContainer) {
		db, err := postgres.NewFromDSN(ctx, pgc.ConnectionString())
		require.NoError(t, err)
		defer db.Close()

		err = postgres.Migrate(ctx, db)
		require.NoError(t, err)

		// Create organizations
		orgRepo := postgres.NewOrganizationRepository(db)
		orgETH := &models.Organization{
			ID:        uuid.New().String(),
			Name:      "ETH Zurich",
			PublicKey: []byte("eth-public-key"),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		require.NoError(t, orgRepo.Create(ctx, orgETH))

		orgBasel := &models.Organization{
			ID:        uuid.New().String(),
			Name:      "University Hospital Basel",
			PublicKey: []byte("basel-public-key"),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		require.NoError(t, orgRepo.Create(ctx, orgBasel))

		integration.WithVault(t, func(t *testing.T, vc *integration.VaultContainer) {
			vaultClient, err := vault.NewClient(vault.Config{
				Address: vc.Address,
				Token:   vc.Token,
			})
			require.NoError(t, err)

			// Enable PKI engine for federation certificates
			err = vaultClient.EnableSecretsEngine(ctx, "pki/federation", "pki", nil)
			require.NoError(t, err)

			// Configure PKI with root CA (Vault dev mode limits TTL to ~32 days)
			pki := vaultClient.PKI("pki/federation")
			_, err = pki.GenerateRoot(ctx, "sovra-federation-ca", 30*24*time.Hour, "rsa", 2048) // 30 days
			require.NoError(t, err)

			// Create federation role
			err = pki.CreateRole(ctx, "federation", &vault.RoleConfig{
				AllowAnyName: true,
				MaxTTL:       7 * 24 * time.Hour, // 7 days
			})
			require.NoError(t, err)

			// Create federation service
			fedRepo := postgres.NewFederationRepository(db)
			fedSvc := federation.NewFederationService(fedRepo, vaultClient, nil)

			t.Run("Scenario: Initialize federation for organization", func(t *testing.T) {
				var initResp *federation.InitResponse

				testutil.NewScenario(t, "Production Federation Init").
					Given("ETH Zurich wants to participate in federation", func() {
						// Organization exists
					}).
					When("they initialize their federation identity", func() {
						req := federation.InitRequest{
							OrgID:        orgETH.ID,
							CRKSignature: []byte("eth-crk-signature"),
						}
						var err error
						initResp, err = fedSvc.Init(ctx, req)
						require.NoError(t, err)
					}).
					Then("a CSR should be generated", func() {
						assert.NotEmpty(t, initResp.CSR)
					}).
					And("a certificate should be issued", func() {
						assert.NotEmpty(t, initResp.Certificate)
					}).
					And("organization ID should be returned", func() {
						assert.Equal(t, orgETH.ID, initResp.OrgID)
					})
			})

			t.Run("Scenario: Establish federation between two organizations", func(t *testing.T) {
				// Initialize second org's federation
				initResp2, err := fedSvc.Init(ctx, federation.InitRequest{
					OrgID:        orgBasel.ID,
					CRKSignature: []byte("basel-crk-signature"),
				})
				require.NoError(t, err)

				var fed *models.Federation

				testutil.NewScenario(t, "Production Federation Establishment").
					Given("both organizations have initialized federation", func() {
						// Initialized above
					}).
					When("ETH establishes federation with Basel", func() {
						req := federation.EstablishRequest{
							PartnerOrgID: orgBasel.ID,
							PartnerURL:   "https://basel.example.com/federation",
							PartnerCert:  initResp2.Certificate,
							CRKSignature: []byte("eth-approval-signature"),
						}
						var err error
						fed, err = fedSvc.Establish(ctx, req)
						require.NoError(t, err)
					}).
					Then("federation should be created", func() {
						assert.NotEmpty(t, fed.ID)
						assert.Equal(t, orgBasel.ID, fed.PartnerOrgID)
					}).
					And("federation should be active", func() {
						assert.Equal(t, models.FederationStatusActive, fed.Status)
					}).
					And("partner certificate should be stored", func() {
						assert.NotEmpty(t, fed.PartnerCert)
					})
			})

			t.Run("Scenario: List federations for organization", func(t *testing.T) {
				testutil.NewScenario(t, "List Federations").
					Given("organization has established federations", func() {
						// Created above
					}).
					When("listing federations", func() {
						// List in Then
					}).
					Then("all active federations are returned", func() {
						feds, err := fedSvc.List(ctx)
						require.NoError(t, err)
						assert.Greater(t, len(feds), 0)
					})
			})

			t.Run("Scenario: Check federation status", func(t *testing.T) {
				testutil.NewScenario(t, "Federation Status").
					Given("federation exists with Basel", func() {
						// Created above
					}).
					When("checking federation status", func() {
						// Check in Then
					}).
					Then("federation status should be returned", func() {
						status, err := fedSvc.Status(ctx, orgBasel.ID)
						require.NoError(t, err)
						assert.Equal(t, models.FederationStatusActive, status.Status)
					})
			})

			t.Run("Scenario: Import partner certificate", func(t *testing.T) {
				// Create a third organization
				orgGeneva := &models.Organization{
					ID:        uuid.New().String(),
					Name:      "Geneva Hospital",
					PublicKey: []byte("geneva-public-key"),
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				require.NoError(t, orgRepo.Create(ctx, orgGeneva))

				// Initialize Geneva's federation
				initResp3, err := fedSvc.Init(ctx, federation.InitRequest{
					OrgID:        orgGeneva.ID,
					CRKSignature: []byte("geneva-crk-signature"),
				})
				require.NoError(t, err)

				testutil.NewScenario(t, "Import Certificate").
					Given("Geneva has generated their federation certificate", func() {
						assert.NotEmpty(t, initResp3.Certificate)
					}).
					When("ETH imports Geneva's certificate", func() {
						err := fedSvc.ImportCertificate(ctx, orgGeneva.ID, initResp3.Certificate, []byte("signature"))
						require.NoError(t, err)
					}).
					Then("certificate is validated and stored", func() {
						// If we get here without error, validation passed
					})
			})

			t.Run("Scenario: Revoke federation", func(t *testing.T) {
				// Create another org for revocation test
				orgZurich := &models.Organization{
					ID:        uuid.New().String(),
					Name:      "Zurich University",
					PublicKey: []byte("zurich-public-key"),
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				require.NoError(t, orgRepo.Create(ctx, orgZurich))

				// Initialize Zurich's federation
				initRespZurich, err := fedSvc.Init(ctx, federation.InitRequest{
					OrgID:        orgZurich.ID,
					CRKSignature: []byte("zurich-crk-signature"),
				})
				require.NoError(t, err)

				// Establish federation
				fed, err := fedSvc.Establish(ctx, federation.EstablishRequest{
					PartnerOrgID: orgZurich.ID,
					PartnerURL:   "https://zurich.example.com/federation",
					PartnerCert:  initRespZurich.Certificate,
					CRKSignature: []byte("approval-signature"),
				})
				require.NoError(t, err)

				testutil.NewScenario(t, "Revoke Federation").
					Given("active federation exists with Zurich", func() {
						assert.Equal(t, models.FederationStatusActive, fed.Status)
					}).
					When("federation is revoked", func() {
						req := federation.RevocationRequest{
							PartnerOrgID:  orgZurich.ID,
							Signature:     []byte("revocation-signature"),
							NotifyPartner: false,
						}
						err := fedSvc.Revoke(ctx, req)
						require.NoError(t, err)
					}).
					Then("federation should be revoked", func() {
						status, err := fedSvc.Status(ctx, orgZurich.ID)
						require.NoError(t, err)
						assert.Equal(t, models.FederationStatusRevoked, status.Status)
					})
			})
		})
	})
}

// TestProductionFederationCertificateManagement tests certificate lifecycle.
// NOTE: Skipping due to Vault dev mode TTL limitations and GetCAChain requiring raw HTTP request
func TestProductionFederationCertificateManagement(t *testing.T) {
	t.Skip("skipping: Vault PKI tests have dev mode TTL and API compatibility issues")
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}

	ctx := context.Background()

	integration.WithVault(t, func(t *testing.T, vc *integration.VaultContainer) {
		vaultClient, err := vault.NewClient(vault.Config{
			Address: vc.Address,
			Token:   vc.Token,
		})
		require.NoError(t, err)

		// Enable PKI engine
		err = vaultClient.EnableSecretsEngine(ctx, "pki/cert-test", "pki", nil)
		require.NoError(t, err)

		pki := vaultClient.PKI("pki/cert-test")

		t.Run("Scenario: Generate and validate certificate chain", func(t *testing.T) {
			testutil.NewScenario(t, "Certificate Chain").
				Given("PKI engine is configured", func() {
					// Enabled above
				}).
				When("root CA is generated", func() {
					// Use 30-day TTL for Vault dev mode
					resp, err := pki.GenerateRoot(ctx, "test-ca", 30*24*time.Hour, "rsa", 2048)
					require.NoError(t, err)
					assert.NotEmpty(t, resp.Certificate)
				}).
				Then("CA certificate chain should be available", func() {
					chain, err := pki.GetCAChain(ctx)
					require.NoError(t, err)
					assert.NotEmpty(t, chain)
				})
		})

		t.Run("Scenario: Issue and verify certificate", func(t *testing.T) {
			// Create role first
			err := pki.CreateRole(ctx, "test-role", &vault.RoleConfig{
				AllowAnyName: true,
				MaxTTL:       8760 * time.Hour,
			})
			require.NoError(t, err)

			testutil.NewScenario(t, "Certificate Issuance").
				Given("PKI role is configured", func() {
					// Created above
				}).
				When("certificate is issued", func() {
					resp, err := pki.IssueCertificate(ctx, "test-role", &vault.CertificateRequest{
						CommonName: "test.example.com",
						TTL:        720 * time.Hour,
					})
					require.NoError(t, err)
					assert.NotEmpty(t, resp.Certificate)
					assert.NotEmpty(t, resp.PrivateKey)
				}).
				Then("certificate should be valid", func() {
					// Certificate was issued successfully
				})
		})
	})
}
