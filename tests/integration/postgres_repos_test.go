// Package integration contains integration tests with real infrastructure.
package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/witlox/sovra/internal/audit"
	"github.com/witlox/sovra/pkg/models"
	"github.com/witlox/sovra/pkg/postgres"
)

// TestPostgresRepositoriesIntegration tests all postgres repositories.
func TestPostgresRepositoriesIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	WithPostgres(t, func(t *testing.T, pgc *PostgresContainer) {
		// Create database connection using NewFromDSN
		ctx := context.Background()
		db, err := postgres.NewFromDSN(ctx, pgc.ConnectionString())
		require.NoError(t, err)
		defer db.Close()

		// Run migrations
		err = postgres.Migrate(ctx, db)
		require.NoError(t, err)

		t.Run("organization_repository", func(t *testing.T) {
			repo := postgres.NewOrganizationRepository(db)

			t.Run("create and get organization", func(t *testing.T) {
				org := &models.Organization{
					ID:        uuid.New().String(),
					Name:      "Test Organization",
					PublicKey: []byte("test-public-key"),
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}

				err := repo.Create(ctx, org)
				require.NoError(t, err)

				retrieved, err := repo.Get(ctx, org.ID)
				require.NoError(t, err)
				assert.Equal(t, org.Name, retrieved.Name)
			})

			t.Run("update organization", func(t *testing.T) {
				org := &models.Organization{
					ID:        uuid.New().String(),
					Name:      "Original Name",
					PublicKey: []byte("key"),
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				err := repo.Create(ctx, org)
				require.NoError(t, err)

				org.Name = "Updated Name"
				org.UpdatedAt = time.Now()
				err = repo.Update(ctx, org)
				require.NoError(t, err)

				retrieved, err := repo.Get(ctx, org.ID)
				require.NoError(t, err)
				assert.Equal(t, "Updated Name", retrieved.Name)
			})

			t.Run("delete organization", func(t *testing.T) {
				org := &models.Organization{
					ID:        uuid.New().String(),
					Name:      "To Delete",
					PublicKey: []byte("key"),
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				err := repo.Create(ctx, org)
				require.NoError(t, err)

				err = repo.Delete(ctx, org.ID)
				require.NoError(t, err)

				_, err = repo.Get(ctx, org.ID)
				require.Error(t, err)
			})
		})

		t.Run("workspace_repository", func(t *testing.T) {
			// First create an organization for the workspace
			orgRepo := postgres.NewOrganizationRepository(db)
			org := &models.Organization{
				ID:        uuid.New().String(),
				Name:      "Workspace Test Org",
				PublicKey: []byte("key"),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			err := orgRepo.Create(ctx, org)
			require.NoError(t, err)

			repo := postgres.NewWorkspaceRepository(db)

			t.Run("create and get workspace", func(t *testing.T) {
				ws := &models.Workspace{
					ID:              uuid.New().String(),
					Name:            "Test Workspace",
					OwnerOrgID:      org.ID,
					ParticipantOrgs: []string{org.ID},
					Classification:  models.ClassificationConfidential,
					Mode:            models.WorkspaceModeConnected,
					Status:          models.WorkspaceStatusActive,
					DEKWrapped:      map[string][]byte{org.ID: []byte("wrapped-dek")},
					CreatedAt:       time.Now(),
					UpdatedAt:       time.Now(),
				}

				err := repo.Create(ctx, ws)
				require.NoError(t, err)

				retrieved, err := repo.Get(ctx, ws.ID)
				require.NoError(t, err)
				assert.Equal(t, ws.Name, retrieved.Name)
				assert.Equal(t, ws.OwnerOrgID, retrieved.OwnerOrgID)
			})

			t.Run("list workspaces by org", func(t *testing.T) {
				// Create multiple workspaces
				for i := 0; i < 3; i++ {
					ws := &models.Workspace{
						ID:              uuid.New().String(),
						Name:            "List Test WS",
						OwnerOrgID:      org.ID,
						ParticipantOrgs: []string{org.ID},
						Classification:  models.ClassificationConfidential,
						Status:          models.WorkspaceStatusActive,
						DEKWrapped:      map[string][]byte{},
						CreatedAt:       time.Now(),
						UpdatedAt:       time.Now(),
					}
					_ = repo.Create(ctx, ws)
				}

				workspaces, err := repo.List(ctx, org.ID, 100, 0)
				require.NoError(t, err)
				assert.GreaterOrEqual(t, len(workspaces), 3)
			})

			t.Run("update workspace", func(t *testing.T) {
				ws := &models.Workspace{
					ID:              uuid.New().String(),
					Name:            "Original WS",
					OwnerOrgID:      org.ID,
					ParticipantOrgs: []string{org.ID},
					Classification:  models.ClassificationConfidential,
					Status:          models.WorkspaceStatusActive,
					DEKWrapped:      map[string][]byte{},
					CreatedAt:       time.Now(),
					UpdatedAt:       time.Now(),
				}
				err := repo.Create(ctx, ws)
				require.NoError(t, err)

				ws.Name = "Updated WS"
				ws.Status = models.WorkspaceStatusArchived
				ws.UpdatedAt = time.Now()
				err = repo.Update(ctx, ws)
				require.NoError(t, err)

				retrieved, err := repo.Get(ctx, ws.ID)
				require.NoError(t, err)
				assert.Equal(t, "Updated WS", retrieved.Name)
				assert.Equal(t, models.WorkspaceStatusArchived, retrieved.Status)
			})

			t.Run("delete workspace", func(t *testing.T) {
				ws := &models.Workspace{
					ID:              uuid.New().String(),
					Name:            "To Delete WS",
					OwnerOrgID:      org.ID,
					ParticipantOrgs: []string{org.ID},
					Classification:  models.ClassificationConfidential,
					Status:          models.WorkspaceStatusActive,
					DEKWrapped:      map[string][]byte{},
					CreatedAt:       time.Now(),
					UpdatedAt:       time.Now(),
				}
				err := repo.Create(ctx, ws)
				require.NoError(t, err)

				err = repo.Delete(ctx, ws.ID)
				require.NoError(t, err)

				_, err = repo.Get(ctx, ws.ID)
				require.Error(t, err)
			})
		})

		t.Run("policy_repository", func(t *testing.T) {
			// Create org and workspace for policies
			orgRepo := postgres.NewOrganizationRepository(db)
			org := &models.Organization{
				ID:        uuid.New().String(),
				Name:      "Policy Test Org",
				PublicKey: []byte("key"),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			_ = orgRepo.Create(ctx, org)

			wsRepo := postgres.NewWorkspaceRepository(db)
			ws := &models.Workspace{
				ID:             uuid.New().String(),
				Name:           "Policy Test Workspace",
				OwnerOrgID:     org.ID,
				Classification: models.ClassificationSecret,
				Status:         models.WorkspaceStatusActive,
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
			}
			_ = wsRepo.Create(ctx, ws)

			repo := postgres.NewPolicyRepository(db)

			t.Run("create and get policy", func(t *testing.T) {
				p := &models.Policy{
					ID:          uuid.New().String(),
					Name:        "Test Policy",
					WorkspaceID: ws.ID,
					Rego:        "package test\ndefault allow = true",
					Version:     1,
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
				}

				err := repo.Create(ctx, p)
				require.NoError(t, err)

				retrieved, err := repo.Get(ctx, p.ID)
				require.NoError(t, err)
				assert.Equal(t, p.Name, retrieved.Name)
				assert.Equal(t, p.Rego, retrieved.Rego)
			})

			t.Run("get policies for workspace", func(t *testing.T) {
				// Create another workspace for this subtest
				wsForList := &models.Workspace{
					ID:             uuid.New().String(),
					Name:           "List Test Workspace",
					OwnerOrgID:     org.ID,
					Classification: models.ClassificationSecret,
					Status:         models.WorkspaceStatusActive,
					CreatedAt:      time.Now(),
					UpdatedAt:      time.Now(),
				}
				_ = wsRepo.Create(ctx, wsForList)

				for i := 0; i < 3; i++ {
					p := &models.Policy{
						ID:          uuid.New().String(),
						Name:        "WS Policy",
						WorkspaceID: wsForList.ID,
						Rego:        "package test\ndefault allow = true",
						Version:     1,
						CreatedAt:   time.Now(),
						UpdatedAt:   time.Now(),
					}
					_ = repo.Create(ctx, p)
				}

				policies, err := repo.GetByWorkspace(ctx, wsForList.ID)
				require.NoError(t, err)
				assert.Len(t, policies, 3)
			})

			t.Run("update policy", func(t *testing.T) {
				p := &models.Policy{
					ID:          uuid.New().String(),
					Name:        "Update Policy",
					WorkspaceID: ws.ID,
					Rego:        "package test\ndefault allow = false",
					Version:     1,
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
				}
				err := repo.Create(ctx, p)
				require.NoError(t, err)

				p.Rego = "package test\ndefault allow = true"
				p.Version = 2
				p.UpdatedAt = time.Now()
				err = repo.Update(ctx, p)
				require.NoError(t, err)

				retrieved, err := repo.Get(ctx, p.ID)
				require.NoError(t, err)
				assert.Contains(t, retrieved.Rego, "default allow = true")
				assert.Equal(t, 2, retrieved.Version)
			})

			t.Run("delete policy", func(t *testing.T) {
				p := &models.Policy{
					ID:          uuid.New().String(),
					Name:        "Delete Policy",
					WorkspaceID: ws.ID,
					Rego:        "package test",
					Version:     1,
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
				}
				err := repo.Create(ctx, p)
				require.NoError(t, err)

				err = repo.Delete(ctx, p.ID)
				require.NoError(t, err)

				_, err = repo.Get(ctx, p.ID)
				require.Error(t, err)
			})
		})

		t.Run("audit_repository", func(t *testing.T) {
			repo := postgres.NewAuditRepository(db)

			t.Run("create and query audit event", func(t *testing.T) {
				event := &models.AuditEvent{
					ID:        uuid.New().String(),
					Timestamp: time.Now(),
					OrgID:     uuid.New().String(),
					Workspace: uuid.New().String(),
					EventType: models.AuditEventTypeEncrypt,
					Actor:     "user@example.com",
					Result:    models.AuditEventResultSuccess,
					Purpose:   "data analysis",
					Metadata:  map[string]any{"key": "value"},
				}

				err := repo.Create(ctx, event)
				require.NoError(t, err)

				// Get by ID
				retrieved, err := repo.Get(ctx, event.ID)
				require.NoError(t, err)
				assert.Equal(t, event.ID, retrieved.ID)
				assert.Equal(t, event.EventType, retrieved.EventType)
			})
		})

		t.Run("federation_repository", func(t *testing.T) {
			// Create orgs for federation
			orgRepo := postgres.NewOrganizationRepository(db)
			org1 := &models.Organization{
				ID:        uuid.New().String(),
				Name:      "Fed Org 1",
				PublicKey: []byte("key1"),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			org2 := &models.Organization{
				ID:        uuid.New().String(),
				Name:      "Fed Org 2",
				PublicKey: []byte("key2"),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			_ = orgRepo.Create(ctx, org1)
			_ = orgRepo.Create(ctx, org2)

			repo := postgres.NewFederationRepository(db)

			t.Run("create and get federation", func(t *testing.T) {
				fed := &models.Federation{
					ID:           uuid.New().String(),
					OrgID:        org1.ID,
					PartnerOrgID: org2.ID,
					PartnerURL:   "https://partner.example.com",
					Status:       models.FederationStatusActive,
					CreatedAt:    time.Now(),
				}

				err := repo.Create(ctx, fed)
				require.NoError(t, err)

				retrieved, err := repo.Get(ctx, fed.ID)
				require.NoError(t, err)
				assert.Equal(t, fed.OrgID, retrieved.OrgID)
				assert.Equal(t, fed.PartnerOrgID, retrieved.PartnerOrgID)
			})

			t.Run("list federations", func(t *testing.T) {
				federations, err := repo.List(ctx, org1.ID)
				require.NoError(t, err)
				assert.GreaterOrEqual(t, len(federations), 1)
			})

			t.Run("update federation status", func(t *testing.T) {
				fed := &models.Federation{
					ID:           uuid.New().String(),
					OrgID:        org1.ID,
					PartnerOrgID: org2.ID,
					PartnerURL:   "https://partner2.example.com",
					Status:       models.FederationStatusPending,
					CreatedAt:    time.Now(),
				}
				err := repo.Create(ctx, fed)
				require.NoError(t, err)

				fed.Status = models.FederationStatusActive
				err = repo.Update(ctx, fed)
				require.NoError(t, err)

				retrieved, err := repo.Get(ctx, fed.ID)
				require.NoError(t, err)
				assert.Equal(t, models.FederationStatusActive, retrieved.Status)
			})
		})

		t.Run("edge_repository", func(t *testing.T) {
			// Create org for edge
			orgRepo := postgres.NewOrganizationRepository(db)
			org := &models.Organization{
				ID:        uuid.New().String(),
				Name:      "Edge Org",
				PublicKey: []byte("key"),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			_ = orgRepo.Create(ctx, org)

			repo := postgres.NewEdgeNodeRepository(db)

			t.Run("create and get edge node", func(t *testing.T) {
				node := &models.EdgeNode{
					ID:            uuid.New().String(),
					Name:          "Edge Node 1",
					OrgID:         org.ID,
					VaultAddress:  "https://edge1.example.com",
					Certificate:   []byte("edge-cert"),
					Status:        models.EdgeNodeStatusHealthy,
					LastHeartbeat: time.Now(),
				}

				err := repo.Create(ctx, node)
				require.NoError(t, err)

				retrieved, err := repo.Get(ctx, node.ID)
				require.NoError(t, err)
				assert.Equal(t, node.Name, retrieved.Name)
				assert.Equal(t, node.VaultAddress, retrieved.VaultAddress)
			})

			t.Run("list edge nodes by org", func(t *testing.T) {
				nodes, err := repo.GetByOrgID(ctx, org.ID)
				require.NoError(t, err)
				assert.GreaterOrEqual(t, len(nodes), 1)
			})

			t.Run("update edge node status", func(t *testing.T) {
				node := &models.EdgeNode{
					ID:            uuid.New().String(),
					Name:          "Edge Update",
					OrgID:         org.ID,
					VaultAddress:  "https://edge2.example.com",
					Certificate:   []byte("key"),
					Status:        models.EdgeNodeStatusHealthy,
					LastHeartbeat: time.Now(),
				}
				err := repo.Create(ctx, node)
				require.NoError(t, err)

				node.Status = models.EdgeNodeStatusUnhealthy
				err = repo.Update(ctx, node)
				require.NoError(t, err)

				retrieved, err := repo.Get(ctx, node.ID)
				require.NoError(t, err)
				assert.Equal(t, models.EdgeNodeStatusUnhealthy, retrieved.Status)
			})

			t.Run("delete edge node", func(t *testing.T) {
				node := &models.EdgeNode{
					ID:            uuid.New().String(),
					Name:          "Edge Delete",
					OrgID:         org.ID,
					VaultAddress:  "https://edge3.example.com",
					Certificate:   []byte("cert"),
					Status:        models.EdgeNodeStatusHealthy,
					LastHeartbeat: time.Now(),
				}
				err := repo.Create(ctx, node)
				require.NoError(t, err)

				err = repo.Delete(ctx, node.ID)
				require.NoError(t, err)

				_, err = repo.Get(ctx, node.ID)
				require.Error(t, err)
			})
		})

		t.Run("crk_repository", func(t *testing.T) {
			// Create org for CRK
			orgRepo := postgres.NewOrganizationRepository(db)
			org := &models.Organization{
				ID:        uuid.New().String(),
				Name:      "CRK Org",
				PublicKey: []byte("key"),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			_ = orgRepo.Create(ctx, org)

			repo := postgres.NewCRKRepository(db)

			t.Run("create and get CRK", func(t *testing.T) {
				crk := &models.CRK{
					ID:          uuid.New().String(),
					OrgID:       org.ID,
					PublicKey:   []byte("crk-public-key"),
					Version:     1,
					Threshold:   3,
					TotalShares: 5,
					Status:      models.CRKStatusActive,
					CreatedAt:   time.Now(),
				}

				err := repo.Create(ctx, crk)
				require.NoError(t, err)

				retrieved, err := repo.Get(ctx, crk.ID)
				require.NoError(t, err)
				assert.Equal(t, crk.OrgID, retrieved.OrgID)
				assert.Equal(t, crk.Version, retrieved.Version)
			})

			t.Run("get CRK by org ID", func(t *testing.T) {
				crk := &models.CRK{
					ID:          uuid.New().String(),
					OrgID:       org.ID,
					PublicKey:   []byte("crk-public-key-2"),
					Version:     2,
					Threshold:   3,
					TotalShares: 5,
					Status:      models.CRKStatusActive,
					CreatedAt:   time.Now(),
				}
				_ = repo.Create(ctx, crk)

				retrieved, err := repo.GetByOrgID(ctx, org.ID)
				require.NoError(t, err)
				assert.Equal(t, org.ID, retrieved.OrgID)
			})

			t.Run("update CRK status", func(t *testing.T) {
				crk := &models.CRK{
					ID:          uuid.New().String(),
					OrgID:       org.ID,
					PublicKey:   []byte("crk-public-key-3"),
					Version:     3,
					Threshold:   3,
					TotalShares: 5,
					Status:      models.CRKStatusActive,
					CreatedAt:   time.Now(),
				}
				err := repo.Create(ctx, crk)
				require.NoError(t, err)

				crk.Status = models.CRKStatusRotating
				err = repo.Update(ctx, crk)
				require.NoError(t, err)

				retrieved, err := repo.Get(ctx, crk.ID)
				require.NoError(t, err)
				assert.Equal(t, models.CRKStatusRotating, retrieved.Status)
			})

			t.Run("create and get shares", func(t *testing.T) {
				crk := &models.CRK{
					ID:          uuid.New().String(),
					OrgID:       org.ID,
					PublicKey:   []byte("crk-share-key"),
					Version:     4,
					Threshold:   3,
					TotalShares: 5,
					Status:      models.CRKStatusActive,
					CreatedAt:   time.Now(),
				}
				err := repo.Create(ctx, crk)
				require.NoError(t, err)

				// Create shares
				share := &models.CRKShare{
					ID:          uuid.New().String(),
					CRKID:       crk.ID,
					Index:       1,
					Data:        []byte("encrypted-share-1"),
					CustodianID: "holder-1",
					CreatedAt:   time.Now(),
				}
				err = repo.CreateShare(ctx, share)
				require.NoError(t, err)

				// Get shares
				shares, err := repo.GetShares(ctx, crk.ID)
				require.NoError(t, err)
				assert.GreaterOrEqual(t, len(shares), 1)
			})

			t.Run("delete CRK", func(t *testing.T) {
				crk := &models.CRK{
					ID:          uuid.New().String(),
					OrgID:       org.ID,
					PublicKey:   []byte("crk-delete-key"),
					Version:     5,
					Threshold:   3,
					TotalShares: 5,
					Status:      models.CRKStatusActive,
					CreatedAt:   time.Now(),
				}
				err := repo.Create(ctx, crk)
				require.NoError(t, err)

				err = repo.Delete(ctx, crk.ID)
				require.NoError(t, err)

				_, err = repo.Get(ctx, crk.ID)
				require.Error(t, err)
			})
		})

		t.Run("organization_list", func(t *testing.T) {
			repo := postgres.NewOrganizationRepository(db)

			// Create some orgs for listing
			for i := 0; i < 3; i++ {
				org := &models.Organization{
					ID:        uuid.New().String(),
					Name:      "List Org",
					PublicKey: []byte("key"),
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				_ = repo.Create(ctx, org)
			}

			orgs, err := repo.List(ctx, 100, 0)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, len(orgs), 3)
		})

		t.Run("workspace_additional_methods", func(t *testing.T) {
			orgRepo := postgres.NewOrganizationRepository(db)
			org := &models.Organization{
				ID:        uuid.New().String(),
				Name:      "WS Methods Org",
				PublicKey: []byte("key"),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			_ = orgRepo.Create(ctx, org)

			repo := postgres.NewWorkspaceRepository(db)

			t.Run("get workspace by name", func(t *testing.T) {
				ws := &models.Workspace{
					ID:              uuid.New().String(),
					Name:            "unique-ws-name-" + uuid.New().String(),
					OwnerOrgID:      org.ID,
					ParticipantOrgs: []string{org.ID},
					Classification:  models.ClassificationConfidential,
					Status:          models.WorkspaceStatusActive,
					DEKWrapped:      map[string][]byte{},
					CreatedAt:       time.Now(),
					UpdatedAt:       time.Now(),
				}
				err := repo.Create(ctx, ws)
				require.NoError(t, err)

				retrieved, err := repo.GetByName(ctx, ws.Name)
				require.NoError(t, err)
				assert.Equal(t, ws.ID, retrieved.ID)
			})

			t.Run("list workspaces by participant", func(t *testing.T) {
				// Use existing org as participant
				ws := &models.Workspace{
					ID:              uuid.New().String(),
					Name:            "participant-ws-" + uuid.New().String(),
					OwnerOrgID:      org.ID,
					ParticipantOrgs: []string{org.ID},
					Classification:  models.ClassificationConfidential,
					Status:          models.WorkspaceStatusActive,
					DEKWrapped:      map[string][]byte{},
					CreatedAt:       time.Now(),
					UpdatedAt:       time.Now(),
				}
				_ = repo.Create(ctx, ws)

				// Query by the org ID that's in participants
				workspaces, err := repo.ListByParticipant(ctx, org.ID)
				require.NoError(t, err)
				assert.GreaterOrEqual(t, len(workspaces), 1)
			})
		})

		t.Run("federation_additional_methods", func(t *testing.T) {
			orgRepo := postgres.NewOrganizationRepository(db)
			org1 := &models.Organization{
				ID:        uuid.New().String(),
				Name:      "Fed Methods Org1",
				PublicKey: []byte("key"),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			org2 := &models.Organization{
				ID:        uuid.New().String(),
				Name:      "Fed Methods Org2",
				PublicKey: []byte("key"),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			_ = orgRepo.Create(ctx, org1)
			_ = orgRepo.Create(ctx, org2)

			repo := postgres.NewFederationRepository(db)

			t.Run("get federation by partner", func(t *testing.T) {
				fed := &models.Federation{
					ID:           uuid.New().String(),
					OrgID:        org1.ID,
					PartnerOrgID: org2.ID,
					PartnerURL:   "https://partner-getby.example.com",
					Status:       models.FederationStatusActive,
					CreatedAt:    time.Now(),
				}
				err := repo.Create(ctx, fed)
				require.NoError(t, err)

				retrieved, err := repo.GetByPartner(ctx, org1.ID, org2.ID)
				require.NoError(t, err)
				assert.Equal(t, fed.ID, retrieved.ID)
			})

			t.Run("delete federation", func(t *testing.T) {
				fed := &models.Federation{
					ID:           uuid.New().String(),
					OrgID:        org1.ID,
					PartnerOrgID: org2.ID,
					PartnerURL:   "https://partner-delete.example.com",
					Status:       models.FederationStatusActive,
					CreatedAt:    time.Now(),
				}
				err := repo.Create(ctx, fed)
				require.NoError(t, err)

				err = repo.Delete(ctx, fed.ID)
				require.NoError(t, err)

				_, err = repo.Get(ctx, fed.ID)
				require.Error(t, err)
			})
		})

		t.Run("policy_additional_methods", func(t *testing.T) {
			orgRepo := postgres.NewOrganizationRepository(db)
			org := &models.Organization{
				ID:        uuid.New().String(),
				Name:      "Policy Methods Org",
				PublicKey: []byte("key"),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			_ = orgRepo.Create(ctx, org)

			wsRepo := postgres.NewWorkspaceRepository(db)
			ws := &models.Workspace{
				ID:              uuid.New().String(),
				Name:            "policy-methods-ws-" + uuid.New().String(),
				OwnerOrgID:      org.ID,
				ParticipantOrgs: []string{org.ID},
				Classification:  models.ClassificationSecret,
				Status:          models.WorkspaceStatusActive,
				DEKWrapped:      map[string][]byte{},
				CreatedAt:       time.Now(),
				UpdatedAt:       time.Now(),
			}
			_ = wsRepo.Create(ctx, ws)

			repo := postgres.NewPolicyRepository(db)

			t.Run("get organization policies", func(t *testing.T) {
				// Create policy with org_id but no workspace_id
				p := &models.Policy{
					ID:    uuid.New().String(),
					Name:  "Org-Level Policy",
					OrgID: org.ID, // Set org ID
					// No WorkspaceID - this is an org-level policy
					Rego:      "package org\ndefault allow = true",
					Version:   1,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				_ = repo.Create(ctx, p)

				policies, err := repo.GetOrganizationPolicies(ctx, org.ID)
				require.NoError(t, err)
				assert.GreaterOrEqual(t, len(policies), 1)
			})

			t.Run("list all policies", func(t *testing.T) {
				policies, err := repo.List(ctx, 100, 0)
				require.NoError(t, err)
				assert.GreaterOrEqual(t, len(policies), 1)
			})
		})

		t.Run("audit_additional_methods", func(t *testing.T) {
			orgRepo := postgres.NewOrganizationRepository(db)
			org := &models.Organization{
				ID:        uuid.New().String(),
				Name:      "Audit Methods Org",
				PublicKey: []byte("key"),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			_ = orgRepo.Create(ctx, org)

			repo := postgres.NewAuditRepository(db)

			t.Run("query audit events", func(t *testing.T) {
				// Create some events first
				for i := 0; i < 3; i++ {
					event := &models.AuditEvent{
						ID:        uuid.New().String(),
						EventType: models.AuditEventTypeWorkspaceCreate,
						OrgID:     org.ID,
						Actor:     "actor-1",
						Timestamp: time.Now(),
						Result:    models.AuditEventResultSuccess,
						Metadata:  map[string]any{"index": i},
					}
					_ = repo.Create(ctx, event)
				}

				events, err := repo.Query(ctx, audit.QueryParams{OrgID: org.ID, Limit: 100})
				require.NoError(t, err)
				assert.GreaterOrEqual(t, len(events), 3)
			})

			t.Run("count audit events", func(t *testing.T) {
				count, err := repo.Count(ctx, audit.QueryParams{OrgID: org.ID})
				require.NoError(t, err)
				assert.GreaterOrEqual(t, count, int64(3))
			})
		})

		t.Run("db_additional_methods", func(t *testing.T) {
			t.Run("health check", func(t *testing.T) {
				err := db.HealthCheck(ctx)
				require.NoError(t, err)
			})

			t.Run("current migration version", func(t *testing.T) {
				version, err := postgres.CurrentVersion(ctx, db.DB)
				require.NoError(t, err)
				assert.GreaterOrEqual(t, version, 1)
			})

			t.Run("transaction with error", func(t *testing.T) {
				err := db.WithTx(ctx, func(tx *postgres.Tx) error {
					return assert.AnError
				})
				require.Error(t, err)
			})
		})
	})
}
