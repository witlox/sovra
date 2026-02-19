// Package main implements the sovra-cli command-line tool.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/witlox/sovra/internal/crk"
	"github.com/witlox/sovra/pkg/client"
	"github.com/witlox/sovra/pkg/models"
)

var version = "dev"

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// getClient creates an API client from the command flags.
func getClient(cmd *cobra.Command) *client.Client {
	apiURL, _ := cmd.Root().PersistentFlags().GetString("api-url")
	orgID, _ := cmd.Root().PersistentFlags().GetString("org-id")
	token := os.Getenv("SOVRA_TOKEN")

	return client.New(client.Config{
		BaseURL: apiURL,
		Token:   token,
		OrgID:   orgID,
		Timeout: 30 * time.Second,
	})
}

var rootCmd = &cobra.Command{
	Use:     "sovra-cli",
	Short:   "Sovra CLI - Federated Key Management",
	Long:    `Sovra CLI provides command-line access to Sovra federated key management operations.`,
	Version: version,
}

func init() {
	// Add subcommands
	rootCmd.AddCommand(crkCmd)
	rootCmd.AddCommand(workspaceCmd)
	rootCmd.AddCommand(federationCmd)
	rootCmd.AddCommand(policyCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(identityCmd)
	rootCmd.AddCommand(edgeCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)

	// Global flags
	rootCmd.PersistentFlags().String("config", "", "Config file path")
	rootCmd.PersistentFlags().String("org-id", "", "Organization ID")
	rootCmd.PersistentFlags().String("api-url", "http://localhost:8080", "API Gateway URL")
	rootCmd.PersistentFlags().Bool("json", false, "Output in JSON format")
}

// ============================================================================
// CRK Commands
// ============================================================================

var crkCmd = &cobra.Command{
	Use:   "crk",
	Short: "Customer Root Key management",
	Long:  `Manage Customer Root Keys (CRK) including generation, signing, and verification.`,
}

var crkGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new CRK with Shamir shares",
	RunE:  runCRKGenerate,
}

var crkSignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign data using CRK shares",
	RunE:  runCRKSign,
}

var crkVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a signature against CRK public key",
	RunE:  runCRKVerify,
}

func init() {
	// CRK generate flags
	crkGenerateCmd.Flags().Int("shares", 5, "Total number of shares")
	crkGenerateCmd.Flags().Int("threshold", 3, "Threshold required to reconstruct")
	crkGenerateCmd.Flags().String("output", "", "Output file for shares (default: stdout)")

	// CRK sign flags
	crkSignCmd.Flags().String("shares-file", "", "JSON file containing shares")
	crkSignCmd.Flags().String("public-key", "", "Public key (base64)")
	crkSignCmd.Flags().String("data", "", "Data to sign (or use stdin)")
	crkSignCmd.Flags().String("data-file", "", "File containing data to sign")

	// CRK verify flags
	crkVerifyCmd.Flags().String("public-key", "", "Public key (base64)")
	crkVerifyCmd.Flags().String("signature", "", "Signature (base64)")
	crkVerifyCmd.Flags().String("data", "", "Original data")
	crkVerifyCmd.Flags().String("data-file", "", "File containing original data")

	// CRK ceremony start flags
	crkCeremonyStartCmd.Flags().Int("shares", 5, "Total number of shares")
	crkCeremonyStartCmd.Flags().Int("threshold", 3, "Threshold required to reconstruct")

	// CRK ceremony add-share flags
	crkCeremonyAddShareCmd.Flags().String("share-file", "", "JSON file containing the share")
	crkCeremonyAddShareCmd.Flags().String("share-data", "", "Base64-encoded share data")
	crkCeremonyAddShareCmd.Flags().Int("share-index", 0, "Share index")

	crkCeremonyCmd.AddCommand(crkCeremonyStartCmd)
	crkCeremonyCmd.AddCommand(crkCeremonyAddShareCmd)
	crkCeremonyCmd.AddCommand(crkCeremonyCompleteCmd)
	crkCeremonyCmd.AddCommand(crkCeremonyCancelCmd)

	crkRotateCmd.Flags().Int("threshold", 3, "Threshold for rotation ceremony")

	crkCmd.AddCommand(crkGenerateCmd)
	crkCmd.AddCommand(crkSignCmd)
	crkCmd.AddCommand(crkVerifyCmd)
	crkCmd.AddCommand(crkCeremonyCmd)
	crkCmd.AddCommand(crkRotateCmd)
}

func runCRKGenerate(cmd *cobra.Command, args []string) error {
	orgID, _ := cmd.Flags().GetString("org-id")
	if orgID == "" {
		orgID, _ = cmd.Root().PersistentFlags().GetString("org-id")
	}
	if orgID == "" {
		return fmt.Errorf("--org-id is required")
	}

	shares, _ := cmd.Flags().GetInt("shares")
	threshold, _ := cmd.Flags().GetInt("threshold")
	output, _ := cmd.Flags().GetString("output")

	// Generate CRK
	manager := crk.NewManager()
	crkKey, err := manager.Generate(orgID, shares, threshold)
	if err != nil {
		return fmt.Errorf("failed to generate CRK: %w", err)
	}

	// Get shares
	shareList, err := manager.GetShares(crkKey.ID)
	if err != nil {
		return fmt.Errorf("failed to get shares: %w", err)
	}

	// Build output
	result := struct {
		OrgID     string            `json:"org_id"`
		CRKID     string            `json:"crk_id"`
		PublicKey string            `json:"public_key"`
		Shares    int               `json:"total_shares"`
		Threshold int               `json:"threshold"`
		ShareData []models.CRKShare `json:"shares"`
	}{
		OrgID:     orgID,
		CRKID:     crkKey.ID,
		PublicKey: fmt.Sprintf("%x", crkKey.PublicKey),
		Shares:    shares,
		Threshold: threshold,
		ShareData: shareList,
	}

	// Output (JSON format for both modes)
	data, _ := json.MarshalIndent(result, "", "  ")

	if output != "" {
		if err := os.WriteFile(output, data, 0600); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		fmt.Printf("CRK generated successfully. Shares written to %s\n", output)
		fmt.Printf("Public Key: %s\n", result.PublicKey)
	} else {
		fmt.Println(string(data))
	}

	return nil
}

func runCRKSign(cmd *cobra.Command, args []string) error {
	sharesFile, _ := cmd.Flags().GetString("shares-file")
	pubKey, _ := cmd.Flags().GetString("public-key")
	data, _ := cmd.Flags().GetString("data")
	dataFile, _ := cmd.Flags().GetString("data-file")

	if sharesFile == "" {
		return fmt.Errorf("--shares-file is required")
	}
	if pubKey == "" {
		return fmt.Errorf("--public-key is required")
	}

	// Read data
	var dataBytes []byte
	if dataFile != "" {
		var err error
		dataBytes, err = os.ReadFile(dataFile)
		if err != nil {
			return fmt.Errorf("failed to read data file: %w", err)
		}
	} else if data != "" {
		dataBytes = []byte(data)
	} else {
		return fmt.Errorf("--data or --data-file is required")
	}

	// Read shares
	sharesData, err := os.ReadFile(sharesFile)
	if err != nil {
		return fmt.Errorf("failed to read shares file: %w", err)
	}

	var sharesInput struct {
		Shares []models.CRKShare `json:"shares"`
	}
	if err := json.Unmarshal(sharesData, &sharesInput); err != nil {
		return fmt.Errorf("failed to parse shares: %w", err)
	}

	// Decode public key
	var pubKeyBytes []byte
	if _, err := fmt.Sscanf(pubKey, "%x", &pubKeyBytes); err != nil {
		return fmt.Errorf("invalid public key format: %w", err)
	}

	// Sign
	manager := crk.NewManager()
	signature, err := manager.Sign(sharesInput.Shares, pubKeyBytes, dataBytes)
	if err != nil {
		return fmt.Errorf("failed to sign: %w", err)
	}

	fmt.Printf("%x\n", signature)
	return nil
}

func runCRKVerify(cmd *cobra.Command, args []string) error {
	pubKey, _ := cmd.Flags().GetString("public-key")
	sig, _ := cmd.Flags().GetString("signature")
	data, _ := cmd.Flags().GetString("data")
	dataFile, _ := cmd.Flags().GetString("data-file")

	if pubKey == "" || sig == "" {
		return fmt.Errorf("--public-key and --signature are required")
	}

	// Read data
	var dataBytes []byte
	if dataFile != "" {
		var err error
		dataBytes, err = os.ReadFile(dataFile)
		if err != nil {
			return fmt.Errorf("failed to read data file: %w", err)
		}
	} else if data != "" {
		dataBytes = []byte(data)
	} else {
		return fmt.Errorf("--data or --data-file is required")
	}

	// Decode
	var pubKeyBytes, sigBytes []byte
	if _, err := fmt.Sscanf(pubKey, "%x", &pubKeyBytes); err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	if _, err := fmt.Sscanf(sig, "%x", &sigBytes); err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	// Verify
	manager := crk.NewManager()
	valid, err := manager.Verify(pubKeyBytes, dataBytes, sigBytes)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	if valid {
		fmt.Println("Signature is VALID")
		return nil
	}
	fmt.Println("Signature is INVALID")
	os.Exit(1)
	return nil
}

// CRK Ceremony Commands

var crkCeremonyCmd = &cobra.Command{
	Use:   "ceremony",
	Short: "CRK ceremony management",
	Long:  `Manage CRK ceremonies for key generation and rotation.`,
}

var crkCeremonyStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start a CRK ceremony",
	RunE: func(cmd *cobra.Command, args []string) error {
		orgID, _ := cmd.Root().PersistentFlags().GetString("org-id")
		if orgID == "" {
			return fmt.Errorf("--org-id is required")
		}

		shares, _ := cmd.Flags().GetInt("shares")
		threshold, _ := cmd.Flags().GetInt("threshold")

		c := getClient(cmd)
		ctx := context.Background()

		resp, err := c.StartCRKCeremony(ctx, orgID, shares, threshold)
		if err != nil {
			return fmt.Errorf("start ceremony: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(resp, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Ceremony started: %s\nStatus: %s\nThreshold: %d\nCollected: %d\n",
				resp.ID, resp.Status, resp.Threshold, resp.Collected)
		}
		return nil
	},
}

var crkCeremonyAddShareCmd = &cobra.Command{
	Use:   "add-share [ceremony-id]",
	Short: "Add a share to a CRK ceremony",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		shareFile, _ := cmd.Flags().GetString("share-file")
		shareData, _ := cmd.Flags().GetString("share-data")
		shareIndex, _ := cmd.Flags().GetInt("share-index")

		var share models.CRKShare
		if shareFile != "" {
			content, err := os.ReadFile(shareFile)
			if err != nil {
				return fmt.Errorf("read share file: %w", err)
			}
			if err := json.Unmarshal(content, &share); err != nil {
				return fmt.Errorf("parse share file: %w", err)
			}
		} else if shareData != "" {
			decoded, err := base64.StdEncoding.DecodeString(shareData)
			if err != nil {
				return fmt.Errorf("decode share data: %w", err)
			}
			share = models.CRKShare{
				Index: shareIndex,
				Data:  decoded,
			}
		} else {
			return fmt.Errorf("--share-file or --share-data is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		resp, err := c.AddCRKShare(ctx, args[0], share)
		if err != nil {
			return fmt.Errorf("add share: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(resp, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Share added to ceremony %s\nStatus: %s\nCollected: %d/%d\n",
				resp.ID, resp.Status, resp.Collected, resp.Threshold)
		}
		return nil
	},
}

var crkCeremonyCompleteCmd = &cobra.Command{
	Use:   "complete [ceremony-id]",
	Short: "Complete a CRK ceremony",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		resp, err := c.CompleteCRKCeremony(ctx, args[0])
		if err != nil {
			return fmt.Errorf("complete ceremony: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(resp, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Ceremony completed: %s\nStatus: %s\n", resp.ID, resp.Status)
		}
		return nil
	},
}

var crkCeremonyCancelCmd = &cobra.Command{
	Use:   "cancel [ceremony-id]",
	Short: "Cancel a CRK ceremony",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		if err := c.CancelCRKCeremony(ctx, args[0]); err != nil {
			return fmt.Errorf("cancel ceremony: %w", err)
		}

		fmt.Printf("Ceremony cancelled: %s\n", args[0])
		return nil
	},
}

var crkRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate the CRK (starts a rotation ceremony)",
	RunE: func(cmd *cobra.Command, args []string) error {
		threshold, _ := cmd.Flags().GetInt("threshold")

		c := getClient(cmd)
		ctx := context.Background()

		resp, err := c.RotateCRK(ctx, client.RotateCRKRequest{Threshold: threshold})
		if err != nil {
			return fmt.Errorf("rotate CRK: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(resp, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("CRK rotation ceremony started: %s\nStatus: %s\nThreshold: %d\n",
				resp.ID, resp.Status, resp.Threshold)
		}
		return nil
	},
}

// ============================================================================
// Workspace Commands
// ============================================================================

var workspaceCmd = &cobra.Command{
	Use:   "workspace",
	Short: "Workspace management",
	Long:  `Manage shared cryptographic workspaces between organizations.`,
}

var workspaceCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new workspace",
	RunE:  runWorkspaceCreate,
}

var workspaceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List workspaces",
	RunE:  runWorkspaceList,
}

var workspaceGetCmd = &cobra.Command{
	Use:   "get [workspace-id]",
	Short: "Get workspace details",
	Args:  cobra.ExactArgs(1),
	RunE:  runWorkspaceGet,
}

func init() {
	workspaceCreateCmd.Flags().String("name", "", "Workspace name")
	workspaceCreateCmd.Flags().StringSlice("participants", nil, "Participant organization IDs")
	workspaceCreateCmd.Flags().String("classification", "CONFIDENTIAL", "Data classification")
	workspaceCreateCmd.Flags().String("purpose", "", "Workspace purpose")

	workspaceListCmd.Flags().Int("limit", 50, "Maximum results")
	workspaceListCmd.Flags().Int("offset", 0, "Result offset")

	workspaceUpdateCmd.Flags().String("purpose", "", "New workspace purpose")
	workspaceUpdateCmd.Flags().String("classification", "", "New data classification")
	workspaceUpdateCmd.Flags().String("mode", "", "New workspace mode")

	workspaceExtendCmd.Flags().String("expires-at", "", "New expiration time (RFC3339)")

	workspaceInviteCmd.Flags().String("org-id", "", "Organization ID to invite")

	workspaceDeleteCmd.Flags().String("org-id", "", "Organization ID for signature")

	workspaceAcceptInvitationCmd.Flags().String("org-id", "", "Organization ID")

	workspaceDeclineInvitationCmd.Flags().String("org-id", "", "Organization ID")

	workspaceAddParticipantCmd.Flags().String("org-id", "", "Organization ID to add")

	workspaceRemoveParticipantCmd.Flags().String("org-id", "", "Organization ID to remove")

	workspaceCmd.AddCommand(workspaceCreateCmd)
	workspaceCmd.AddCommand(workspaceListCmd)
	workspaceCmd.AddCommand(workspaceGetCmd)
	workspaceCmd.AddCommand(workspaceUpdateCmd)
	workspaceCmd.AddCommand(workspaceRotateDEKCmd)
	workspaceCmd.AddCommand(workspaceExtendCmd)
	workspaceCmd.AddCommand(workspaceInviteCmd)
	workspaceCmd.AddCommand(workspaceDeleteCmd)
	workspaceCmd.AddCommand(workspaceAcceptInvitationCmd)
	workspaceCmd.AddCommand(workspaceDeclineInvitationCmd)
	workspaceCmd.AddCommand(workspaceAddParticipantCmd)
	workspaceCmd.AddCommand(workspaceRemoveParticipantCmd)
	workspaceCmd.AddCommand(workspaceArchiveCmd)
}

func runWorkspaceCreate(cmd *cobra.Command, args []string) error {
	name, _ := cmd.Flags().GetString("name")
	participants, _ := cmd.Flags().GetStringSlice("participants")
	classification, _ := cmd.Flags().GetString("classification")
	purpose, _ := cmd.Flags().GetString("purpose")

	if name == "" {
		return fmt.Errorf("--name is required")
	}
	if len(participants) == 0 {
		return fmt.Errorf("--participants is required")
	}

	c := getClient(cmd)
	ctx := context.Background()

	ws, err := c.CreateWorkspace(ctx, client.WorkspaceCreateRequest{
		Name:           name,
		Participants:   participants,
		Classification: models.Classification(classification),
		Purpose:        purpose,
	})
	if err != nil {
		return fmt.Errorf("create workspace: %w", err)
	}

	jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
	if jsonOutput {
		data, _ := json.MarshalIndent(ws, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("Workspace created: %s (%s)\n", ws.Name, ws.ID)
	}
	return nil
}

func runWorkspaceList(cmd *cobra.Command, args []string) error {
	limit, _ := cmd.Flags().GetInt("limit")
	offset, _ := cmd.Flags().GetInt("offset")

	c := getClient(cmd)
	ctx := context.Background()

	workspaces, err := c.ListWorkspaces(ctx, limit, offset)
	if err != nil {
		return fmt.Errorf("list workspaces: %w", err)
	}

	jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
	if jsonOutput {
		data, _ := json.MarshalIndent(workspaces, "", "  ")
		fmt.Println(string(data))
	} else {
		for _, ws := range workspaces {
			fmt.Printf("%s  %s  %s\n", ws.ID, ws.Name, ws.Status)
		}
	}
	return nil
}

func runWorkspaceGet(cmd *cobra.Command, args []string) error {
	c := getClient(cmd)
	ctx := context.Background()

	ws, err := c.GetWorkspace(ctx, args[0])
	if err != nil {
		return fmt.Errorf("get workspace: %w", err)
	}

	jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
	if jsonOutput {
		data, _ := json.MarshalIndent(ws, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("ID: %s\nName: %s\nOwner: %s\nStatus: %s\nParticipants: %v\n",
			ws.ID, ws.Name, ws.OwnerOrgID, ws.Status, ws.ParticipantOrgs)
	}
	return nil
}

var workspaceUpdateCmd = &cobra.Command{
	Use:   "update [workspace-id]",
	Short: "Update a workspace",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		purpose, _ := cmd.Flags().GetString("purpose")
		classification, _ := cmd.Flags().GetString("classification")
		mode, _ := cmd.Flags().GetString("mode")

		req := client.UpdateWorkspaceRequest{}
		if purpose != "" {
			req.Purpose = purpose
		}
		if classification != "" {
			req.Classification = models.Classification(classification)
		}
		if mode != "" {
			req.Mode = models.WorkspaceMode(mode)
		}

		c := getClient(cmd)
		ctx := context.Background()

		ws, err := c.UpdateWorkspace(ctx, args[0], req)
		if err != nil {
			return fmt.Errorf("update workspace: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(ws, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Workspace updated: %s (%s)\n", ws.Name, ws.ID)
		}
		return nil
	},
}

var workspaceRotateDEKCmd = &cobra.Command{
	Use:   "rotate-dek [workspace-id]",
	Short: "Rotate the DEK for a workspace",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		if err := c.RotateWorkspaceDEK(ctx, args[0], nil); err != nil {
			return fmt.Errorf("rotate DEK: %w", err)
		}

		fmt.Printf("DEK rotated for workspace: %s\n", args[0])
		return nil
	},
}

var workspaceExtendCmd = &cobra.Command{
	Use:   "extend [workspace-id]",
	Short: "Extend workspace expiration",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		expiresAt, _ := cmd.Flags().GetString("expires-at")
		if expiresAt == "" {
			return fmt.Errorf("--expires-at is required (RFC3339 format)")
		}

		t, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return fmt.Errorf("invalid --expires-at format (expected RFC3339): %w", err)
		}

		c := getClient(cmd)
		ctx := context.Background()

		if err := c.ExtendWorkspace(ctx, args[0], t, nil); err != nil {
			return fmt.Errorf("extend workspace: %w", err)
		}

		fmt.Printf("Workspace %s extended to %s\n", args[0], t.Format(time.RFC3339))
		return nil
	},
}

var workspaceInviteCmd = &cobra.Command{
	Use:   "invite [workspace-id]",
	Short: "Invite an organization to a workspace",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		orgID, _ := cmd.Flags().GetString("org-id")
		if orgID == "" {
			return fmt.Errorf("--org-id is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		invitation, err := c.InviteParticipant(ctx, args[0], client.InviteParticipantRequest{OrgID: orgID})
		if err != nil {
			return fmt.Errorf("invite participant: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(invitation, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Invitation created: %s\nWorkspace: %s\nOrg: %s\nStatus: %s\nExpires: %s\n",
				invitation.ID, invitation.WorkspaceID, invitation.OrgID, invitation.Status, invitation.ExpiresAt.Format(time.RFC3339))
		}
		return nil
	},
}

var workspaceDeleteCmd = &cobra.Command{
	Use:   "delete [workspace-id]",
	Short: "Delete a workspace",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		if err := c.DeleteWorkspace(ctx, args[0], client.DeleteWorkspaceRequest{}); err != nil {
			return fmt.Errorf("delete workspace: %w", err)
		}

		fmt.Printf("Workspace deleted: %s\n", args[0])
		return nil
	},
}

var workspaceAcceptInvitationCmd = &cobra.Command{
	Use:   "accept-invitation [workspace-id]",
	Short: "Accept a workspace invitation",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		orgID, _ := cmd.Flags().GetString("org-id")
		if orgID == "" {
			return fmt.Errorf("--org-id is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		if err := c.AcceptInvitation(ctx, args[0], client.AcceptInvitationRequest{OrgID: orgID}); err != nil {
			return fmt.Errorf("accept invitation: %w", err)
		}

		fmt.Printf("Invitation accepted for workspace: %s\n", args[0])
		return nil
	},
}

var workspaceDeclineInvitationCmd = &cobra.Command{
	Use:   "decline-invitation [workspace-id]",
	Short: "Decline a workspace invitation",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		orgID, _ := cmd.Flags().GetString("org-id")
		if orgID == "" {
			return fmt.Errorf("--org-id is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		if err := c.DeclineInvitation(ctx, args[0], client.DeclineInvitationRequest{OrgID: orgID}); err != nil {
			return fmt.Errorf("decline invitation: %w", err)
		}

		fmt.Printf("Invitation declined for workspace: %s\n", args[0])
		return nil
	},
}

var workspaceAddParticipantCmd = &cobra.Command{
	Use:   "add-participant [workspace-id]",
	Short: "Add a participant to a workspace",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		orgID, _ := cmd.Flags().GetString("org-id")
		if orgID == "" {
			return fmt.Errorf("--org-id is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		if err := c.AddParticipant(ctx, args[0], client.AddParticipantRequest{OrgID: orgID}); err != nil {
			return fmt.Errorf("add participant: %w", err)
		}

		fmt.Printf("Participant %s added to workspace %s\n", orgID, args[0])
		return nil
	},
}

var workspaceRemoveParticipantCmd = &cobra.Command{
	Use:   "remove-participant [workspace-id]",
	Short: "Remove a participant from a workspace",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		orgID, _ := cmd.Flags().GetString("org-id")
		if orgID == "" {
			return fmt.Errorf("--org-id is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		if err := c.RemoveParticipant(ctx, args[0], orgID, client.RemoveParticipantRequest{}); err != nil {
			return fmt.Errorf("remove participant: %w", err)
		}

		fmt.Printf("Participant %s removed from workspace %s\n", orgID, args[0])
		return nil
	},
}

var workspaceArchiveCmd = &cobra.Command{
	Use:   "archive [workspace-id]",
	Short: "Archive a workspace",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		if err := c.ArchiveWorkspace(ctx, args[0], client.ArchiveWorkspaceRequest{}); err != nil {
			return fmt.Errorf("archive workspace: %w", err)
		}

		fmt.Printf("Workspace archived: %s\n", args[0])
		return nil
	},
}

// ============================================================================
// Federation Commands
// ============================================================================

var federationCmd = &cobra.Command{
	Use:   "federation",
	Short: "Federation management",
	Long:  `Manage federation relationships with partner organizations.`,
}

var federationListCmd = &cobra.Command{
	Use:   "list",
	Short: "List federation partners",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		federations, err := c.ListFederations(ctx)
		if err != nil {
			return fmt.Errorf("list federations: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(federations, "", "  ")
			fmt.Println(string(data))
		} else {
			for _, fed := range federations {
				fmt.Printf("%s  %s  %s\n", fed.ID, fed.PartnerOrgID, fed.Status)
			}
		}
		return nil
	},
}

var federationStatusCmd = &cobra.Command{
	Use:   "status [partner-org-id]",
	Short: "Get federation status",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		fed, err := c.GetFederationStatus(ctx, args[0])
		if err != nil {
			return fmt.Errorf("get federation status: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(fed, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Partner: %s\nStatus: %s\nEstablished: %s\n",
				fed.PartnerOrgID, fed.Status, fed.EstablishedAt.Format(time.RFC3339))
		}
		return nil
	},
}

var federationInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize federation for the organization",
	RunE: func(cmd *cobra.Command, args []string) error {
		orgID, _ := cmd.Root().PersistentFlags().GetString("org-id")
		if orgID == "" {
			return fmt.Errorf("--org-id is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		resp, err := c.InitFederation(ctx, client.InitFederationRequest{OrgID: orgID})
		if err != nil {
			return fmt.Errorf("init federation: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(resp, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Federation initialized for org: %s\n", resp.OrgID)
		}
		return nil
	},
}

var federationEstablishCmd = &cobra.Command{
	Use:   "establish",
	Short: "Establish federation with a partner",
	RunE: func(cmd *cobra.Command, args []string) error {
		partnerOrg, _ := cmd.Flags().GetString("partner-org")
		partnerURL, _ := cmd.Flags().GetString("partner-url")

		if partnerOrg == "" || partnerURL == "" {
			return fmt.Errorf("--partner-org and --partner-url are required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		fed, err := c.EstablishFederation(ctx, client.EstablishFederationRequest{
			PartnerOrgID: partnerOrg,
			PartnerURL:   partnerURL,
		})
		if err != nil {
			return fmt.Errorf("establish federation: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(fed, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Federation established with: %s\nStatus: %s\n", fed.PartnerOrgID, fed.Status)
		}
		return nil
	},
}

var federationRevokeCmd = &cobra.Command{
	Use:   "revoke [partner-org-id]",
	Short: "Revoke federation with a partner",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		if err := c.RevokeFederation(ctx, args[0], client.RevokeFederationRequest{
			NotifyPartner: true,
			RevokeCerts:   true,
		}); err != nil {
			return fmt.Errorf("revoke federation: %w", err)
		}

		fmt.Printf("Federation revoked: %s\n", args[0])
		return nil
	},
}

var federationHealthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check federation partner health",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		resp, err := c.FederationHealth(ctx)
		if err != nil {
			return fmt.Errorf("federation health: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(resp, "", "  ")
			fmt.Println(string(data))
		} else {
			for _, r := range resp.Results {
				status := "healthy"
				if !r.Healthy {
					status = "unhealthy"
				}
				fmt.Printf("%s  %s", r.PartnerOrgID, status)
				if r.Error != "" {
					fmt.Printf("  error=%s", r.Error)
				}
				fmt.Println()
			}
		}
		return nil
	},
}

var federationImportCertCmd = &cobra.Command{
	Use:   "import-cert",
	Short: "Import a federation partner certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		partnerOrg, _ := cmd.Flags().GetString("partner-org")
		certFile, _ := cmd.Flags().GetString("cert-file")

		if partnerOrg == "" || certFile == "" {
			return fmt.Errorf("--partner-org and --cert-file are required")
		}

		certData, err := os.ReadFile(certFile)
		if err != nil {
			return fmt.Errorf("read certificate file: %w", err)
		}

		c := getClient(cmd)
		ctx := context.Background()

		if err := c.ImportFederationCertificate(ctx, client.ImportFederationCertificateRequest{
			PartnerOrgID: partnerOrg,
			Certificate:  certData,
		}); err != nil {
			return fmt.Errorf("import certificate: %w", err)
		}

		fmt.Printf("Certificate imported for partner: %s\n", partnerOrg)
		return nil
	},
}

func init() {
	federationEstablishCmd.Flags().String("partner-org", "", "Partner organization ID")
	federationEstablishCmd.Flags().String("partner-url", "", "Partner API URL")

	federationImportCertCmd.Flags().String("partner-org", "", "Partner organization ID")
	federationImportCertCmd.Flags().String("cert-file", "", "Certificate file path")

	federationCmd.AddCommand(federationListCmd)
	federationCmd.AddCommand(federationStatusCmd)
	federationCmd.AddCommand(federationInitCmd)
	federationCmd.AddCommand(federationEstablishCmd)
	federationCmd.AddCommand(federationRevokeCmd)
	federationCmd.AddCommand(federationHealthCmd)
	federationCmd.AddCommand(federationImportCertCmd)
}

// ============================================================================
// Policy Commands
// ============================================================================

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Policy management",
	Long:  `Manage OPA Rego policies for access control.`,
}

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List policies for a workspace",
	RunE: func(cmd *cobra.Command, args []string) error {
		workspace, _ := cmd.Flags().GetString("workspace")
		if workspace == "" {
			return fmt.Errorf("--workspace is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		resp, err := c.GetPoliciesForWorkspace(ctx, workspace)
		if err != nil {
			return fmt.Errorf("list policies: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(resp, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Found %d policies:\n", resp.Count)
			for _, p := range resp.Policies {
				fmt.Printf("%s  %s  v%d  %s\n", p.ID, p.Name, p.Version, p.UpdatedAt.Format(time.RFC3339))
			}
		}
		return nil
	},
}

var policyGetCmd = &cobra.Command{
	Use:   "get [policy-id]",
	Short: "Get policy details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		policy, err := c.GetPolicy(ctx, args[0])
		if err != nil {
			return fmt.Errorf("get policy: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(policy, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("ID: %s\nName: %s\nWorkspace: %s\nVersion: %d\nUpdated: %s\n---\n%s\n",
				policy.ID, policy.Name, policy.WorkspaceID, policy.Version, policy.UpdatedAt.Format(time.RFC3339), policy.Rego)
		}
		return nil
	},
}

var policyCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new policy",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		regoFile, _ := cmd.Flags().GetString("rego-file")
		workspace, _ := cmd.Flags().GetString("workspace")

		if name == "" || regoFile == "" || workspace == "" {
			return fmt.Errorf("--name, --rego-file, and --workspace are required")
		}

		rego, err := os.ReadFile(regoFile)
		if err != nil {
			return fmt.Errorf("read rego file: %w", err)
		}

		c := getClient(cmd)
		ctx := context.Background()

		policy, err := c.CreatePolicy(ctx, client.CreatePolicyRequest{
			Name:      name,
			Workspace: workspace,
			Rego:      string(rego),
		})
		if err != nil {
			return fmt.Errorf("create policy: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(policy, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Policy created: %s (%s)\n", policy.Name, policy.ID)
		}
		return nil
	},
}

var policyUpdateCmd = &cobra.Command{
	Use:   "update [policy-id]",
	Short: "Update a policy",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		regoFile, _ := cmd.Flags().GetString("rego-file")
		if regoFile == "" {
			return fmt.Errorf("--rego-file is required")
		}

		rego, err := os.ReadFile(regoFile)
		if err != nil {
			return fmt.Errorf("read rego file: %w", err)
		}

		c := getClient(cmd)
		ctx := context.Background()

		policy, err := c.UpdatePolicy(ctx, args[0], client.UpdatePolicyRequest{
			Rego: string(rego),
		})
		if err != nil {
			return fmt.Errorf("update policy: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(policy, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Policy updated: %s (v%d)\n", policy.Name, policy.Version)
		}
		return nil
	},
}

var policyDeleteCmd = &cobra.Command{
	Use:   "delete [policy-id]",
	Short: "Delete a policy",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		if err := c.DeletePolicy(ctx, args[0], client.DeletePolicyRequest{}); err != nil {
			return fmt.Errorf("delete policy: %w", err)
		}

		fmt.Printf("Policy deleted: %s\n", args[0])
		return nil
	},
}

var policyEvaluateCmd = &cobra.Command{
	Use:   "evaluate",
	Short: "Evaluate a policy",
	RunE: func(cmd *cobra.Command, args []string) error {
		workspace, _ := cmd.Flags().GetString("workspace")
		inputFile, _ := cmd.Flags().GetString("input-file")

		if workspace == "" || inputFile == "" {
			return fmt.Errorf("--workspace and --input-file are required")
		}

		inputData, err := os.ReadFile(inputFile)
		if err != nil {
			return fmt.Errorf("read input file: %w", err)
		}

		var req client.EvaluatePolicyRequest
		if err := json.Unmarshal(inputData, &req); err != nil {
			return fmt.Errorf("parse input file: %w", err)
		}
		req.Workspace = workspace

		c := getClient(cmd)
		ctx := context.Background()

		result, err := c.EvaluatePolicy(ctx, req)
		if err != nil {
			return fmt.Errorf("evaluate policy: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
		} else {
			if result.Allowed {
				fmt.Println("Result: ALLOWED")
			} else {
				fmt.Printf("Result: DENIED\nReason: %s\n", result.DenyReason)
			}
			if result.PolicyID != "" {
				fmt.Printf("Policy: %s\n", result.PolicyID)
			}
		}
		return nil
	},
}

var policyValidateCmd = &cobra.Command{
	Use:   "validate [rego-file]",
	Short: "Validate a Rego policy",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		content, err := os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}

		c := getClient(cmd)
		ctx := context.Background()

		result, err := c.ValidatePolicy(ctx, client.ValidatePolicyRequest{Rego: string(content)})
		if err != nil {
			return fmt.Errorf("validate policy: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
		} else {
			if result.Valid {
				fmt.Println("Policy syntax: OK")
			} else {
				fmt.Printf("Policy syntax: INVALID\nError: %s\n", result.Error)
			}
		}
		return nil
	},
}

func init() {
	policyListCmd.Flags().String("workspace", "", "Workspace ID")

	policyCreateCmd.Flags().String("name", "", "Policy name")
	policyCreateCmd.Flags().String("rego-file", "", "Path to Rego policy file")
	policyCreateCmd.Flags().String("workspace", "", "Workspace ID")

	policyUpdateCmd.Flags().String("rego-file", "", "Path to Rego policy file")

	policyEvaluateCmd.Flags().String("workspace", "", "Workspace ID")
	policyEvaluateCmd.Flags().String("input-file", "", "JSON input file for evaluation")

	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyGetCmd)
	policyCmd.AddCommand(policyCreateCmd)
	policyCmd.AddCommand(policyUpdateCmd)
	policyCmd.AddCommand(policyDeleteCmd)
	policyCmd.AddCommand(policyEvaluateCmd)
	policyCmd.AddCommand(policyValidateCmd)
}

// ============================================================================
// Audit Commands
// ============================================================================

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit log management",
	Long:  `Query and export audit logs.`,
}

var auditQueryCmd = &cobra.Command{
	Use:   "query",
	Short: "Query audit events",
	RunE: func(cmd *cobra.Command, args []string) error {
		since, _ := cmd.Flags().GetString("since")
		until, _ := cmd.Flags().GetString("until")
		eventType, _ := cmd.Flags().GetString("event-type")
		limit, _ := cmd.Flags().GetInt("limit")

		c := getClient(cmd)
		ctx := context.Background()

		events, err := c.QueryAudit(ctx, client.AuditQueryParams{
			Since:     since,
			Until:     until,
			EventType: eventType,
			Limit:     limit,
		})
		if err != nil {
			return fmt.Errorf("query audit: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(events, "", "  ")
			fmt.Println(string(data))
		} else {
			for _, ev := range events {
				fmt.Printf("%s  %s  %s  %s  %s\n",
					ev.Timestamp.Format(time.RFC3339), ev.EventType, ev.Actor, ev.Result, ev.Workspace)
			}
		}
		return nil
	},
}

var auditExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export audit logs",
	RunE: func(cmd *cobra.Command, args []string) error {
		since, _ := cmd.Flags().GetString("since")
		until, _ := cmd.Flags().GetString("until")
		format, _ := cmd.Flags().GetString("format")
		output, _ := cmd.Flags().GetString("output")

		c := getClient(cmd)
		ctx := context.Background()

		data, err := c.ExportAudit(ctx, client.ExportAuditRequest{
			Since:  since,
			Until:  until,
			Format: format,
		})
		if err != nil {
			return fmt.Errorf("export audit: %w", err)
		}

		if output != "" {
			if err := os.WriteFile(output, data, 0644); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
			fmt.Printf("Exported audit logs to %s\n", output)
		} else {
			fmt.Println(string(data))
		}
		return nil
	},
}

var auditGetCmd = &cobra.Command{
	Use:   "get [event-id]",
	Short: "Get audit event details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		event, err := c.GetAuditEvent(ctx, args[0])
		if err != nil {
			return fmt.Errorf("get audit event: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(event, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("ID: %s\nTimestamp: %s\nType: %s\nActor: %s\nResult: %s\nWorkspace: %s\n",
				event.ID, event.Timestamp.Format(time.RFC3339), event.EventType, event.Actor, event.Result, event.Workspace)
		}
		return nil
	},
}

var auditStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Get audit statistics",
	RunE: func(cmd *cobra.Command, args []string) error {
		since, _ := cmd.Flags().GetString("since")

		c := getClient(cmd)
		ctx := context.Background()

		stats, err := c.GetAuditStats(ctx, since)
		if err != nil {
			return fmt.Errorf("get audit stats: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(stats, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Total Events: %d\nSuccess: %d\nErrors: %d\nDenied: %d\nUnique Actors: %d\n",
				stats.TotalEvents, stats.SuccessCount, stats.ErrorCount, stats.DeniedCount, stats.UniqueActors)
		}
		return nil
	},
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify audit log integrity",
	RunE: func(cmd *cobra.Command, args []string) error {
		since, _ := cmd.Flags().GetString("since")
		until, _ := cmd.Flags().GetString("until")

		c := getClient(cmd)
		ctx := context.Background()

		result, err := c.VerifyAuditIntegrity(ctx, client.VerifyAuditIntegrityRequest{
			Since: since,
			Until: until,
		})
		if err != nil {
			return fmt.Errorf("verify audit integrity: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
		} else {
			if result.Valid {
				fmt.Println("Audit integrity: VALID")
			} else {
				fmt.Println("Audit integrity: INVALID")
			}
			if result.Since != "" {
				fmt.Printf("Range: %s to %s\n", result.Since, result.Until)
			}
		}
		return nil
	},
}

func init() {
	auditQueryCmd.Flags().String("since", "", "Start time (RFC3339)")
	auditQueryCmd.Flags().String("until", "", "End time (RFC3339)")
	auditQueryCmd.Flags().String("event-type", "", "Filter by event type")
	auditQueryCmd.Flags().Int("limit", 100, "Maximum results")

	auditExportCmd.Flags().String("format", "json", "Export format (json, csv)")
	auditExportCmd.Flags().String("output", "", "Output file")
	auditExportCmd.Flags().String("since", "", "Start time (RFC3339)")
	auditExportCmd.Flags().String("until", "", "End time (RFC3339)")

	auditStatsCmd.Flags().String("since", "", "Start time (RFC3339)")

	auditVerifyCmd.Flags().String("since", "", "Start time (RFC3339)")
	auditVerifyCmd.Flags().String("until", "", "End time (RFC3339)")

	auditCmd.AddCommand(auditQueryCmd)
	auditCmd.AddCommand(auditExportCmd)
	auditCmd.AddCommand(auditGetCmd)
	auditCmd.AddCommand(auditStatsCmd)
	auditCmd.AddCommand(auditVerifyCmd)
}

// ============================================================================
// Identity Commands
// ============================================================================

var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Identity management",
	Long:  `Manage admin, user, service, and device identities.`,
}

var identityListCmd = &cobra.Command{
	Use:   "list",
	Short: "List identities",
	RunE: func(cmd *cobra.Command, args []string) error {
		idType, _ := cmd.Flags().GetString("type")
		if idType == "" {
			return fmt.Errorf("--type is required (admin, user, service, device)")
		}

		c := getClient(cmd)
		ctx := context.Background()
		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")

		switch idType {
		case "admin":
			admins, err := c.ListAdmins(ctx)
			if err != nil {
				return fmt.Errorf("list admins: %w", err)
			}
			if jsonOutput {
				data, _ := json.MarshalIndent(admins, "", "  ")
				fmt.Println(string(data))
			} else {
				for _, a := range admins {
					fmt.Printf("%s  %s  %s  %s  active=%v\n", a.ID, a.Email, a.Name, a.Role, a.Active)
				}
			}
		case "user":
			users, err := c.ListUsers(ctx)
			if err != nil {
				return fmt.Errorf("list users: %w", err)
			}
			if jsonOutput {
				data, _ := json.MarshalIndent(users, "", "  ")
				fmt.Println(string(data))
			} else {
				for _, u := range users {
					fmt.Printf("%s  %s  %s  active=%v\n", u.ID, u.Email, u.Name, u.Active)
				}
			}
		case "service":
			services, err := c.ListServices(ctx)
			if err != nil {
				return fmt.Errorf("list services: %w", err)
			}
			if jsonOutput {
				data, _ := json.MarshalIndent(services, "", "  ")
				fmt.Println(string(data))
			} else {
				for _, s := range services {
					fmt.Printf("%s  %s  %s  active=%v\n", s.ID, s.Name, s.AuthMethod, s.Active)
				}
			}
		case "device":
			devices, err := c.ListDevices(ctx)
			if err != nil {
				return fmt.Errorf("list devices: %w", err)
			}
			if jsonOutput {
				data, _ := json.MarshalIndent(devices, "", "  ")
				fmt.Println(string(data))
			} else {
				for _, d := range devices {
					fmt.Printf("%s  %s  %s  %s\n", d.ID, d.DeviceName, d.DeviceType, d.Status)
				}
			}
		default:
			return fmt.Errorf("unknown identity type: %s (use admin, user, service, device)", idType)
		}
		return nil
	},
}

var identityGetCmd = &cobra.Command{
	Use:   "get [identity-id]",
	Short: "Get identity details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		idType, _ := cmd.Flags().GetString("type")
		if idType == "" {
			return fmt.Errorf("--type is required (admin, user, service, device)")
		}

		c := getClient(cmd)
		ctx := context.Background()
		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")

		switch idType {
		case "admin":
			admin, err := c.GetAdmin(ctx, args[0])
			if err != nil {
				return fmt.Errorf("get admin: %w", err)
			}
			if jsonOutput {
				data, _ := json.MarshalIndent(admin, "", "  ")
				fmt.Println(string(data))
			} else {
				fmt.Printf("ID: %s\nEmail: %s\nName: %s\nRole: %s\nMFA: %v\nActive: %v\nCreated: %s\n",
					admin.ID, admin.Email, admin.Name, admin.Role, admin.MFAEnabled, admin.Active, admin.CreatedAt.Format(time.RFC3339))
			}
		case "user":
			user, err := c.GetUser(ctx, args[0])
			if err != nil {
				return fmt.Errorf("get user: %w", err)
			}
			if jsonOutput {
				data, _ := json.MarshalIndent(user, "", "  ")
				fmt.Println(string(data))
			} else {
				fmt.Printf("ID: %s\nEmail: %s\nName: %s\nSSO: %s\nActive: %v\nCreated: %s\n",
					user.ID, user.Email, user.Name, user.SSOProvider, user.Active, user.CreatedAt.Format(time.RFC3339))
			}
		case "service":
			svc, err := c.GetService(ctx, args[0])
			if err != nil {
				return fmt.Errorf("get service: %w", err)
			}
			if jsonOutput {
				data, _ := json.MarshalIndent(svc, "", "  ")
				fmt.Println(string(data))
			} else {
				fmt.Printf("ID: %s\nName: %s\nAuth: %s\nVaultRole: %s\nActive: %v\nCreated: %s\n",
					svc.ID, svc.Name, svc.AuthMethod, svc.VaultRole, svc.Active, svc.CreatedAt.Format(time.RFC3339))
			}
		case "device":
			dev, err := c.GetDevice(ctx, args[0])
			if err != nil {
				return fmt.Errorf("get device: %w", err)
			}
			if jsonOutput {
				data, _ := json.MarshalIndent(dev, "", "  ")
				fmt.Println(string(data))
			} else {
				fmt.Printf("ID: %s\nName: %s\nType: %s\nStatus: %s\nCertSerial: %s\nEnrolled: %s\n",
					dev.ID, dev.DeviceName, dev.DeviceType, dev.Status, dev.CertificateSerial, dev.EnrolledAt.Format(time.RFC3339))
			}
		default:
			return fmt.Errorf("unknown identity type: %s (use admin, user, service, device)", idType)
		}
		return nil
	},
}

// identity create subcommands

var identityCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an identity",
}

var identityCreateAdminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Create an admin identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		email, _ := cmd.Flags().GetString("email")
		name, _ := cmd.Flags().GetString("name")
		role, _ := cmd.Flags().GetString("role")

		if email == "" || name == "" {
			return fmt.Errorf("--email and --name are required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		admin, err := c.CreateAdmin(ctx, client.CreateAdminRequest{
			Email: email,
			Name:  name,
			Role:  models.AdminRole(role),
		})
		if err != nil {
			return fmt.Errorf("create admin: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(admin, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Admin created: %s (%s)\n", admin.Name, admin.ID)
		}
		return nil
	},
}

var identityCreateServiceCmd = &cobra.Command{
	Use:   "service",
	Short: "Create a service identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		authMethod, _ := cmd.Flags().GetString("auth-method")

		if name == "" {
			return fmt.Errorf("--name is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		svc, err := c.CreateService(ctx, client.CreateServiceRequest{
			Name:       name,
			AuthMethod: models.AuthMethod(authMethod),
		})
		if err != nil {
			return fmt.Errorf("create service: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(svc, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Service created: %s (%s)\n", svc.Name, svc.ID)
		}
		return nil
	},
}

var identityDeleteCmd = &cobra.Command{
	Use:   "delete [identity-id]",
	Short: "Delete an identity",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		idType, _ := cmd.Flags().GetString("type")
		if idType == "" {
			return fmt.Errorf("--type is required (admin, user, service)")
		}

		c := getClient(cmd)
		ctx := context.Background()

		switch idType {
		case "admin":
			if err := c.DeleteAdmin(ctx, args[0]); err != nil {
				return fmt.Errorf("delete admin: %w", err)
			}
		case "user":
			if err := c.DeleteUser(ctx, args[0]); err != nil {
				return fmt.Errorf("delete user: %w", err)
			}
		case "service":
			if err := c.DeleteService(ctx, args[0]); err != nil {
				return fmt.Errorf("delete service: %w", err)
			}
		default:
			return fmt.Errorf("unknown identity type: %s (use admin, user, service)", idType)
		}

		fmt.Printf("Identity deleted: %s\n", args[0])
		return nil
	},
}

// Device enrollment/revocation

var identityEnrollDeviceCmd = &cobra.Command{
	Use:   "enroll-device",
	Short: "Enroll a device identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		deviceType, _ := cmd.Flags().GetString("device-type")

		if name == "" {
			return fmt.Errorf("--name is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		dev, err := c.EnrollDevice(ctx, client.EnrollDeviceRequest{
			DeviceName: name,
			DeviceType: deviceType,
		})
		if err != nil {
			return fmt.Errorf("enroll device: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(dev, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Device enrolled: %s (%s)\n", dev.DeviceName, dev.ID)
		}
		return nil
	},
}

var identityRevokeDeviceCmd = &cobra.Command{
	Use:   "revoke-device [device-id]",
	Short: "Revoke a device identity",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		if err := c.RevokeDevice(ctx, args[0]); err != nil {
			return fmt.Errorf("revoke device: %w", err)
		}

		fmt.Printf("Device revoked: %s\n", args[0])
		return nil
	},
}

// MFA subcommands

var identityMFACmd = &cobra.Command{
	Use:   "mfa",
	Short: "MFA management for admin identities",
}

var identityMFAEnableCmd = &cobra.Command{
	Use:   "enable [admin-id]",
	Short: "Enable MFA for an admin identity",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		resp, err := c.EnableMFA(ctx, args[0])
		if err != nil {
			return fmt.Errorf("enable MFA: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(resp, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("MFA enabled for admin %s\nSecret: %s\nQR Code URL: %s\n", args[0], resp.Secret, resp.QRCodeURL)
		}
		return nil
	},
}

var identityMFAVerifyCmd = &cobra.Command{
	Use:   "verify [admin-id]",
	Short: "Verify MFA setup for an admin identity",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		code, _ := cmd.Flags().GetString("code")
		if code == "" {
			return fmt.Errorf("--code is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		if err := c.VerifyMFA(ctx, args[0], client.VerifyMFARequest{Code: code}); err != nil {
			return fmt.Errorf("verify MFA: %w", err)
		}

		fmt.Printf("MFA verified for admin %s\n", args[0])
		return nil
	},
}

// Group subcommands

var identityGroupCmd = &cobra.Command{
	Use:   "group",
	Short: "Identity group management",
}

var identityGroupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an identity group",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		description, _ := cmd.Flags().GetString("description")

		if name == "" {
			return fmt.Errorf("--name is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		group, err := c.CreateGroup(ctx, client.CreateGroupRequest{
			Name:        name,
			Description: description,
		})
		if err != nil {
			return fmt.Errorf("create group: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(group, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Group created: %s (%s)\n", group.Name, group.ID)
		}
		return nil
	},
}

var identityGroupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List identity groups",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		groups, err := c.ListGroups(ctx)
		if err != nil {
			return fmt.Errorf("list groups: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(groups, "", "  ")
			fmt.Println(string(data))
		} else {
			for _, g := range groups {
				fmt.Printf("%s  %s  %s\n", g.ID, g.Name, g.Description)
			}
		}
		return nil
	},
}

var identityGroupAddMemberCmd = &cobra.Command{
	Use:   "add-member [group-id]",
	Short: "Add a member to a group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		identityID, _ := cmd.Flags().GetString("identity-id")
		identityType, _ := cmd.Flags().GetString("identity-type")

		if identityID == "" || identityType == "" {
			return fmt.Errorf("--identity-id and --identity-type are required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		if err := c.AddGroupMember(ctx, args[0], client.AddGroupMemberRequest{
			IdentityID:   identityID,
			IdentityType: models.IdentityType(identityType),
		}); err != nil {
			return fmt.Errorf("add group member: %w", err)
		}

		fmt.Printf("Member %s added to group %s\n", identityID, args[0])
		return nil
	},
}

var identityGroupRemoveMemberCmd = &cobra.Command{
	Use:   "remove-member [group-id]",
	Short: "Remove a member from a group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		identityID, _ := cmd.Flags().GetString("identity-id")
		if identityID == "" {
			return fmt.Errorf("--identity-id is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		if err := c.RemoveGroupMember(ctx, args[0], identityID); err != nil {
			return fmt.Errorf("remove group member: %w", err)
		}

		fmt.Printf("Member %s removed from group %s\n", identityID, args[0])
		return nil
	},
}

// Role subcommands

var identityRoleCmd = &cobra.Command{
	Use:   "role",
	Short: "Role management",
}

var identityRoleCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a role",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		description, _ := cmd.Flags().GetString("description")

		if name == "" {
			return fmt.Errorf("--name is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		role, err := c.CreateRole(ctx, client.CreateRoleRequest{
			Name:        name,
			Description: description,
		})
		if err != nil {
			return fmt.Errorf("create role: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(role, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Role created: %s (%s)\n", role.Name, role.ID)
		}
		return nil
	},
}

var identityRoleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List roles",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		roles, err := c.ListRoles(ctx)
		if err != nil {
			return fmt.Errorf("list roles: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(roles, "", "  ")
			fmt.Println(string(data))
		} else {
			for _, r := range roles {
				fmt.Printf("%s  %s  %s\n", r.ID, r.Name, r.Description)
			}
		}
		return nil
	},
}

var identityRoleAssignCmd = &cobra.Command{
	Use:   "assign [role-id]",
	Short: "Assign a role to an identity",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		identityID, _ := cmd.Flags().GetString("identity-id")
		identityType, _ := cmd.Flags().GetString("identity-type")

		if identityID == "" || identityType == "" {
			return fmt.Errorf("--identity-id and --identity-type are required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		if err := c.AssignRole(ctx, args[0], client.AssignRoleRequest{
			IdentityID:   identityID,
			IdentityType: models.IdentityType(identityType),
		}); err != nil {
			return fmt.Errorf("assign role: %w", err)
		}

		fmt.Printf("Role %s assigned to %s\n", args[0], identityID)
		return nil
	},
}

var identityRoleUnassignCmd = &cobra.Command{
	Use:   "unassign [role-id]",
	Short: "Unassign a role from an identity",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		identityID, _ := cmd.Flags().GetString("identity-id")
		if identityID == "" {
			return fmt.Errorf("--identity-id is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		if err := c.UnassignRole(ctx, args[0], identityID); err != nil {
			return fmt.Errorf("unassign role: %w", err)
		}

		fmt.Printf("Role %s unassigned from %s\n", args[0], identityID)
		return nil
	},
}

func init() {
	// identity list flags
	identityListCmd.Flags().String("type", "", "Identity type (admin, user, service, device)")

	// identity get flags
	identityGetCmd.Flags().String("type", "", "Identity type (admin, user, service, device)")

	// identity create admin flags
	identityCreateAdminCmd.Flags().String("email", "", "Admin email address")
	identityCreateAdminCmd.Flags().String("name", "", "Admin display name")
	identityCreateAdminCmd.Flags().String("role", "operations_admin", "Admin role (super_admin, security_admin, operations_admin, auditor)")

	// identity create service flags
	identityCreateServiceCmd.Flags().String("name", "", "Service name")
	identityCreateServiceCmd.Flags().String("auth-method", "approle", "Authentication method (approle, kubernetes, cert)")

	// identity delete flags
	identityDeleteCmd.Flags().String("type", "", "Identity type (admin, user, service)")

	// identity enroll-device flags
	identityEnrollDeviceCmd.Flags().String("name", "", "Device name")
	identityEnrollDeviceCmd.Flags().String("device-type", "", "Device type")

	// identity mfa verify flags
	identityMFAVerifyCmd.Flags().String("code", "", "MFA verification code")

	// identity group create flags
	identityGroupCreateCmd.Flags().String("name", "", "Group name")
	identityGroupCreateCmd.Flags().String("description", "", "Group description")

	// identity group add-member flags
	identityGroupAddMemberCmd.Flags().String("identity-id", "", "Identity ID to add")
	identityGroupAddMemberCmd.Flags().String("identity-type", "", "Identity type (admin, user, service, device)")

	// identity group remove-member flags
	identityGroupRemoveMemberCmd.Flags().String("identity-id", "", "Identity ID to remove")

	// identity role create flags
	identityRoleCreateCmd.Flags().String("name", "", "Role name")
	identityRoleCreateCmd.Flags().String("description", "", "Role description")

	// identity role assign flags
	identityRoleAssignCmd.Flags().String("identity-id", "", "Identity ID to assign role to")
	identityRoleAssignCmd.Flags().String("identity-type", "", "Identity type (admin, user, service, device)")

	// identity role unassign flags
	identityRoleUnassignCmd.Flags().String("identity-id", "", "Identity ID to unassign role from")

	// identity create user-sso flags
	identityCreateUserSSOCmd.Flags().String("email", "", "User email address")
	identityCreateUserSSOCmd.Flags().String("name", "", "User display name")
	identityCreateUserSSOCmd.Flags().String("sso-provider", "", "SSO provider (azure_ad, okta, google)")
	identityCreateUserSSOCmd.Flags().String("sso-subject", "", "SSO subject identifier")

	// Wire up create subcommands
	identityCreateCmd.AddCommand(identityCreateAdminCmd)
	identityCreateCmd.AddCommand(identityCreateServiceCmd)
	identityCreateCmd.AddCommand(identityCreateUserSSOCmd)

	// Wire up MFA subcommands
	identityMFACmd.AddCommand(identityMFAEnableCmd)
	identityMFACmd.AddCommand(identityMFAVerifyCmd)

	// Wire up group subcommands
	identityGroupCmd.AddCommand(identityGroupCreateCmd)
	identityGroupCmd.AddCommand(identityGroupListCmd)
	identityGroupCmd.AddCommand(identityGroupAddMemberCmd)
	identityGroupCmd.AddCommand(identityGroupRemoveMemberCmd)

	// Wire up role subcommands
	identityRoleCmd.AddCommand(identityRoleCreateCmd)
	identityRoleCmd.AddCommand(identityRoleListCmd)
	identityRoleCmd.AddCommand(identityRoleAssignCmd)
	identityRoleCmd.AddCommand(identityRoleUnassignCmd)

	// Wire up identity subcommands
	identityCmd.AddCommand(identityListCmd)
	identityCmd.AddCommand(identityGetCmd)
	identityCmd.AddCommand(identityCreateCmd)
	identityCmd.AddCommand(identityDeleteCmd)
	identityCmd.AddCommand(identityEnrollDeviceCmd)
	identityCmd.AddCommand(identityRevokeDeviceCmd)
	identityCmd.AddCommand(identityMFACmd)
	identityCmd.AddCommand(identityGroupCmd)
	identityCmd.AddCommand(identityRoleCmd)
	identityCmd.AddCommand(identityAdminCmd)
	identityCmd.AddCommand(identityServiceCmd)
}

// Admin enable/disable subcommands

var identityAdminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Admin identity operations",
}

var identityAdminDisableCmd = &cobra.Command{
	Use:   "disable [admin-id]",
	Short: "Disable an admin identity",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		active := false
		admin, err := c.UpdateAdmin(ctx, args[0], client.UpdateAdminRequest{Active: &active})
		if err != nil {
			return fmt.Errorf("disable admin: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(admin, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Admin disabled: %s (%s)\n", admin.Name, admin.ID)
		}
		return nil
	},
}

var identityAdminEnableCmd = &cobra.Command{
	Use:   "enable [admin-id]",
	Short: "Enable an admin identity",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		active := true
		admin, err := c.UpdateAdmin(ctx, args[0], client.UpdateAdminRequest{Active: &active})
		if err != nil {
			return fmt.Errorf("enable admin: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(admin, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Admin enabled: %s (%s)\n", admin.Name, admin.ID)
		}
		return nil
	},
}

// Service identity subcommands

var identityServiceCmd = &cobra.Command{
	Use:   "service",
	Short: "Service identity operations",
}

var identityServiceRotateCmd = &cobra.Command{
	Use:   "rotate [service-id]",
	Short: "Rotate credentials for a service identity",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		svc, err := c.RotateServiceCredentials(ctx, args[0])
		if err != nil {
			return fmt.Errorf("rotate service credentials: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(svc, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Service credentials rotated: %s (%s)\n", svc.Name, svc.ID)
		}
		return nil
	},
}

func init() {
	identityAdminCmd.AddCommand(identityAdminDisableCmd)
	identityAdminCmd.AddCommand(identityAdminEnableCmd)

	identityServiceCmd.AddCommand(identityServiceRotateCmd)
}

// ============================================================================
// Edge Node Commands
// ============================================================================

var edgeCmd = &cobra.Command{
	Use:   "edge",
	Short: "Edge node management",
	Long:  `Manage edge nodes (Vault clusters) in the federation.`,
}

var edgeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List edge nodes",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		edges, err := c.ListEdgeNodes(ctx)
		if err != nil {
			return fmt.Errorf("list edge nodes: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(edges, "", "  ")
			fmt.Println(string(data))
		} else {
			for _, e := range edges {
				fmt.Printf("%s  %s  %s  %s\n", e.ID, e.Name, e.Region, e.Status)
			}
		}
		return nil
	},
}

var edgeGetCmd = &cobra.Command{
	Use:   "get [edge-id]",
	Short: "Get edge node details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		edge, err := c.GetEdgeNode(ctx, args[0])
		if err != nil {
			return fmt.Errorf("get edge node: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(edge, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("ID: %s\nName: %s\nRegion: %s\nStatus: %s\nVault: %s\n",
				edge.ID, edge.Name, edge.Region, edge.Status, edge.VaultAddress)
		}
		return nil
	},
}

var edgeRegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a new edge node",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		vaultAddr, _ := cmd.Flags().GetString("vault-addr")
		region, _ := cmd.Flags().GetString("region")

		if name == "" || vaultAddr == "" {
			return fmt.Errorf("--name and --vault-addr are required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		edge, err := c.RegisterEdgeNode(ctx, client.EdgeNodeRegisterRequest{
			Name:      name,
			VaultAddr: vaultAddr,
			Region:    region,
		})
		if err != nil {
			return fmt.Errorf("register edge node: %w", err)
		}

		fmt.Printf("Edge node registered: %s (%s)\n", edge.Name, edge.ID)
		return nil
	},
}

var edgeUnregisterCmd = &cobra.Command{
	Use:   "unregister [edge-id]",
	Short: "Unregister an edge node",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		if err := c.UnregisterEdgeNode(ctx, args[0]); err != nil {
			return fmt.Errorf("unregister edge node: %w", err)
		}

		fmt.Printf("Edge node unregistered: %s\n", args[0])
		return nil
	},
}

var edgeHealthCmd = &cobra.Command{
	Use:   "health [edge-id]",
	Short: "Check edge node health",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		health, err := c.GetEdgeHealth(ctx, args[0])
		if err != nil {
			return fmt.Errorf("get edge health: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(health, "", "  ")
			fmt.Println(string(data))
		} else {
			status := "healthy"
			if !health.Healthy {
				status = "unhealthy"
			}
			fmt.Printf("Status: %s\nVersion: %s\nVault Sealed: %v\nHA Enabled: %v\nCluster Nodes: %d\n",
				status, health.Version, health.VaultSealed, health.HAEnabled, health.ClusterNodes)
			if health.ErrorMessage != "" {
				fmt.Printf("Error: %s\n", health.ErrorMessage)
			}
		}
		return nil
	},
}

var edgeSyncPoliciesCmd = &cobra.Command{
	Use:   "sync-policies [edge-id]",
	Short: "Sync policies to edge node",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		if err := c.SyncEdgePolicies(ctx, args[0]); err != nil {
			return fmt.Errorf("sync policies: %w", err)
		}

		fmt.Printf("Policies synced to edge node: %s\n", args[0])
		return nil
	},
}

var edgeSyncKeysCmd = &cobra.Command{
	Use:   "sync-keys [edge-id]",
	Short: "Sync keys to edge node",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workspaceID, _ := cmd.Flags().GetString("workspace")
		if workspaceID == "" {
			return fmt.Errorf("--workspace is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		if err := c.SyncEdgeKeys(ctx, args[0], client.SyncEdgeKeysRequest{
			WorkspaceID: workspaceID,
		}); err != nil {
			return fmt.Errorf("sync keys: %w", err)
		}

		fmt.Printf("Keys synced to edge node: %s\n", args[0])
		return nil
	},
}

var edgeSyncStatusCmd = &cobra.Command{
	Use:   "sync-status [edge-id]",
	Short: "Get edge node sync status",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		status, err := c.GetEdgeSyncStatus(ctx, args[0])
		if err != nil {
			return fmt.Errorf("get sync status: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(status, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Last Synced: %s\nSync In Progress: %v\nPolicies Synced: %d\nKeys Synced: %d\nErrors: %d\n",
				status.LastSyncedAt, status.SyncInProgress, status.PoliciesSynced, status.KeysSynced, status.ErrorCount)
			if status.LastError != "" {
				fmt.Printf("Last Error: %s\n", status.LastError)
			}
		}
		return nil
	},
}

func init() {
	edgeRegisterCmd.Flags().String("name", "", "Edge node name")
	edgeRegisterCmd.Flags().String("vault-addr", "", "Vault address")
	edgeRegisterCmd.Flags().String("region", "", "Region")

	edgeSyncKeysCmd.Flags().String("workspace", "", "Workspace ID")

	edgeCmd.AddCommand(edgeListCmd)
	edgeCmd.AddCommand(edgeGetCmd)
	edgeCmd.AddCommand(edgeRegisterCmd)
	edgeCmd.AddCommand(edgeUnregisterCmd)
	edgeCmd.AddCommand(edgeHealthCmd)
	edgeCmd.AddCommand(edgeSyncPoliciesCmd)
	edgeCmd.AddCommand(edgeSyncKeysCmd)
	edgeCmd.AddCommand(edgeSyncStatusCmd)
}

// ============================================================================
// Login/Logout Commands
// ============================================================================

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with the Sovra API",
	RunE: func(cmd *cobra.Command, args []string) error {
		email, _ := cmd.Flags().GetString("email")
		password, _ := cmd.Flags().GetString("password")

		if email == "" {
			return fmt.Errorf("--email is required")
		}
		if password == "" {
			return fmt.Errorf("--password is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		resp, err := c.Login(ctx, email, password)
		if err != nil {
			return fmt.Errorf("login failed: %w", err)
		}

		fmt.Printf("Login successful. Token expires at: %s\n", resp.ExpiresAt.Format(time.RFC3339))
		fmt.Printf("Set SOVRA_TOKEN environment variable with:\nexport SOVRA_TOKEN=%s\n", resp.Token)
		return nil
	},
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out from the Sovra API",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		if err := c.Logout(ctx); err != nil {
			return fmt.Errorf("logout failed: %w", err)
		}

		fmt.Println("Logged out successfully.")
		return nil
	},
}

func init() {
	loginCmd.Flags().String("email", "", "Email address")
	loginCmd.Flags().String("password", "", "Password")
}

// ============================================================================
// Encrypt/Decrypt Commands
// ============================================================================

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt data in a workspace",
	RunE: func(cmd *cobra.Command, args []string) error {
		workspaceID, _ := cmd.Flags().GetString("workspace")
		data, _ := cmd.Flags().GetString("data")
		dataFile, _ := cmd.Flags().GetString("data-file")
		output, _ := cmd.Flags().GetString("output")
		inputDir, _ := cmd.Flags().GetString("input-dir")
		outputDir, _ := cmd.Flags().GetString("output-dir")

		if workspaceID == "" {
			return fmt.Errorf("--workspace is required")
		}

		c := getClient(cmd)

		// Batch mode
		if inputDir != "" {
			if outputDir == "" {
				return fmt.Errorf("--output-dir is required with --input-dir")
			}
			return batchEncrypt(c, workspaceID, inputDir, outputDir)
		}

		var plaintext []byte
		if dataFile != "" {
			var err error
			plaintext, err = os.ReadFile(dataFile)
			if err != nil {
				return fmt.Errorf("read data file: %w", err)
			}
		} else if data != "" {
			plaintext = []byte(data)
		} else {
			return fmt.Errorf("--data or --data-file is required")
		}

		ctx := context.Background()

		// Parse optional encryption context
		encContext, _ := cmd.Flags().GetString("context")
		var ciphertext []byte
		if encContext != "" {
			var ctxMap map[string]string
			if err := json.Unmarshal([]byte(encContext), &ctxMap); err != nil {
				return fmt.Errorf("parse --context JSON: %w", err)
			}
			var encErr error
			ciphertext, encErr = c.EncryptWithContext(ctx, workspaceID, plaintext, ctxMap)
			if encErr != nil {
				return fmt.Errorf("encrypt: %w", encErr)
			}
		} else {
			var encErr error
			ciphertext, encErr = c.Encrypt(ctx, workspaceID, plaintext)
			if encErr != nil {
				return fmt.Errorf("encrypt: %w", encErr)
			}
		}

		encoded := base64.StdEncoding.EncodeToString(ciphertext)
		if output != "" {
			if err := os.WriteFile(output, []byte(encoded), 0644); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
			fmt.Printf("Encrypted data written to %s\n", output)
		} else {
			fmt.Println(encoded)
		}
		return nil
	},
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt data from a workspace",
	RunE: func(cmd *cobra.Command, args []string) error {
		workspaceID, _ := cmd.Flags().GetString("workspace")
		data, _ := cmd.Flags().GetString("data")
		dataFile, _ := cmd.Flags().GetString("data-file")
		output, _ := cmd.Flags().GetString("output")
		inputDir, _ := cmd.Flags().GetString("input-dir")
		outputDir, _ := cmd.Flags().GetString("output-dir")

		if workspaceID == "" {
			return fmt.Errorf("--workspace is required")
		}

		c := getClient(cmd)

		// Batch mode
		if inputDir != "" {
			if outputDir == "" {
				return fmt.Errorf("--output-dir is required with --input-dir")
			}
			return batchDecrypt(c, workspaceID, inputDir, outputDir)
		}

		var encoded string
		if dataFile != "" {
			content, err := os.ReadFile(dataFile)
			if err != nil {
				return fmt.Errorf("read data file: %w", err)
			}
			encoded = string(content)
		} else if data != "" {
			encoded = data
		} else {
			return fmt.Errorf("--data or --data-file is required")
		}

		ciphertext, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return fmt.Errorf("decode base64: %w", err)
		}

		ctx := context.Background()

		// Parse optional encryption context
		encContext, _ := cmd.Flags().GetString("context")
		var plaintext []byte
		if encContext != "" {
			var ctxMap map[string]string
			if err := json.Unmarshal([]byte(encContext), &ctxMap); err != nil {
				return fmt.Errorf("parse --context JSON: %w", err)
			}
			var decErr error
			plaintext, decErr = c.DecryptWithContext(ctx, workspaceID, ciphertext, ctxMap)
			if decErr != nil {
				return fmt.Errorf("decrypt: %w", decErr)
			}
		} else {
			var decErr error
			plaintext, decErr = c.Decrypt(ctx, workspaceID, ciphertext)
			if decErr != nil {
				return fmt.Errorf("decrypt: %w", decErr)
			}
		}

		if output != "" {
			if err := os.WriteFile(output, plaintext, 0644); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
			fmt.Printf("Decrypted data written to %s\n", output)
		} else {
			fmt.Println(string(plaintext))
		}
		return nil
	},
}

func init() {
	encryptCmd.Flags().String("workspace", "", "Workspace ID")
	encryptCmd.Flags().String("data", "", "Data to encrypt")
	encryptCmd.Flags().String("data-file", "", "File containing data to encrypt")
	encryptCmd.Flags().String("output", "", "Output file")
	encryptCmd.Flags().String("input-dir", "", "Directory of files to encrypt (batch mode)")
	encryptCmd.Flags().String("output-dir", "", "Output directory for batch mode")
	encryptCmd.Flags().String("context", "", "Encryption context (JSON string)")

	decryptCmd.Flags().String("workspace", "", "Workspace ID")
	decryptCmd.Flags().String("data", "", "Base64 encoded ciphertext")
	decryptCmd.Flags().String("data-file", "", "File containing base64 ciphertext")
	decryptCmd.Flags().String("output", "", "Output file")
	decryptCmd.Flags().String("input-dir", "", "Directory of files to decrypt (batch mode)")
	decryptCmd.Flags().String("output-dir", "", "Output directory for batch mode")
	decryptCmd.Flags().String("context", "", "Decryption context (JSON string)")

	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(healthCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(metricsCmd)
	rootCmd.AddCommand(activityCmd)
}

// ============================================================================
// Metrics Command
// ============================================================================

var metricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Retrieve Prometheus metrics",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		data, err := c.GetMetrics(ctx)
		if err != nil {
			return fmt.Errorf("get metrics: %w", err)
		}

		fmt.Print(data)
		return nil
	},
}

// ============================================================================
// Activity Log Command
// ============================================================================

var activityCmd = &cobra.Command{
	Use:   "activity [actor-id]",
	Short: "View activity log for an actor",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		since, _ := cmd.Flags().GetString("since")
		until, _ := cmd.Flags().GetString("until")
		limit, _ := cmd.Flags().GetInt("limit")

		c := getClient(cmd)
		ctx := context.Background()

		events, err := c.GetActivityLog(ctx, args[0], client.AuditQueryParams{
			Since: since,
			Until: until,
			Limit: limit,
		})
		if err != nil {
			return fmt.Errorf("get activity log: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(events, "", "  ")
			fmt.Println(string(data))
		} else {
			for _, ev := range events {
				fmt.Printf("%s  %s  %s  %s\n",
					ev.Timestamp.Format(time.RFC3339), ev.EventType, ev.Result, ev.Workspace)
			}
		}
		return nil
	},
}

func init() {
	activityCmd.Flags().String("since", "", "Start time (RFC3339)")
	activityCmd.Flags().String("until", "", "End time (RFC3339)")
	activityCmd.Flags().Int("limit", 100, "Maximum results")
}

// ============================================================================
// Health Command
// ============================================================================

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check API health status",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		resp, err := c.Health(ctx)
		if err != nil {
			return fmt.Errorf("health check: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(resp, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Status: %s\nVersion: %s\n", resp.Status, resp.Version)
		}
		return nil
	},
}

// ============================================================================
// Config Commands
// ============================================================================

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management",
	Long:  `Show and validate CLI configuration.`,
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, _ := cmd.Root().PersistentFlags().GetString("config")
		if configPath == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("get home directory: %w", err)
			}
			configPath = filepath.Join(home, ".sovra", "config.json")
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("No config file found at %s\n", configPath)
				fmt.Println("Using defaults:")
				apiURL, _ := cmd.Root().PersistentFlags().GetString("api-url")
				orgID, _ := cmd.Root().PersistentFlags().GetString("org-id")
				fmt.Printf("  API URL: %s\n", apiURL)
				fmt.Printf("  Org ID: %s\n", orgID)
				fmt.Printf("  Token: %s\n", maskToken(os.Getenv("SOVRA_TOKEN")))
				return nil
			}
			return fmt.Errorf("read config: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			fmt.Println(string(data))
		} else {
			fmt.Printf("Config file: %s\n---\n%s\n", configPath, string(data))
		}
		return nil
	},
}

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, _ := cmd.Root().PersistentFlags().GetString("config")
		if configPath == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("get home directory: %w", err)
			}
			configPath = filepath.Join(home, ".sovra", "config.json")
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("No config file at %s (using defaults)\n", configPath)
				return nil
			}
			return fmt.Errorf("read config: %w", err)
		}

		var cfg map[string]any
		if err := json.Unmarshal(data, &cfg); err != nil {
			fmt.Printf("Config INVALID: %s\n", err)
			os.Exit(1)
		}

		issues := []string{}
		if v, ok := cfg["api_url"]; ok {
			if s, ok := v.(string); !ok || s == "" {
				issues = append(issues, "api_url is empty or not a string")
			}
		}
		if v, ok := cfg["org_id"]; ok {
			if s, ok := v.(string); !ok || s == "" {
				issues = append(issues, "org_id is empty or not a string")
			}
		}

		if len(issues) > 0 {
			fmt.Println("Config validation issues:")
			for _, issue := range issues {
				fmt.Printf("  - %s\n", issue)
			}
			os.Exit(1)
		}

		fmt.Println("Config: OK")
		return nil
	},
}

func init() {
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configValidateCmd)
}

func maskToken(token string) string {
	if token == "" {
		return "(not set)"
	}
	if len(token) <= 8 {
		return strings.Repeat("*", len(token))
	}
	return token[:4] + strings.Repeat("*", len(token)-8) + token[len(token)-4:]
}

// ============================================================================
// Identity Create User SSO Command
// ============================================================================

var identityCreateUserSSOCmd = &cobra.Command{
	Use:   "user-sso",
	Short: "Create a user identity from SSO",
	RunE: func(cmd *cobra.Command, args []string) error {
		email, _ := cmd.Flags().GetString("email")
		name, _ := cmd.Flags().GetString("name")
		ssoProvider, _ := cmd.Flags().GetString("sso-provider")
		ssoSubject, _ := cmd.Flags().GetString("sso-subject")

		if email == "" || name == "" || ssoProvider == "" || ssoSubject == "" {
			return fmt.Errorf("--email, --name, --sso-provider, and --sso-subject are required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		user, err := c.CreateUserFromSSO(ctx, client.CreateUserSSORequest{
			Email:       email,
			Name:        name,
			SSOProvider: models.SSOProvider(ssoProvider),
			SSOSubject:  ssoSubject,
		})
		if err != nil {
			return fmt.Errorf("create SSO user: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(user, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("SSO user created: %s (%s)\n", user.Name, user.ID)
		}
		return nil
	},
}

// ============================================================================
// Certificate Commands
// ============================================================================

var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "Certificate management",
	Long:  `Manage certificates issued by the Vault PKI engine.`,
}

var certIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a new certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		commonName, _ := cmd.Flags().GetString("common-name")
		role, _ := cmd.Flags().GetString("role")
		ttl, _ := cmd.Flags().GetString("ttl")
		altNames, _ := cmd.Flags().GetStringSlice("alt-names")

		if commonName == "" {
			return fmt.Errorf("--common-name is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		cert, err := c.IssueCertificate(ctx, role, client.IssueCertificateRequest{
			CommonName: commonName,
			AltNames:   altNames,
			TTL:        ttl,
		})
		if err != nil {
			return fmt.Errorf("issue certificate: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(cert, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Certificate issued:\n  Serial: %s\n  Common Name: %s\n", cert.SerialNumber, commonName)
			if cert.Certificate != "" {
				fmt.Printf("  Certificate:\n%s\n", cert.Certificate)
			}
		}
		return nil
	},
}

var certRevokeCmd = &cobra.Command{
	Use:   "revoke [serial]",
	Short: "Revoke a certificate",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		if err := c.RevokeCertificate(ctx, args[0]); err != nil {
			return fmt.Errorf("revoke certificate: %w", err)
		}

		fmt.Printf("Certificate revoked: %s\n", args[0])
		return nil
	},
}

var certGetCmd = &cobra.Command{
	Use:   "get [serial]",
	Short: "Get a certificate by serial number",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		cert, err := c.ReadCertificate(ctx, args[0])
		if err != nil {
			return fmt.Errorf("get certificate: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(cert, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Serial: %s\n", cert.SerialNumber)
			if cert.Certificate != "" {
				fmt.Printf("Certificate:\n%s\n", cert.Certificate)
			}
		}
		return nil
	},
}

var certListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all certificates",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		result, err := c.ListCertificates(ctx)
		if err != nil {
			return fmt.Errorf("list certificates: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Certificates (%d):\n", result.Count)
			for _, serial := range result.Certificates {
				fmt.Printf("  %s\n", serial)
			}
		}
		return nil
	},
}

var certCAChainCmd = &cobra.Command{
	Use:   "ca-chain",
	Short: "Get the CA certificate chain",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		result, err := c.GetCAChain(ctx)
		if err != nil {
			return fmt.Errorf("get CA chain: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Println(result.CAChain)
		}
		return nil
	},
}

var certTidyCmd = &cobra.Command{
	Use:   "tidy",
	Short: "Tidy the certificate store",
	RunE: func(cmd *cobra.Command, args []string) error {
		safetyBuffer, _ := cmd.Flags().GetString("safety-buffer")

		c := getClient(cmd)
		ctx := context.Background()

		if err := c.TidyCertificates(ctx, safetyBuffer); err != nil {
			return fmt.Errorf("tidy certificates: %w", err)
		}

		fmt.Println("Tidy operation started")
		return nil
	},
}

func init() {
	certIssueCmd.Flags().String("common-name", "", "Common name for the certificate")
	certIssueCmd.Flags().String("role", "default", "PKI role to use")
	certIssueCmd.Flags().String("ttl", "", "TTL for the certificate (e.g. 8760h)")
	certIssueCmd.Flags().StringSlice("alt-names", nil, "Subject alternative names")

	certTidyCmd.Flags().String("safety-buffer", "", "Safety buffer duration (e.g. 72h)")

	certCmd.AddCommand(certIssueCmd)
	certCmd.AddCommand(certRevokeCmd)
	certCmd.AddCommand(certGetCmd)
	certCmd.AddCommand(certListCmd)
	certCmd.AddCommand(certCAChainCmd)
	certCmd.AddCommand(certTidyCmd)

	rootCmd.AddCommand(certCmd)
}

// ============================================================================
// Workspace Export/Import Commands
// ============================================================================

var workspaceExportCmd = &cobra.Command{
	Use:   "export [workspace-id]",
	Short: "Export a workspace as a bundle",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		output, _ := cmd.Flags().GetString("output")

		c := getClient(cmd)
		ctx := context.Background()

		bundle, err := c.ExportWorkspace(ctx, args[0])
		if err != nil {
			return fmt.Errorf("export workspace: %w", err)
		}

		data, _ := json.MarshalIndent(bundle, "", "  ")

		if output != "" {
			if err := os.WriteFile(output, data, 0644); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
			fmt.Printf("Workspace exported to %s\n", output)
		} else {
			fmt.Println(string(data))
		}
		return nil
	},
}

var workspaceImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import a workspace from a bundle",
	RunE: func(cmd *cobra.Command, args []string) error {
		input, _ := cmd.Flags().GetString("input")
		if input == "" {
			return fmt.Errorf("--input is required")
		}

		data, err := os.ReadFile(input)
		if err != nil {
			return fmt.Errorf("read input: %w", err)
		}

		var bundle client.WorkspaceBundleResponse
		if err := json.Unmarshal(data, &bundle); err != nil {
			return fmt.Errorf("parse bundle: %w", err)
		}

		c := getClient(cmd)
		ctx := context.Background()

		ws, err := c.ImportWorkspace(ctx, &bundle)
		if err != nil {
			return fmt.Errorf("import workspace: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			out, _ := json.MarshalIndent(ws, "", "  ")
			fmt.Println(string(out))
		} else {
			fmt.Printf("Workspace imported: %s (%s)\n", ws.Name, ws.ID)
		}
		return nil
	},
}

func init() {
	workspaceExportCmd.Flags().String("output", "", "Output file path")
	workspaceImportCmd.Flags().String("input", "", "Input file path")

	workspaceCmd.AddCommand(workspaceExportCmd)
	workspaceCmd.AddCommand(workspaceImportCmd)
}

// ============================================================================
// Emergency Access Commands
// ============================================================================

var emergencyAccessCmd = &cobra.Command{
	Use:   "emergency-access",
	Short: "Emergency access management",
	Long:  `Manage break-glass emergency access requests.`,
}

var emergencyAccessRequestCmd = &cobra.Command{
	Use:   "request",
	Short: "Request emergency access",
	RunE: func(cmd *cobra.Command, args []string) error {
		orgID, _ := cmd.Flags().GetString("org-id")
		reason, _ := cmd.Flags().GetString("reason")

		if reason == "" {
			return fmt.Errorf("--reason is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		req, err := c.RequestEmergencyAccess(ctx, client.EmergencyAccessRequestPayload{
			OrgID:  orgID,
			Reason: reason,
		})
		if err != nil {
			return fmt.Errorf("request emergency access: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(req, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Emergency access requested: %s (status: %s)\n", req.ID, req.Status)
		}
		return nil
	},
}

var emergencyAccessApproveCmd = &cobra.Command{
	Use:   "approve [request-id]",
	Short: "Approve an emergency access request",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		if err := c.ApproveEmergencyAccess(ctx, args[0]); err != nil {
			return fmt.Errorf("approve emergency access: %w", err)
		}

		fmt.Printf("Emergency access approved: %s\n", args[0])
		return nil
	},
}

var emergencyAccessDenyCmd = &cobra.Command{
	Use:   "deny [request-id]",
	Short: "Deny an emergency access request",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		if err := c.DenyEmergencyAccess(ctx, args[0]); err != nil {
			return fmt.Errorf("deny emergency access: %w", err)
		}

		fmt.Printf("Emergency access denied: %s\n", args[0])
		return nil
	},
}

var emergencyAccessCompleteCmd = &cobra.Command{
	Use:   "complete [request-id]",
	Short: "Complete an emergency access request",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		if err := c.CompleteEmergencyAccess(ctx, args[0]); err != nil {
			return fmt.Errorf("complete emergency access: %w", err)
		}

		fmt.Printf("Emergency access completed: %s\n", args[0])
		return nil
	},
}

var emergencyAccessVerifyCmd = &cobra.Command{
	Use:   "verify [request-id]",
	Short: "Verify emergency access with CRK signature",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sigStr, _ := cmd.Flags().GetString("signature")
		if sigStr == "" {
			return fmt.Errorf("--signature is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		if err := c.VerifyEmergencyAccess(ctx, args[0], []byte(sigStr)); err != nil {
			return fmt.Errorf("verify emergency access: %w", err)
		}

		fmt.Printf("Emergency access verified: %s\n", args[0])
		return nil
	},
}

var emergencyAccessListCmd = &cobra.Command{
	Use:   "list",
	Short: "List emergency access requests",
	RunE: func(cmd *cobra.Command, args []string) error {
		orgID, _ := cmd.Flags().GetString("org-id")

		c := getClient(cmd)
		ctx := context.Background()

		result, err := c.ListEmergencyAccess(ctx, orgID)
		if err != nil {
			return fmt.Errorf("list emergency access: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Emergency Access Requests (%d):\n", result.Count)
			for _, req := range result.Requests {
				fmt.Printf("  %s  status=%s  reason=%s\n", req.ID, req.Status, req.Reason)
			}
		}
		return nil
	},
}

var emergencyAccessGetCmd = &cobra.Command{
	Use:   "get [request-id]",
	Short: "Get emergency access request details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		req, err := c.GetEmergencyAccess(ctx, args[0])
		if err != nil {
			return fmt.Errorf("get emergency access: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(req, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("ID: %s\nStatus: %s\nReason: %s\nRequested By: %s\nRequested At: %s\n",
				req.ID, req.Status, req.Reason, req.RequestedBy, req.RequestedAt.Format(time.RFC3339))
		}
		return nil
	},
}

func init() {
	emergencyAccessRequestCmd.Flags().String("org-id", "", "Organization ID")
	emergencyAccessRequestCmd.Flags().String("reason", "", "Reason for emergency access")

	emergencyAccessVerifyCmd.Flags().String("signature", "", "CRK signature (base64)")

	emergencyAccessListCmd.Flags().String("org-id", "", "Organization ID")

	emergencyAccessCmd.AddCommand(emergencyAccessRequestCmd)
	emergencyAccessCmd.AddCommand(emergencyAccessApproveCmd)
	emergencyAccessCmd.AddCommand(emergencyAccessDenyCmd)
	emergencyAccessCmd.AddCommand(emergencyAccessCompleteCmd)
	emergencyAccessCmd.AddCommand(emergencyAccessVerifyCmd)
	emergencyAccessCmd.AddCommand(emergencyAccessListCmd)
	emergencyAccessCmd.AddCommand(emergencyAccessGetCmd)

	rootCmd.AddCommand(emergencyAccessCmd)
}

// ============================================================================
// Account Recovery Commands
// ============================================================================

var accountRecoveryCmd = &cobra.Command{
	Use:   "account-recovery",
	Short: "Account recovery management",
	Long:  `Manage account recovery using CRK share reconstruction.`,
}

var accountRecoveryInitiateCmd = &cobra.Command{
	Use:   "initiate",
	Short: "Initiate account recovery",
	RunE: func(cmd *cobra.Command, args []string) error {
		adminID, _ := cmd.Flags().GetString("admin-id")
		reason, _ := cmd.Flags().GetString("reason")
		recoveryType, _ := cmd.Flags().GetString("type")

		if adminID == "" || reason == "" {
			return fmt.Errorf("--admin-id and --reason are required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		recovery, err := c.InitiateRecovery(ctx, client.InitiateRecoveryRequest{
			AdminID:      adminID,
			RecoveryType: recoveryType,
			Reason:       reason,
		})
		if err != nil {
			return fmt.Errorf("initiate recovery: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(recovery, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Recovery initiated: %s (status: %s, shares needed: %d)\n",
				recovery.ID, recovery.Status, recovery.SharesNeeded)
		}
		return nil
	},
}

var accountRecoveryShareCmd = &cobra.Command{
	Use:   "share [recovery-id]",
	Short: "Submit a share for account recovery",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		if err := c.CollectRecoveryShare(ctx, args[0]); err != nil {
			return fmt.Errorf("collect share: %w", err)
		}

		fmt.Printf("Share collected for recovery: %s\n", args[0])
		return nil
	},
}

var accountRecoveryCompleteCmd = &cobra.Command{
	Use:   "complete [recovery-id]",
	Short: "Complete account recovery",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		if err := c.CompleteRecovery(ctx, args[0]); err != nil {
			return fmt.Errorf("complete recovery: %w", err)
		}

		fmt.Printf("Recovery completed: %s\n", args[0])
		return nil
	},
}

func init() {
	accountRecoveryInitiateCmd.Flags().String("admin-id", "", "Admin ID initiating recovery")
	accountRecoveryInitiateCmd.Flags().String("reason", "", "Reason for recovery")
	accountRecoveryInitiateCmd.Flags().String("type", "lost_credentials", "Recovery type (lost_credentials, locked_account)")

	accountRecoveryCmd.AddCommand(accountRecoveryInitiateCmd)
	accountRecoveryCmd.AddCommand(accountRecoveryShareCmd)
	accountRecoveryCmd.AddCommand(accountRecoveryCompleteCmd)

	rootCmd.AddCommand(accountRecoveryCmd)
}

// ============================================================================
// Compliance Commands
// ============================================================================

var complianceCmd = &cobra.Command{
	Use:   "compliance",
	Short: "Compliance report generation",
	Long:  `Generate compliance reports including summaries, GDPR DSAR, and access reviews.`,
}

var complianceSummaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Generate a compliance summary report",
	RunE: func(cmd *cobra.Command, args []string) error {
		since, _ := cmd.Flags().GetString("since")
		until, _ := cmd.Flags().GetString("until")

		c := getClient(cmd)
		ctx := context.Background()

		report, err := c.GenerateComplianceSummary(ctx, client.ComplianceReportRequest{
			Since: since,
			Until: until,
		})
		if err != nil {
			return fmt.Errorf("generate summary: %w", err)
		}

		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(data))
		return nil
	},
}

var complianceDSARCmd = &cobra.Command{
	Use:   "gdpr-dsar",
	Short: "Generate a GDPR Data Subject Access Request report",
	RunE: func(cmd *cobra.Command, args []string) error {
		subjectID, _ := cmd.Flags().GetString("subject-id")
		if subjectID == "" {
			return fmt.Errorf("--subject-id is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		report, err := c.GenerateGDPRDSAR(ctx, client.DSARRequest{
			SubjectID: subjectID,
		})
		if err != nil {
			return fmt.Errorf("generate DSAR: %w", err)
		}

		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(data))
		return nil
	},
}

var complianceAccessReviewCmd = &cobra.Command{
	Use:   "access-review",
	Short: "Generate an access review report",
	RunE: func(cmd *cobra.Command, args []string) error {
		since, _ := cmd.Flags().GetString("since")
		until, _ := cmd.Flags().GetString("until")

		c := getClient(cmd)
		ctx := context.Background()

		report, err := c.GenerateAccessReview(ctx, client.ComplianceReportRequest{
			Since: since,
			Until: until,
		})
		if err != nil {
			return fmt.Errorf("generate access review: %w", err)
		}

		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(data))
		return nil
	},
}

func init() {
	complianceSummaryCmd.Flags().String("since", "", "Start time (RFC3339)")
	complianceSummaryCmd.Flags().String("until", "", "End time (RFC3339)")

	complianceDSARCmd.Flags().String("subject-id", "", "Data subject ID")

	complianceAccessReviewCmd.Flags().String("since", "", "Start time (RFC3339)")
	complianceAccessReviewCmd.Flags().String("until", "", "End time (RFC3339)")

	complianceCmd.AddCommand(complianceSummaryCmd)
	complianceCmd.AddCommand(complianceDSARCmd)
	complianceCmd.AddCommand(complianceAccessReviewCmd)

	rootCmd.AddCommand(complianceCmd)
}

// ============================================================================
// Rotation Policy Commands
// ============================================================================

var rotationPolicyCmd = &cobra.Command{
	Use:   "rotation-policy",
	Short: "Key rotation policy management",
	Long:  `Manage automatic key rotation policies for workspaces.`,
}

var rotationPolicySetCmd = &cobra.Command{
	Use:   "set [workspace-id]",
	Short: "Set a rotation policy for a workspace",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		maxAge, _ := cmd.Flags().GetString("max-age")
		enabled, _ := cmd.Flags().GetBool("enabled")

		if maxAge == "" {
			return fmt.Errorf("--max-age is required")
		}

		c := getClient(cmd)
		ctx := context.Background()

		policy, err := c.SetRotationPolicy(ctx, args[0], client.SetRotationPolicyRequest{
			MaxAge:  maxAge,
			Enabled: enabled,
		})
		if err != nil {
			return fmt.Errorf("set rotation policy: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(policy, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Rotation policy set for workspace %s (max_age=%s, enabled=%v)\n",
				policy.WorkspaceID, policy.MaxAge, policy.Enabled)
		}
		return nil
	},
}

var rotationPolicyGetCmd = &cobra.Command{
	Use:   "get [workspace-id]",
	Short: "Get the rotation policy for a workspace",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		policy, err := c.GetRotationPolicy(ctx, args[0])
		if err != nil {
			return fmt.Errorf("get rotation policy: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(policy, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Workspace: %s\nMax Age: %s\nEnabled: %v\n",
				policy.WorkspaceID, policy.MaxAge, policy.Enabled)
		}
		return nil
	},
}

var rotationPolicyDeleteCmd = &cobra.Command{
	Use:   "delete [workspace-id]",
	Short: "Delete the rotation policy for a workspace",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		if err := c.DeleteRotationPolicy(ctx, args[0]); err != nil {
			return fmt.Errorf("delete rotation policy: %w", err)
		}

		fmt.Printf("Rotation policy deleted for workspace %s\n", args[0])
		return nil
	},
}

var rotationPolicyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all rotation policies",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := getClient(cmd)
		ctx := context.Background()

		result, err := c.ListRotationPolicies(ctx)
		if err != nil {
			return fmt.Errorf("list rotation policies: %w", err)
		}

		jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
		if jsonOutput {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Rotation Policies (%d):\n", result.Count)
			for _, p := range result.Policies {
				fmt.Printf("  workspace=%s  max_age=%s  enabled=%v\n",
					p.WorkspaceID, p.MaxAge, p.Enabled)
			}
		}
		return nil
	},
}

func init() {
	rotationPolicySetCmd.Flags().String("max-age", "", "Maximum key age (e.g. 720h)")
	rotationPolicySetCmd.Flags().Bool("enabled", true, "Enable the policy")

	rotationPolicyCmd.AddCommand(rotationPolicySetCmd)
	rotationPolicyCmd.AddCommand(rotationPolicyGetCmd)
	rotationPolicyCmd.AddCommand(rotationPolicyDeleteCmd)
	rotationPolicyCmd.AddCommand(rotationPolicyListCmd)

	rootCmd.AddCommand(rotationPolicyCmd)
}

// ============================================================================
// Batch Encrypt/Decrypt Helpers
// ============================================================================

func batchEncrypt(c *client.Client, workspaceID, inputDir, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	entries, err := os.ReadDir(inputDir)
	if err != nil {
		return fmt.Errorf("read input directory: %w", err)
	}

	ctx := context.Background()
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		plaintext, err := os.ReadFile(filepath.Join(inputDir, entry.Name()))
		if err != nil {
			return fmt.Errorf("read %s: %w", entry.Name(), err)
		}

		ciphertext, err := c.Encrypt(ctx, workspaceID, plaintext)
		if err != nil {
			return fmt.Errorf("encrypt %s: %w", entry.Name(), err)
		}

		encoded := base64.StdEncoding.EncodeToString(ciphertext)
		outPath := filepath.Join(outputDir, entry.Name()+".enc")
		if err := os.WriteFile(outPath, []byte(encoded), 0644); err != nil {
			return fmt.Errorf("write %s: %w", outPath, err)
		}
		count++
	}

	fmt.Printf("Encrypted %d files to %s\n", count, outputDir)
	return nil
}

func batchDecrypt(c *client.Client, workspaceID, inputDir, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	entries, err := os.ReadDir(inputDir)
	if err != nil {
		return fmt.Errorf("read input directory: %w", err)
	}

	ctx := context.Background()
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		encoded, err := os.ReadFile(filepath.Join(inputDir, entry.Name()))
		if err != nil {
			return fmt.Errorf("read %s: %w", entry.Name(), err)
		}

		ciphertext, err := base64.StdEncoding.DecodeString(string(encoded))
		if err != nil {
			return fmt.Errorf("decode %s: %w", entry.Name(), err)
		}

		plaintext, err := c.Decrypt(ctx, workspaceID, ciphertext)
		if err != nil {
			return fmt.Errorf("decrypt %s: %w", entry.Name(), err)
		}

		outName := strings.TrimSuffix(entry.Name(), ".enc")
		outPath := filepath.Join(outputDir, outName)
		if err := os.WriteFile(outPath, plaintext, 0644); err != nil {
			return fmt.Errorf("write %s: %w", outPath, err)
		}
		count++
	}

	fmt.Printf("Decrypted %d files to %s\n", count, outputDir)
	return nil
}
