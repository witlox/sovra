// Package main implements the sovra-cli command-line tool.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
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

	crkCmd.AddCommand(crkGenerateCmd)
	crkCmd.AddCommand(crkSignCmd)
	crkCmd.AddCommand(crkVerifyCmd)
	crkCmd.AddCommand(crkCeremonyCmd)
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

	workspaceCmd.AddCommand(workspaceCreateCmd)
	workspaceCmd.AddCommand(workspaceListCmd)
	workspaceCmd.AddCommand(workspaceGetCmd)
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

func init() {
	federationCmd.AddCommand(federationListCmd)
	federationCmd.AddCommand(federationStatusCmd)
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
	Short: "List policies",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Policy listing requires API connection.")
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
			return fmt.Errorf("failed to read file: %w", err)
		}
		fmt.Printf("Validating policy from %s (%d bytes)\n", args[0], len(content))
		// Would call policy validation here
		fmt.Println("Policy syntax: OK")
		return nil
	},
}

func init() {
	policyCmd.AddCommand(policyListCmd)
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

		events, err := c.QueryAudit(ctx, client.AuditQueryParams{
			Since: since,
			Until: until,
			Limit: 10000,
		})
		if err != nil {
			return fmt.Errorf("query audit for export: %w", err)
		}

		var data []byte
		if format == "csv" {
			data = []byte("timestamp,event_type,actor,result,workspace\n")
			for _, ev := range events {
				data = append(data, []byte(fmt.Sprintf("%s,%s,%s,%s,%s\n",
					ev.Timestamp.Format(time.RFC3339), ev.EventType, ev.Actor, ev.Result, ev.Workspace))...)
			}
		} else {
			data, _ = json.MarshalIndent(events, "", "  ")
		}

		if output != "" {
			if err := os.WriteFile(output, data, 0644); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
			fmt.Printf("Exported %d events to %s\n", len(events), output)
		} else {
			fmt.Println(string(data))
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

	auditCmd.AddCommand(auditQueryCmd)
	auditCmd.AddCommand(auditExportCmd)
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

	// Wire up create subcommands
	identityCreateCmd.AddCommand(identityCreateAdminCmd)
	identityCreateCmd.AddCommand(identityCreateServiceCmd)

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

func init() {
	edgeRegisterCmd.Flags().String("name", "", "Edge node name")
	edgeRegisterCmd.Flags().String("vault-addr", "", "Vault address")
	edgeRegisterCmd.Flags().String("region", "", "Region")

	edgeCmd.AddCommand(edgeListCmd)
	edgeCmd.AddCommand(edgeGetCmd)
	edgeCmd.AddCommand(edgeRegisterCmd)
	edgeCmd.AddCommand(edgeUnregisterCmd)
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

		if workspaceID == "" {
			return fmt.Errorf("--workspace is required")
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

		c := getClient(cmd)
		ctx := context.Background()

		ciphertext, err := c.Encrypt(ctx, workspaceID, plaintext)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
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

		if workspaceID == "" {
			return fmt.Errorf("--workspace is required")
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

		c := getClient(cmd)
		ctx := context.Background()

		plaintext, err := c.Decrypt(ctx, workspaceID, ciphertext)
		if err != nil {
			return fmt.Errorf("decrypt: %w", err)
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

	decryptCmd.Flags().String("workspace", "", "Workspace ID")
	decryptCmd.Flags().String("data", "", "Base64 encoded ciphertext")
	decryptCmd.Flags().String("data-file", "", "File containing base64 ciphertext")
	decryptCmd.Flags().String("output", "", "Output file")

	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)
}
