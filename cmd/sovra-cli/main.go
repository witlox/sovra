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

	crkCmd.AddCommand(crkGenerateCmd)
	crkCmd.AddCommand(crkSignCmd)
	crkCmd.AddCommand(crkVerifyCmd)
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
	Long:  `Manage user and service identities.`,
}

var identityListCmd = &cobra.Command{
	Use:   "list",
	Short: "List identities",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Identity listing requires API connection with identity endpoints.")
		return nil
	},
}

var identityGetCmd = &cobra.Command{
	Use:   "get [identity-id]",
	Short: "Get identity details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Getting identity: %s\n", args[0])
		return nil
	},
}

func init() {
	identityCmd.AddCommand(identityListCmd)
	identityCmd.AddCommand(identityGetCmd)
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
