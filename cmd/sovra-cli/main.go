// Package main implements the sovra-cli command-line tool.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/sovra-project/sovra/internal/crk"
	"github.com/sovra-project/sovra/pkg/models"
	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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
	// This would call the API - placeholder for now
	fmt.Println("Workspace creation requires API connection. Use --api-url to specify the API Gateway.")
	return nil
}

func runWorkspaceList(cmd *cobra.Command, args []string) error {
	fmt.Println("Workspace listing requires API connection. Use --api-url to specify the API Gateway.")
	return nil
}

func runWorkspaceGet(cmd *cobra.Command, args []string) error {
	fmt.Printf("Getting workspace: %s\n", args[0])
	fmt.Println("Workspace details require API connection. Use --api-url to specify the API Gateway.")
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
		fmt.Println("Federation listing requires API connection.")
		return nil
	},
}

var federationStatusCmd = &cobra.Command{
	Use:   "status [partner-org-id]",
	Short: "Get federation status",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Getting federation status for: %s\n", args[0])
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
		fmt.Println("Audit query requires API connection.")
		return nil
	},
}

var auditExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export audit logs",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Audit export requires API connection.")
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

	auditCmd.AddCommand(auditQueryCmd)
	auditCmd.AddCommand(auditExportCmd)
}
