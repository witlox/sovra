package vault

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// PKIClient provides operations for the Vault PKI secrets engine.
type PKIClient struct {
	*Client
	mountPath string
}

// CSRRequest holds parameters for generating a CSR.
type CSRRequest struct {
	CommonName          string
	AltNames            []string
	IPSANs              []string
	URISANs             []string
	OtherSANs           []string
	Organization        []string
	OrganizationalUnit  []string
	Country             []string
	Locality            []string
	Province            []string
	StreetAddress       []string
	PostalCode          []string
	KeyType             string
	KeyBits             int
	AddBasicConstraints bool
}

// CSRResponse holds the response from CSR generation.
type CSRResponse struct {
	CSR        string
	PrivateKey string
}

// CertificateRequest holds parameters for issuing or signing a certificate.
type CertificateRequest struct {
	CommonName        string
	AltNames          []string
	IPSANs            []string
	URISANs           []string
	TTL               time.Duration
	Format            string
	PrivateKeyFormat  string
	ExcludeCNFromSANs bool
}

// Certificate holds a certificate response from Vault.
type Certificate struct {
	Certificate    string
	PrivateKey     string
	PrivateKeyType string
	SerialNumber   string
	IssuingCA      string
	CAChain        []string
	Expiration     time.Time
}

// RoleConfig holds configuration for a PKI role.
type RoleConfig struct {
	TTL                    time.Duration
	MaxTTL                 time.Duration
	AllowLocalhost         bool
	AllowedDomains         []string
	AllowedDomainsTemplate bool
	AllowBareDomains       bool
	AllowSubdomains        bool
	AllowGlobDomains       bool
	AllowAnyName           bool
	AllowIPSANs            bool
	AllowedURISANs         []string
	AllowedOtherSANs       []string
	ServerFlag             bool
	ClientFlag             bool
	CodeSigningFlag        bool
	EmailProtectionFlag    bool
	KeyType                string
	KeyBits                int
	KeyUsage               []string
	ExtKeyUsage            []string
	ExtKeyUsageOIDs        []string
	UseCSRCommonName       bool
	UseCSRSANs             bool
	RequireCN              bool
	BasicConstraintsValid  bool
	NotBeforeDuration      time.Duration
}

// PKI returns a PKIClient for the given mount path.
func (c *Client) PKI(mountPath string) *PKIClient {
	if mountPath == "" {
		mountPath = "pki"
	}
	return &PKIClient{
		Client:    c,
		mountPath: mountPath,
	}
}

// Enable enables the PKI secrets engine at the configured mount path.
func (p *PKIClient) Enable(ctx context.Context, options map[string]interface{}) error {
	return p.EnableSecretsEngine(ctx, p.mountPath, "pki", options)
}

// GenerateRoot generates a new self-signed root CA.
func (p *PKIClient) GenerateRoot(ctx context.Context, commonName string, ttl time.Duration, keyType string, keyBits int) (*Certificate, error) {
	path := fmt.Sprintf("%s/root/generate/internal", p.mountPath)

	data := map[string]interface{}{
		"common_name": commonName,
		"ttl":         ttl.String(),
	}

	if keyType != "" {
		data["key_type"] = keyType
	}
	if keyBits > 0 {
		data["key_bits"] = keyBits
	}

	secret, err := p.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to generate root CA", "common_name", commonName, "error", err)
		return nil, fmt.Errorf("vault: failed to generate root CA: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: no response from root CA generation")
	}

	cert := &Certificate{}
	if v, ok := secret.Data["certificate"].(string); ok {
		cert.Certificate = v
	}
	if v, ok := secret.Data["issuing_ca"].(string); ok {
		cert.IssuingCA = v
	}
	if v, ok := secret.Data["serial_number"].(string); ok {
		cert.SerialNumber = v
	}

	p.logger.InfoContext(ctx, "root CA generated", "common_name", commonName, "path", p.mountPath)
	return cert, nil
}

// GenerateIntermediate generates a new intermediate CA CSR.
func (p *PKIClient) GenerateIntermediate(ctx context.Context, commonName string, keyType string, keyBits int) (*CSRResponse, error) {
	path := fmt.Sprintf("%s/intermediate/generate/internal", p.mountPath)

	data := map[string]interface{}{
		"common_name": commonName,
	}

	if keyType != "" {
		data["key_type"] = keyType
	}
	if keyBits > 0 {
		data["key_bits"] = keyBits
	}

	secret, err := p.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to generate intermediate CSR", "common_name", commonName, "error", err)
		return nil, fmt.Errorf("vault: failed to generate intermediate CSR: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: no response from intermediate CSR generation")
	}

	resp := &CSRResponse{}
	if v, ok := secret.Data["csr"].(string); ok {
		resp.CSR = v
	}

	p.logger.InfoContext(ctx, "intermediate CSR generated", "common_name", commonName)
	return resp, nil
}

// SignIntermediate signs an intermediate CA CSR with the root CA.
func (p *PKIClient) SignIntermediate(ctx context.Context, csr string, commonName string, ttl time.Duration) (*Certificate, error) {
	path := fmt.Sprintf("%s/root/sign-intermediate", p.mountPath)

	data := map[string]interface{}{
		"csr":         csr,
		"common_name": commonName,
		"ttl":         ttl.String(),
	}

	secret, err := p.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to sign intermediate", "common_name", commonName, "error", err)
		return nil, fmt.Errorf("vault: failed to sign intermediate: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: no response from sign intermediate")
	}

	cert := &Certificate{}
	if v, ok := secret.Data["certificate"].(string); ok {
		cert.Certificate = v
	}
	if v, ok := secret.Data["issuing_ca"].(string); ok {
		cert.IssuingCA = v
	}
	if v, ok := secret.Data["serial_number"].(string); ok {
		cert.SerialNumber = v
	}
	if chain, ok := secret.Data["ca_chain"].([]interface{}); ok {
		for _, c := range chain {
			if s, ok := c.(string); ok {
				cert.CAChain = append(cert.CAChain, s)
			}
		}
	}

	p.logger.InfoContext(ctx, "intermediate signed", "common_name", commonName)
	return cert, nil
}

// SetSignedIntermediate sets a signed intermediate CA certificate.
func (p *PKIClient) SetSignedIntermediate(ctx context.Context, certificate string) error {
	path := fmt.Sprintf("%s/intermediate/set-signed", p.mountPath)

	data := map[string]interface{}{
		"certificate": certificate,
	}

	_, err := p.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to set signed intermediate", "error", err)
		return fmt.Errorf("vault: failed to set signed intermediate: %w", err)
	}

	p.logger.InfoContext(ctx, "signed intermediate set", "path", p.mountPath)
	return nil
}

// GenerateCSR generates a Certificate Signing Request.
func (p *PKIClient) GenerateCSR(ctx context.Context, req *CSRRequest) (*CSRResponse, error) {
	path := fmt.Sprintf("%s/intermediate/generate/internal", p.mountPath)

	data := map[string]interface{}{
		"common_name": req.CommonName,
	}

	if len(req.AltNames) > 0 {
		data["alt_names"] = joinStrings(req.AltNames)
	}
	if len(req.IPSANs) > 0 {
		data["ip_sans"] = joinStrings(req.IPSANs)
	}
	if len(req.URISANs) > 0 {
		data["uri_sans"] = joinStrings(req.URISANs)
	}
	if len(req.Organization) > 0 {
		data["organization"] = joinStrings(req.Organization)
	}
	if len(req.OrganizationalUnit) > 0 {
		data["ou"] = joinStrings(req.OrganizationalUnit)
	}
	if len(req.Country) > 0 {
		data["country"] = joinStrings(req.Country)
	}
	if len(req.Locality) > 0 {
		data["locality"] = joinStrings(req.Locality)
	}
	if len(req.Province) > 0 {
		data["province"] = joinStrings(req.Province)
	}
	if req.KeyType != "" {
		data["key_type"] = req.KeyType
	}
	if req.KeyBits > 0 {
		data["key_bits"] = req.KeyBits
	}
	data["add_basic_constraints"] = req.AddBasicConstraints

	secret, err := p.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to generate CSR", "common_name", req.CommonName, "error", err)
		return nil, fmt.Errorf("vault: failed to generate CSR: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: no response from CSR generation")
	}

	resp := &CSRResponse{}
	if v, ok := secret.Data["csr"].(string); ok {
		resp.CSR = v
	}
	if v, ok := secret.Data["private_key"].(string); ok {
		resp.PrivateKey = v
	}

	p.logger.InfoContext(ctx, "CSR generated", "common_name", req.CommonName)
	return resp, nil
}

// CreateRole creates a PKI role for issuing certificates.
func (p *PKIClient) CreateRole(ctx context.Context, name string, config *RoleConfig) error {
	path := fmt.Sprintf("%s/roles/%s", p.mountPath, name)

	data := map[string]interface{}{}

	if config != nil {
		if config.TTL > 0 {
			data["ttl"] = config.TTL.String()
		}
		if config.MaxTTL > 0 {
			data["max_ttl"] = config.MaxTTL.String()
		}
		data["allow_localhost"] = config.AllowLocalhost
		if len(config.AllowedDomains) > 0 {
			data["allowed_domains"] = config.AllowedDomains
		}
		data["allowed_domains_template"] = config.AllowedDomainsTemplate
		data["allow_bare_domains"] = config.AllowBareDomains
		data["allow_subdomains"] = config.AllowSubdomains
		data["allow_glob_domains"] = config.AllowGlobDomains
		data["allow_any_name"] = config.AllowAnyName
		data["allow_ip_sans"] = config.AllowIPSANs
		if len(config.AllowedURISANs) > 0 {
			data["allowed_uri_sans"] = config.AllowedURISANs
		}
		data["server_flag"] = config.ServerFlag
		data["client_flag"] = config.ClientFlag
		data["code_signing_flag"] = config.CodeSigningFlag
		data["email_protection_flag"] = config.EmailProtectionFlag
		if config.KeyType != "" {
			data["key_type"] = config.KeyType
		}
		if config.KeyBits > 0 {
			data["key_bits"] = config.KeyBits
		}
		if len(config.KeyUsage) > 0 {
			data["key_usage"] = config.KeyUsage
		}
		if len(config.ExtKeyUsage) > 0 {
			data["ext_key_usage"] = config.ExtKeyUsage
		}
		data["use_csr_common_name"] = config.UseCSRCommonName
		data["use_csr_sans"] = config.UseCSRSANs
		data["require_cn"] = config.RequireCN
		data["basic_constraints_valid_for_non_ca"] = config.BasicConstraintsValid
		if config.NotBeforeDuration > 0 {
			data["not_before_duration"] = config.NotBeforeDuration.String()
		}
	}

	_, err := p.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to create PKI role", "name", name, "error", err)
		return fmt.Errorf("vault: failed to create PKI role %s: %w", name, err)
	}

	p.logger.InfoContext(ctx, "PKI role created", "name", name, "path", p.mountPath)
	return nil
}

// ReadRole reads a PKI role configuration.
func (p *PKIClient) ReadRole(ctx context.Context, name string) (map[string]interface{}, error) {
	path := fmt.Sprintf("%s/roles/%s", p.mountPath, name)

	secret, err := p.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to read PKI role", "name", name, "error", err)
		return nil, fmt.Errorf("vault: failed to read PKI role %s: %w", name, err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: PKI role %s not found", name)
	}

	return secret.Data, nil
}

// DeleteRole deletes a PKI role.
func (p *PKIClient) DeleteRole(ctx context.Context, name string) error {
	path := fmt.Sprintf("%s/roles/%s", p.mountPath, name)

	_, err := p.client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to delete PKI role", "name", name, "error", err)
		return fmt.Errorf("vault: failed to delete PKI role %s: %w", name, err)
	}

	p.logger.InfoContext(ctx, "PKI role deleted", "name", name)
	return nil
}

// ListRoles lists all PKI roles.
func (p *PKIClient) ListRoles(ctx context.Context) ([]string, error) {
	path := fmt.Sprintf("%s/roles", p.mountPath)

	secret, err := p.client.Logical().ListWithContext(ctx, path)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to list PKI roles", "error", err)
		return nil, fmt.Errorf("vault: failed to list PKI roles: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return []string{}, nil
	}

	result := make([]string, 0, len(keys))
	for _, k := range keys {
		if s, ok := k.(string); ok {
			result = append(result, s)
		}
	}

	return result, nil
}

// IssueCertificate issues a new certificate using a role.
func (p *PKIClient) IssueCertificate(ctx context.Context, role string, req *CertificateRequest) (*Certificate, error) {
	path := fmt.Sprintf("%s/issue/%s", p.mountPath, role)

	data := map[string]interface{}{
		"common_name": req.CommonName,
	}

	if len(req.AltNames) > 0 {
		data["alt_names"] = joinStrings(req.AltNames)
	}
	if len(req.IPSANs) > 0 {
		data["ip_sans"] = joinStrings(req.IPSANs)
	}
	if len(req.URISANs) > 0 {
		data["uri_sans"] = joinStrings(req.URISANs)
	}
	if req.TTL > 0 {
		data["ttl"] = req.TTL.String()
	}
	if req.Format != "" {
		data["format"] = req.Format
	}
	if req.PrivateKeyFormat != "" {
		data["private_key_format"] = req.PrivateKeyFormat
	}
	data["exclude_cn_from_sans"] = req.ExcludeCNFromSANs

	secret, err := p.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to issue certificate", "role", role, "common_name", req.CommonName, "error", err)
		return nil, fmt.Errorf("vault: failed to issue certificate: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: no response from certificate issuance")
	}

	cert := parseCertificateResponse(secret.Data)
	p.logger.InfoContext(ctx, "certificate issued", "role", role, "common_name", req.CommonName, "serial", cert.SerialNumber)
	return cert, nil
}

// SignCertificate signs a CSR using a role.
func (p *PKIClient) SignCertificate(ctx context.Context, role string, csr string, commonName string, ttl time.Duration) (*Certificate, error) {
	path := fmt.Sprintf("%s/sign/%s", p.mountPath, role)

	data := map[string]interface{}{
		"csr":         csr,
		"common_name": commonName,
	}

	if ttl > 0 {
		data["ttl"] = ttl.String()
	}

	secret, err := p.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to sign certificate", "role", role, "common_name", commonName, "error", err)
		return nil, fmt.Errorf("vault: failed to sign certificate: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: no response from certificate signing")
	}

	cert := parseCertificateResponse(secret.Data)
	p.logger.InfoContext(ctx, "certificate signed", "role", role, "common_name", commonName, "serial", cert.SerialNumber)
	return cert, nil
}

// SignVerbatim signs a CSR without a role, using the CSR as-is.
func (p *PKIClient) SignVerbatim(ctx context.Context, csr string, ttl time.Duration) (*Certificate, error) {
	path := fmt.Sprintf("%s/sign-verbatim", p.mountPath)

	data := map[string]interface{}{
		"csr": csr,
	}

	if ttl > 0 {
		data["ttl"] = ttl.String()
	}

	secret, err := p.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to sign certificate verbatim", "error", err)
		return nil, fmt.Errorf("vault: failed to sign certificate verbatim: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: no response from verbatim signing")
	}

	cert := parseCertificateResponse(secret.Data)
	p.logger.InfoContext(ctx, "certificate signed verbatim", "serial", cert.SerialNumber)
	return cert, nil
}

// RevokeCertificate revokes a certificate by serial number.
func (p *PKIClient) RevokeCertificate(ctx context.Context, serialNumber string) error {
	path := fmt.Sprintf("%s/revoke", p.mountPath)

	data := map[string]interface{}{
		"serial_number": serialNumber,
	}

	_, err := p.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to revoke certificate", "serial", serialNumber, "error", err)
		return fmt.Errorf("vault: failed to revoke certificate %s: %w", serialNumber, err)
	}

	p.logger.InfoContext(ctx, "certificate revoked", "serial", serialNumber)
	return nil
}

// ReadCertificate reads a certificate by serial number.
func (p *PKIClient) ReadCertificate(ctx context.Context, serialNumber string) (*Certificate, error) {
	path := fmt.Sprintf("%s/cert/%s", p.mountPath, serialNumber)

	secret, err := p.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to read certificate", "serial", serialNumber, "error", err)
		return nil, fmt.Errorf("vault: failed to read certificate %s: %w", serialNumber, err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: certificate %s not found", serialNumber)
	}

	cert := &Certificate{SerialNumber: serialNumber}
	if v, ok := secret.Data["certificate"].(string); ok {
		cert.Certificate = v
	}

	return cert, nil
}

// ListCertificates lists all certificate serial numbers.
func (p *PKIClient) ListCertificates(ctx context.Context) ([]string, error) {
	path := fmt.Sprintf("%s/certs", p.mountPath)

	secret, err := p.client.Logical().ListWithContext(ctx, path)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to list certificates", "error", err)
		return nil, fmt.Errorf("vault: failed to list certificates: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return []string{}, nil
	}

	result := make([]string, 0, len(keys))
	for _, k := range keys {
		if s, ok := k.(string); ok {
			result = append(result, s)
		}
	}

	return result, nil
}

// GetCAChain returns the CA certificate chain.
func (p *PKIClient) GetCAChain(ctx context.Context) (string, error) {
	path := fmt.Sprintf("%s/ca_chain", p.mountPath)

	secret, err := p.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to get CA chain", "error", err)
		return "", fmt.Errorf("vault: failed to get CA chain: %w", err)
	}

	if secret == nil || secret.Data == nil {
		// Try the non-JSON endpoint using Logical API
		secret, err = p.client.Logical().ReadWithContext(ctx, fmt.Sprintf("%s/ca_chain", p.mountPath))
		if err != nil {
			return "", fmt.Errorf("vault: failed to get CA chain: %w", err)
		}
		if secret == nil || secret.Data == nil {
			return "", nil
		}
	}

	if chain, ok := secret.Data["ca_chain"].(string); ok {
		return chain, nil
	}

	return "", nil
}

// SetURLs configures the issuing certificate URLs.
func (p *PKIClient) SetURLs(ctx context.Context, issuingCertificates, crlDistributionPoints, ocspServers []string) error {
	path := fmt.Sprintf("%s/config/urls", p.mountPath)

	data := map[string]interface{}{}
	if len(issuingCertificates) > 0 {
		data["issuing_certificates"] = issuingCertificates
	}
	if len(crlDistributionPoints) > 0 {
		data["crl_distribution_points"] = crlDistributionPoints
	}
	if len(ocspServers) > 0 {
		data["ocsp_servers"] = ocspServers
	}

	_, err := p.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to set PKI URLs", "error", err)
		return fmt.Errorf("vault: failed to set PKI URLs: %w", err)
	}

	p.logger.InfoContext(ctx, "PKI URLs configured", "path", p.mountPath)
	return nil
}

// TidyCertificates tidies up the certificate store.
func (p *PKIClient) TidyCertificates(ctx context.Context, tidyCertStore, tidyRevokedCerts bool, safetyBuffer time.Duration) error {
	path := fmt.Sprintf("%s/tidy", p.mountPath)

	data := map[string]interface{}{
		"tidy_cert_store":    tidyCertStore,
		"tidy_revoked_certs": tidyRevokedCerts,
	}
	if safetyBuffer > 0 {
		data["safety_buffer"] = safetyBuffer.String()
	}

	_, err := p.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to tidy certificates", "error", err)
		return fmt.Errorf("vault: failed to tidy certificates: %w", err)
	}

	p.logger.InfoContext(ctx, "certificate tidy started", "path", p.mountPath)
	return nil
}

// ParseCertificate parses a PEM-encoded certificate.
func ParseCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

// Helper functions

func parseCertificateResponse(data map[string]interface{}) *Certificate {
	cert := &Certificate{}
	if v, ok := data["certificate"].(string); ok {
		cert.Certificate = v
	}
	if v, ok := data["private_key"].(string); ok {
		cert.PrivateKey = v
	}
	if v, ok := data["private_key_type"].(string); ok {
		cert.PrivateKeyType = v
	}
	if v, ok := data["serial_number"].(string); ok {
		cert.SerialNumber = v
	}
	if v, ok := data["issuing_ca"].(string); ok {
		cert.IssuingCA = v
	}
	if chain, ok := data["ca_chain"].([]interface{}); ok {
		for _, c := range chain {
			if s, ok := c.(string); ok {
				cert.CAChain = append(cert.CAChain, s)
			}
		}
	}
	if exp, ok := data["expiration"].(float64); ok {
		cert.Expiration = time.Unix(int64(exp), 0)
	}
	return cert
}

func joinStrings(s []string) string {
	if len(s) == 0 {
		return ""
	}
	result := s[0]
	for i := 1; i < len(s); i++ {
		result += "," + s[i]
	}
	return result
}
