# Changelog

## [Unreleased]

### Added

#### Client SDK (`pkg/client`)
- **Workspace**: `DeleteWorkspace`, `AddParticipant`, `RemoveParticipant`, `ArchiveWorkspace` methods
- **Federation**: `InitFederation`, `EstablishFederation`, `RevokeFederation`, `FederationHealth`, `ImportFederationCertificate` methods
- **Policy**: `CreatePolicy`, `GetPolicy`, `UpdatePolicy`, `DeletePolicy`, `GetPoliciesForWorkspace`, `EvaluatePolicy`, `ValidatePolicy` methods
- **Audit**: `GetAuditEvent`, `ExportAudit` (server-side), `GetAuditStats`, `VerifyAuditIntegrity` methods
- **Edge**: `GetEdgeHealth`, `SyncEdgePolicies`, `SyncEdgeKeys`, `GetEdgeSyncStatus` methods
- **CRK**: `RotateCRK` method
- **Encryption**: `EncryptWithContext`, `DecryptWithContext` methods with `Context map[string]string` field on request types
- `requestRaw` helper for endpoints returning non-JSON responses

#### CLI (`cmd/sovra-cli`)
- **Workspace**: `delete`, `accept-invitation`, `decline-invitation`, `add-participant`, `remove-participant`, `archive` commands
- **Federation**: `init`, `establish`, `revoke`, `health`, `import-cert` commands
- **Policy**: `get`, `create`, `update`, `delete`, `evaluate` commands
- **Audit**: `get`, `stats`, `verify` commands
- **Edge**: `health`, `sync-policies`, `sync-keys`, `sync-status` commands
- **CRK**: `rotate` command
- **Top-level**: `health` command for API health checks
- **Config**: `config show` and `config validate` commands
- **Identity**: `identity create user-sso` command
- **Encrypt/Decrypt**: `--input-dir`/`--output-dir` flags for batch mode, `--context` flag for encryption context

#### Tests
- 29 new client unit tests covering all new methods

### Fixed
- `policy list` stub replaced with real API call (`GetPoliciesForWorkspace`)
- `policy validate` stub replaced with server-side validation (`ValidatePolicy`)
- `audit export` now uses server-side export API instead of client-side formatting

### Changed
- Handler `EncryptRequest`/`DecryptRequest` types extended with `Context` field (`internal/api/handlers.go`)
