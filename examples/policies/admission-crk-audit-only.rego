# Workspace admission policy: CRK-protected workspace with audit logging.
#
# For CRK-protected workspaces, the Go tier already enforces explicit admission.
# This policy adds no further restrictions but serves as a template showing how
# to inspect the admission tier metadata for CRK workspaces.
#
# In practice, you might extend this to restrict CRK access to specific actors,
# require additional metadata fields, or enforce time windows.
#
# Upload via:
#   sovra policy create \
#     --name admission-crk-audit-only \
#     --workspace <workspace-id> \
#     --rego-file examples/policies/admission-crk-audit-only.rego

package sovra.workspace

import rego.v1

default allow = false

# Allow all admitted users for CRK-protected workspaces
# (Go tier already verified explicit admission)
allow if {
    input.operation == "admit"
    input.metadata.crk_protected == true
    input.metadata.admission_tier == "crk_explicit"
}

# Example: restrict CRK workspace access to specific actors
# Uncomment and customize as needed:
#
# crk_authorized_actors := {"admin-001", "admin-002", "service-pipeline"}
#
# allow if {
#     input.operation == "admit"
#     input.metadata.crk_protected == true
#     crk_authorized_actors[input.actor]
# }

# Non-admission operations pass through
allow if {
    input.operation != "admit"
}
