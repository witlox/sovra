# Workspace admission policy: restrict to specific organizations.
#
# Use this policy to limit which federated partner organizations can
# access a workspace, on top of the standard tier enforcement.
#
# Upload via:
#   sovra policy create \
#     --name admission-org-allowlist \
#     --workspace <workspace-id> \
#     --rego-file examples/policies/admission-org-allowlist.rego

package sovra.workspace

import rego.v1

default allow = false

# Allowed organizations for this workspace
allowed_orgs := {"org-eth-zurich", "org-epfl", "org-unige"}

# Allow admission only from approved organizations
allow if {
    input.operation == "admit"
    allowed_orgs[input.metadata.org_id]
}

# Non-admission operations are not affected by this policy
allow if {
    input.operation != "admit"
}
