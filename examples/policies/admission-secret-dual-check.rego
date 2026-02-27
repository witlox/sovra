# Workspace admission policy: additional restrictions for SECRET workspaces.
#
# This policy demonstrates layering OPA restrictions on SECRET-tier workspaces.
# The Go tier already requires group membership + explicit admission for SECRET.
# This policy adds:
#   - Business hours restriction
#   - Organization allowlist
#   - Group membership verification (belt-and-suspenders)
#
# Upload via:
#   sovra policy create \
#     --name admission-secret-dual-check \
#     --workspace <workspace-id> \
#     --rego-file examples/policies/admission-secret-dual-check.rego

package sovra.workspace

import rego.v1

default allow = false

# Approved organizations for this SECRET workspace
approved_orgs := {"org-eth-zurich", "org-epfl"}

allow if {
    input.operation == "admit"

    # Must be SECRET tier (redundant with Go, but explicit for clarity)
    input.metadata.classification == "SECRET"

    # Must be an approved organization
    approved_orgs[input.metadata.org_id]

    # Must have verified group membership
    input.metadata.group_membership == true

    # Business hours only (09:00–18:00 UTC, Monday–Friday)
    current_hour := time.clock(time.now_ns())[0]
    current_hour >= 9
    current_hour < 18
    day := time.weekday(time.now_ns())
    day != "Saturday"
    day != "Sunday"
}

# Non-admission operations pass through
allow if {
    input.operation != "admit"
}
