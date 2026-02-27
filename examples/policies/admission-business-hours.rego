# Workspace admission policy: restrict access to business hours.
#
# This policy layers on top of the Go-based tier enforcement.
# It can only further restrict access, never loosen it.
#
# Tier enforcement (Go) runs first:
#   - CONFIDENTIAL: group membership sufficient
#   - SECRET: group membership + explicit admission
#   - CRK-protected: explicit admission only
#
# If the tier check passes, this policy is evaluated with input:
#   {
#     "actor":     "<identity-id>",
#     "operation": "admit",
#     "workspace": "<workspace-id>",
#     "metadata": {
#       "classification":   "SECRET",
#       "crk_protected":    false,
#       "admission_tier":   "secret_explicit",
#       "org_id":           "<org-id>",
#       "group_membership": true
#     }
#   }
#
# Upload via:
#   sovra policy create \
#     --name admission-business-hours \
#     --workspace <workspace-id> \
#     --rego-file examples/policies/admission-business-hours.rego

package sovra.workspace

import rego.v1

default allow = false

# Allow admission only during business hours (09:00–18:00 UTC)
allow if {
    input.operation == "admit"
    current_hour := time.clock(time.now_ns())[0]
    current_hour >= 9
    current_hour < 18
}

# Non-admission operations are not affected by this policy
allow if {
    input.operation != "admit"
}
