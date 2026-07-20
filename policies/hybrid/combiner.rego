# QuantumForge — Phase 3: Cryptographic Agility Architecture
#
# Conftest deployment gate for AWS load-balancer listeners and KMS signing
# keys. Approved algorithms and policies are exact allowlists. Exceptions are
# allowed only when their owner, approver, controls, and expiration validate.

package main

import rego.v1
import data.quantumforge.governance

default runtime_config := {}

runtime_config := data.quantumforge_config if data.quantumforge_config

default enforce_cutover := true

enforce_cutover := value if {
	value := object.get(runtime_config, "enforce_cutover", true)
	is_boolean(value)
}

approved_pqc_signing_specs := {"ML_DSA_44", "ML_DSA_65", "ML_DSA_87"}

approved_hybrid_tls_policies := {
	"ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-3-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09",
}

deny contains "input must be a Terraform plan JSON object" if {
	not is_object(input)
}

deny contains "input.resource_changes must be an array" if {
	is_object(input)
	not is_array(object.get(input, "resource_changes", null))
}

valid_change_after(change) if {
	is_object(object.get(change, "after", null))
}

valid_change_after(change) if {
	object.get(change, "after", null) == null
	actions := object.get(change, "actions", [])
	"delete" in actions
}

valid_change_actions(change) if {
	actions := object.get(change, "actions", null)
	is_array(actions)
	count(actions) > 0
	every action in actions {
		is_string(action)
		trim_space(action) != ""
	}
}

valid_resource_change(rc) if {
	is_object(rc)
	address := object.get(rc, "address", null)
	is_string(address)
	trim_space(address) != ""
	type_name := object.get(rc, "type", null)
	is_string(type_name)
	trim_space(type_name) != ""
	change := object.get(rc, "change", null)
	is_object(change)
	valid_change_actions(change)
	valid_change_after(change)
}

deny contains "input.resource_changes contains a malformed entry" if {
	is_array(object.get(input, "resource_changes", null))
	some rc in input.resource_changes
	not valid_resource_change(rc)
}

# Deployment exceptions are evaluated against OPA's runtime clock. Policy data
# cannot freeze or backdate expiry checks.
assessment_time := time.format([time.now_ns(), "UTC", "2006-01-02T15:04:05Z07:00"])
exceptions := object.get(runtime_config, "exceptions", [])

is_exempt(address) if {
	some exception in exceptions
	object.get(exception, "asset_id", "") == address
	governance.is_valid_exception(exception, assessment_time)
}

# Invalid or expired exception records are themselves deployment failures.
deny contains msg if {
	some exception in exceptions
	errors := governance.exception_errors(exception, assessment_time)
	count(errors) > 0
	msg := sprintf(
		"exception %s for %s is invalid: %s",
		[
			object.get(exception, "id", "unknown"),
			object.get(exception, "asset_id", "unknown"),
			concat(", ", sort(errors)),
		],
	)
}

deny contains msg if {
	some id in governance.duplicate_exception_ids(exceptions)
	msg := sprintf("exception id %s is duplicated", [id])
}

# ALB HTTPS and NLB TLS resources are both evaluated by policy, even though the
# reusable Terraform module in this repository is intentionally ALB-only.
deny contains msg if {
	enforce_cutover
	some rc in input.resource_changes
	rc.type == "aws_lb_listener"
	after := object.get(rc.change, "after", null)
	is_object(after)
	protocol := object.get(after, "protocol", "")
	protocol in {"HTTPS", "TLS"}
	policy := object.get(after, "ssl_policy", "")
	not policy in approved_hybrid_tls_policies
	not is_exempt(rc.address)
	msg := sprintf(
		"%s provisions unapproved %s policy %q after cutover; select an explicitly approved hybrid PQ-TLS policy or a valid time-bounded exception",
		[rc.address, protocol, policy],
	)
}

deny contains msg if {
	enforce_cutover
	some rc in input.resource_changes
	rc.type == "aws_kms_key"
	after := object.get(rc.change, "after", null)
	is_object(after)
	object.get(after, "key_usage", "") == "SIGN_VERIFY"
	spec := object.get(after, "customer_master_key_spec", "")
	not spec in approved_pqc_signing_specs
	not is_exempt(rc.address)
	msg := sprintf(
		"%s provisions unapproved signing key spec %q; select ML_DSA_44, ML_DSA_65, or ML_DSA_87, or provide a valid time-bounded exception",
		[rc.address, spec],
	)
}

warn contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_kms_key"
	after := object.get(rc.change, "after", null)
	is_object(after)
	after.customer_master_key_spec == "ML_DSA_44"
	msg := sprintf(
		"%s uses ML_DSA_44 (NIST security category 2); confirm the selected parameter set against the system's documented assurance requirements",
		[rc.address],
	)
}
