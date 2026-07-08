# QuantumForge — Phase 3: Cryptographic Agility Architecture
#
# Crypto-Agility Gate: run against `terraform show -json <planfile>` output
# with `conftest test`. Blocks any plan that:
#   1. Provisions a new/changed HTTPS listener without a hybrid post-quantum
#      TLS policy, once the client-defined cutover has been enabled, and
#   2. Provisions a new/changed asymmetric signing KMS key using a classical
#      algorithm instead of an approved hybrid/PQC combiner (ML-DSA), once
#      the cutover has been enabled.
#
# `deny` is the rule name Conftest checks by default under `package main`.

package main

import rego.v1

# --- configuration -----------------------------------------------------------
#
# Conftest supports supplying this as external data via `--data config.json`.
# When no external config is supplied, `enforce_cutover` defaults to true so
# the gate fails safe (blocks classical-only crypto) rather than failing open.

default enforce_cutover := true

enforce_cutover := data.config.enforce_cutover if {
	data.config.enforce_cutover != null
}

approved_pqc_signing_prefixes := {"ML_DSA_"}

approved_hybrid_tls_marker := "PQ"

# --- ALB / NLB listener check --------------------------------------------------

deny contains msg if {
	enforce_cutover
	some rc in input.resource_changes
	rc.type == "aws_lb_listener"
	after := rc.change.after
	after.protocol == "HTTPS"
	not contains(after.ssl_policy, approved_hybrid_tls_marker)
	msg := sprintf(
		"%s provisions a classical-only TLS policy (%s) after the crypto-agility cutover date — use a hybrid post-quantum ssl_policy (e.g. ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09)",
		[rc.address, after.ssl_policy],
	)
}

# --- KMS signing key check ------------------------------------------------------

deny contains msg if {
	enforce_cutover
	some rc in input.resource_changes
	rc.type == "aws_kms_key"
	after := rc.change.after
	after.key_usage == "SIGN_VERIFY"
	spec := after.customer_master_key_spec
	not is_approved_signing_spec(spec)
	msg := sprintf(
		"%s provisions a non-agile signing key spec (%s) — use an approved post-quantum key_spec (ML_DSA_44 / ML_DSA_65 / ML_DSA_87)",
		[rc.address, spec],
	)
}

is_approved_signing_spec(spec) if {
	some prefix in approved_pqc_signing_prefixes
	startswith(spec, prefix)
}

# --- warn-level advisory: encourage stronger security levels for NSS assets ----

warn contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_kms_key"
	after := rc.change.after
	after.customer_master_key_spec == "ML_DSA_44"
	msg := sprintf(
		"%s uses ML_DSA_44 (NIST security level 1) — consider ML_DSA_65 or ML_DSA_87 for National Security System (NSS) assets under CNSA 2.0",
		[rc.address],
	)
}
