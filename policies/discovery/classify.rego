# QuantumForge — Phase 1: Discovery & Inventory
#
# Classifies cryptographic assets found in a `terraform show -json` plan or
# state document by algorithm family, so a complete crypto census can be
# built without touching production systems directly.
#
# Input shape: standard Terraform plan/state JSON, i.e. a document with a
# top-level `resource_changes` array where each entry has `type`, `address`,
# and `change.after` (the post-apply attribute values).

package quantumforge.discovery

import rego.v1

# --- Reference sets -----------------------------------------------------

classical_only_key_specs := {
	"RSA_2048", "RSA_3072", "RSA_4096",
	"ECC_NIST_P256", "ECC_NIST_P384", "ECC_NIST_P521", "ECC_SECG_P256K1",
}

post_quantum_key_spec_prefixes := {"ML_DSA_", "ML_KEM_"}

# --- KMS key classification ----------------------------------------------

classify_kms_key(after) := "post_quantum" if {
	some prefix in post_quantum_key_spec_prefixes
	startswith(after.customer_master_key_spec, prefix)
}

classify_kms_key(after) := "classical_only" if {
	after.customer_master_key_spec in classical_only_key_specs
}

classify_kms_key(after) := "symmetric" if {
	after.customer_master_key_spec == "SYMMETRIC_DEFAULT"
}

classify_kms_key(after) := "unknown" if {
	spec := after.customer_master_key_spec
	not spec in classical_only_key_specs
	not spec == "SYMMETRIC_DEFAULT"
	not startswith(spec, "ML_DSA_")
	not startswith(spec, "ML_KEM_")
}

# --- TLS listener classification -----------------------------------------

classify_tls_listener(after) := "hybrid_post_quantum" if {
	after.protocol == "HTTPS"
	contains(after.ssl_policy, "PQ")
}

classify_tls_listener(after) := "classical_only" if {
	after.protocol == "HTTPS"
	not contains(after.ssl_policy, "PQ")
}

# --- Inventory assembly ----------------------------------------------------

inventory contains entry if {
	some rc in input.resource_changes
	rc.type == "aws_kms_key"
	entry := {
		"address": rc.address,
		"type": rc.type,
		"classification": classify_kms_key(rc.change.after),
	}
}

inventory contains entry if {
	some rc in input.resource_changes
	rc.type == "aws_lb_listener"
	entry := {
		"address": rc.address,
		"type": rc.type,
		"classification": classify_tls_listener(rc.change.after),
	}
}

# --- Roll-up summary for the executive briefing ---------------------------

pqc_ready_classifications := {"post_quantum", "hybrid_post_quantum"}

summary := {
	"total_assets": count(inventory),
	"post_quantum_ready": count([e | some e in inventory; e.classification in pqc_ready_classifications]),
	"classical_only": count([e | some e in inventory; e.classification == "classical_only"]),
	"symmetric": count([e | some e in inventory; e.classification == "symmetric"]),
	"unknown": count([e | some e in inventory; e.classification == "unknown"]),
}
