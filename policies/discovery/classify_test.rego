package quantumforge.discovery

import rego.v1

# --- classify_kms_key unit tests -----------------------------------------

test_kms_classic_rsa_is_classical_only if {
	classify_kms_key({"customer_master_key_spec": "RSA_2048"}) == "classical_only"
}

test_kms_classic_ecc_is_classical_only if {
	classify_kms_key({"customer_master_key_spec": "ECC_NIST_P384"}) == "classical_only"
}

test_kms_ml_dsa_is_post_quantum if {
	classify_kms_key({"customer_master_key_spec": "ML_DSA_65"}) == "post_quantum"
}

test_kms_ml_kem_is_post_quantum if {
	classify_kms_key({"customer_master_key_spec": "ML_KEM_768"}) == "post_quantum"
}

test_kms_symmetric_default_is_symmetric if {
	classify_kms_key({"customer_master_key_spec": "SYMMETRIC_DEFAULT"}) == "symmetric"
}

test_kms_unrecognized_spec_is_unknown if {
	classify_kms_key({"customer_master_key_spec": "SM2"}) == "unknown"
}

# --- classify_tls_listener unit tests ------------------------------------

test_https_listener_with_pq_policy_is_hybrid if {
	classify_tls_listener({
		"protocol": "HTTPS",
		"ssl_policy": "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
	}) == "hybrid_post_quantum"
}

test_https_listener_without_pq_policy_is_classical_only if {
	classify_tls_listener({
		"protocol": "HTTPS",
		"ssl_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
	}) == "classical_only"
}

# --- inventory + summary integration tests --------------------------------

sample_plan := {"resource_changes": [
	{
		"address": "module.hybrid_pqc_kms.aws_kms_key.pqc_signing",
		"type": "aws_kms_key",
		"change": {"after": {"customer_master_key_spec": "ML_DSA_65"}},
	},
	{
		"address": "aws_kms_key.legacy_rsa",
		"type": "aws_kms_key",
		"change": {"after": {"customer_master_key_spec": "RSA_2048"}},
	},
	{
		"address": "module.hybrid_pqc_alb.aws_lb_listener.hybrid_pqc_https",
		"type": "aws_lb_listener",
		"change": {"after": {
			"protocol": "HTTPS",
			"ssl_policy": "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
		}},
	},
	{
		"address": "aws_lb_listener.legacy_https",
		"type": "aws_lb_listener",
		"change": {"after": {
			"protocol": "HTTPS",
			"ssl_policy": "ELBSecurityPolicy-2016-08",
		}},
	},
]}

test_inventory_has_four_entries if {
	count(inventory) == 4 with input as sample_plan
}

test_summary_counts_are_correct if {
	s := summary with input as sample_plan
	s.total_assets == 4
	s.post_quantum_ready == 2
	s.classical_only == 2
}
