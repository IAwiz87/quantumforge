package main

import rego.v1

# --- fixtures ------------------------------------------------------------------

plan_with_classical_tls_only := {"resource_changes": [{
	"address": "aws_lb_listener.classical",
	"type": "aws_lb_listener",
	"change": {"after": {
		"protocol": "HTTPS",
		"ssl_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
	}},
}]}

plan_with_hybrid_pqc_tls := {"resource_changes": [{
	"address": "module.hybrid_pqc_alb.aws_lb_listener.hybrid_pqc_https",
	"type": "aws_lb_listener",
	"change": {"after": {
		"protocol": "HTTPS",
		"ssl_policy": "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
	}},
}]}

plan_with_classical_signing_key := {"resource_changes": [{
	"address": "aws_kms_key.legacy_signing",
	"type": "aws_kms_key",
	"change": {"after": {
		"key_usage": "SIGN_VERIFY",
		"customer_master_key_spec": "RSA_3072",
	}},
}]}

plan_with_ml_dsa_signing_key := {"resource_changes": [{
	"address": "module.hybrid_pqc_kms.aws_kms_key.pqc_signing",
	"type": "aws_kms_key",
	"change": {"after": {
		"key_usage": "SIGN_VERIFY",
		"customer_master_key_spec": "ML_DSA_65",
	}},
}]}

plan_with_ml_dsa_44_signing_key := {"resource_changes": [{
	"address": "aws_kms_key.low_assurance_signing",
	"type": "aws_kms_key",
	"change": {"after": {
		"key_usage": "SIGN_VERIFY",
		"customer_master_key_spec": "ML_DSA_44",
	}},
}]}

# --- tests -----------------------------------------------------------------------

test_denies_classical_only_tls_listener if {
	count(deny) > 0 with input as plan_with_classical_tls_only
}

test_allows_hybrid_pqc_tls_listener if {
	count(deny) == 0 with input as plan_with_hybrid_pqc_tls
}

test_denies_classical_signing_key if {
	count(deny) > 0 with input as plan_with_classical_signing_key
}

test_allows_ml_dsa_signing_key if {
	count(deny) == 0 with input as plan_with_ml_dsa_signing_key
}

test_warns_on_ml_dsa_44_low_assurance if {
	count(warn) > 0 with input as plan_with_ml_dsa_44_signing_key
}

test_no_warn_on_ml_dsa_65 if {
	count(warn) == 0 with input as plan_with_ml_dsa_signing_key
}
