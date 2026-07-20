package main

import rego.v1

mock_now_ns := time.parse_rfc3339_ns("2026-07-19T12:00:00Z")

plan_with_classical_tls_only := {"resource_changes": [{
	"address": "aws_lb_listener.classical",
	"type": "aws_lb_listener",
	"change": {"actions": ["create"], "after": {
		"protocol": "HTTPS",
		"ssl_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
	}},
}]}

plan_with_fake_pq_suffix := {"resource_changes": [{
	"address": "aws_lb_listener.fake_pq",
	"type": "aws_lb_listener",
	"change": {"actions": ["create"], "after": {
		"protocol": "HTTPS",
		"ssl_policy": "ELBSecurityPolicy-PQ-EVIL",
	}},
}]}

plan_with_classical_nlb_tls := {"resource_changes": [{
	"address": "aws_lb_listener.classical_nlb",
	"type": "aws_lb_listener",
	"change": {"actions": ["create"], "after": {
		"protocol": "TLS",
		"ssl_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
	}},
}]}

plan_with_hybrid_pqc_tls := {"resource_changes": [{
	"address": "module.hybrid_pqc_alb.aws_lb_listener.hybrid_pqc_https",
	"type": "aws_lb_listener",
	"change": {"actions": ["create"], "after": {
		"protocol": "HTTPS",
		"ssl_policy": "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
	}},
}]}

plan_with_classical_signing_key := {"resource_changes": [{
	"address": "aws_kms_key.legacy_signing",
	"type": "aws_kms_key",
	"change": {"actions": ["create"], "after": {
		"key_usage": "SIGN_VERIFY",
		"customer_master_key_spec": "RSA_3072",
	}},
}]}

plan_with_fake_ml_dsa_prefix := {"resource_changes": [{
	"address": "aws_kms_key.fake_pqc",
	"type": "aws_kms_key",
	"change": {"actions": ["create"], "after": {
		"key_usage": "SIGN_VERIFY",
		"customer_master_key_spec": "ML_DSA_EVIL",
	}},
}]}

plan_with_ml_dsa_signing_key := {"resource_changes": [{
	"address": "module.pqc_kms_signing.aws_kms_key.pqc_signing",
	"type": "aws_kms_key",
	"change": {"actions": ["create"], "after": {
		"key_usage": "SIGN_VERIFY",
		"customer_master_key_spec": "ML_DSA_65",
	}},
}]}

plan_with_ml_dsa_44_signing_key := {"resource_changes": [{
	"address": "aws_kms_key.low_assurance_signing",
	"type": "aws_kms_key",
	"change": {"actions": ["create"], "after": {
		"key_usage": "SIGN_VERIFY",
		"customer_master_key_spec": "ML_DSA_44",
	}},
}]}

active_exception_config := {
	"enforce_cutover": true,
	"assessment_time": "2026-07-19T12:00:00Z",
	"exceptions": [{
		"id": "QF-EX-001",
		"asset_id": "aws_lb_listener.classical",
		"owner": "payments-platform",
		"approver": "security-governance",
		"rationale": "Named client dependency cannot negotiate PQ-TLS yet.",
		"compensating_controls": ["TLS 1.3 required"],
		"created_at": "2026-07-01T12:00:00Z",
		"expires_at": "2026-08-01T12:00:00Z",
	}],
}

test_denies_classical_only_tls_listener if {
	count(deny) > 0 with input as plan_with_classical_tls_only
}

test_denies_classical_nlb_tls_listener if {
	count(deny) > 0 with input as plan_with_classical_nlb_tls
}

test_rejects_unrecognized_pq_substring if {
	count(deny) > 0 with input as plan_with_fake_pq_suffix
}

test_allows_exact_hybrid_pqc_tls_policy if {
	count(deny) == 0 with input as plan_with_hybrid_pqc_tls
}

test_denies_classical_signing_key if {
	count(deny) > 0 with input as plan_with_classical_signing_key
}

test_rejects_unrecognized_ml_dsa_prefix if {
	count(deny) > 0 with input as plan_with_fake_ml_dsa_prefix
}

test_allows_ml_dsa_signing_key if {
	count(deny) == 0 with input as plan_with_ml_dsa_signing_key
}

test_warns_on_ml_dsa_44_parameter_set if {
	count(warn) > 0 with input as plan_with_ml_dsa_44_signing_key
}

test_valid_exception_temporarily_allows_asset if {
	count(deny) == 0 with input as plan_with_classical_tls_only with data.quantumforge_config as active_exception_config with time.now_ns as mock_now_ns
}

test_expired_exception_fails_closed if {
	entry := object.union(active_exception_config.exceptions[0], {"expires_at": "2026-07-18T12:00:00Z"})
	expired := object.union(active_exception_config, {
		"assessment_time": "2020-01-01T00:00:00Z",
		"exceptions": [entry],
	})
	count(deny) > 0 with input as plan_with_classical_tls_only with data.quantumforge_config as expired with time.now_ns as mock_now_ns
}

test_duplicate_exception_ids_fail_closed if {
	first := active_exception_config.exceptions[0]
	duplicate := object.union(first, {"asset_id": "aws_kms_key.legacy"})
	config := object.union(active_exception_config, {"exceptions": [first, duplicate]})
	messages := deny with input as plan_with_hybrid_pqc_tls with data.quantumforge_config as config with time.now_ns as mock_now_ns
	some msg in messages
	contains(msg, "is duplicated")
}

test_missing_resource_changes_fails_closed if {
	count(deny) > 0 with input as {}
}

test_null_resource_changes_fails_closed if {
	count(deny) > 0 with input as {"resource_changes": null}
}

test_malformed_resource_entry_fails_closed if {
	result := deny with input as {"resource_changes": [{}]}
	"input.resource_changes contains a malformed entry" in result
}

test_missing_change_actions_fails_closed if {
	plan := {"resource_changes": [{
		"address": "aws_kms_key.malformed",
		"type": "aws_kms_key",
		"change": {"after": {}},
	}]}
	result := deny with input as plan
	"input.resource_changes contains a malformed entry" in result
}

test_delete_only_resource_entry_is_well_formed if {
	plan := {"resource_changes": [{
		"address": "aws_kms_key.retired",
		"type": "aws_kms_key",
		"change": {"actions": ["delete"], "after": null},
	}]}
	result := deny with input as plan
	not "input.resource_changes contains a malformed entry" in result
}

test_non_object_input_fails_closed if {
	count(deny) > 0 with input as []
}
