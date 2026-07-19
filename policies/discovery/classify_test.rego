package quantumforge.discovery

import rego.v1

sample_plan := {"resource_changes": [
	{
		"address": "module.pqc_kms_signing.aws_kms_key.pqc_signing",
		"type": "aws_kms_key",
		"change": {"after": {
			"customer_master_key_spec": "ML_DSA_65",
			"key_usage": "SIGN_VERIFY",
		}},
	},
	{
		"address": "aws_kms_key.legacy",
		"type": "aws_kms_key",
		"change": {"after": {
			"customer_master_key_spec": "RSA_3072",
			"key_usage": "SIGN_VERIFY",
		}},
	},
	{
		"address": "aws_lb_listener.hybrid",
		"type": "aws_lb_listener",
		"change": {"after": {
			"protocol": "HTTPS",
			"ssl_policy": "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
		}},
	},
	{
		"address": "aws_acm_certificate.public",
		"type": "aws_acm_certificate",
		"change": {"after": {"key_algorithm": "RSA_2048"}},
	},
	{
		"address": "aws_acmpca_certificate_authority.internal",
		"type": "aws_acmpca_certificate_authority",
		"change": {"after": {"key_algorithm": "EC_prime256v1"}},
	},
	{
		"address": "aws_cloudfront_distribution.web",
		"type": "aws_cloudfront_distribution",
		"change": {"after": {
			"viewer_certificate": [{"minimum_protocol_version": "TLSv1.2_2021"}],
		}},
	},
	{
		"address": "aws_apigatewayv2_domain_name.api",
		"type": "aws_apigatewayv2_domain_name",
		"change": {"after": {
			"domain_name_configuration": [{"security_policy": "TLS_1_2"}],
		}},
	},
	{
		"address": "aws_vpn_connection.partner",
		"type": "aws_vpn_connection",
		"change": {"after": {"type": "ipsec.1"}},
	},
	{
		"address": "aws_kms_key.deleted",
		"type": "aws_kms_key",
		"change": {"after": null},
	},
]}

test_exact_key_classification if {
	classify_key_spec("ML_DSA_65") == "post_quantum"
	classify_key_spec("ML_DSA_EVIL") == "unknown"
	classify_key_spec("RSA_3072") == "classical_only"
	classify_key_spec("SYMMETRIC_DEFAULT") == "symmetric"
}

test_exact_tls_policy_classification if {
	classify_tls_policy("ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09") == "hybrid_post_quantum"
	classify_tls_policy("ELBSecurityPolicy-PQ-EVIL") == "classical_only"
}

test_inventory_covers_representative_crypto_surfaces if {
	result := inventory with input as sample_plan
	count(result) == 8
	{e.resource_type | some e in result} == {
		"aws_kms_key",
		"aws_lb_listener",
		"aws_acm_certificate",
		"aws_acmpca_certificate_authority",
		"aws_cloudfront_distribution",
		"aws_apigatewayv2_domain_name",
		"aws_vpn_connection",
	}
}

test_deleted_resources_are_not_reported_as_active_assets if {
	result := inventory with input as sample_plan
	not "aws_kms_key.deleted" in {e.address | some e in result}
}

test_summary_preserves_unknown_as_first_class if {
	result := summary with input as sample_plan
	result.total_assets == 8
	result.post_quantum_ready == 2
	result.classical_only == 3
	result.symmetric == 0
	result.unknown == 3
}
