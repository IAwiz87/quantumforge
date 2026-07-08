package quantumforge.scoring

import rego.v1

# --- weight function boundary tests -----------------------------------------

test_hndl_weight_boundaries if {
	hndl_weight(10) == 40
	hndl_weight(9) == 25
	hndl_weight(5) == 25
	hndl_weight(4) == 10
	hndl_weight(0) == 10
}

test_classification_weights if {
	classification_weight("nss") == 40
	classification_weight("regulated") == 25
	classification_weight("internal") == 10
}

test_remediation_cost_weights if {
	remediation_cost_weight("low") == 20
	remediation_cost_weight("medium") == 10
	remediation_cost_weight("high") == 5
}

# --- composite score tests ---------------------------------------------------

test_score_max_case if {
	# 10yr retention (40) + nss (40) + low cost (20) = 100
	score({
		"data_retention_years": 10,
		"data_classification": "nss",
		"remediation_cost": "low",
	}) == 100
}

test_score_min_case if {
	# <5yr retention (10) + internal (10) + high cost (5) = 25
	score({
		"data_retention_years": 2,
		"data_classification": "internal",
		"remediation_cost": "high",
	}) == 25
}

# --- tier boundary tests ------------------------------------------------------

test_tier_critical_above_80 if {
	# score = 40 (hndl>=10) + 40 (nss) + 10 (medium) = 90 -> critical
	tier({
		"data_retention_years": 10,
		"data_classification": "nss",
		"remediation_cost": "medium",
	}) == "critical"
}

test_tier_high_boundary if {
	# score = 40 (hndl>=10) + 10 (internal) + 10 (medium) = 60 -> high
	tier({
		"data_retention_years": 10,
		"data_classification": "internal",
		"remediation_cost": "medium",
	}) == "high"
}

test_tier_medium_boundary if {
	# score = 10 (hndl<5) + 25 (regulated) + 0? no min weight is 5 -> 10+25+5=40 -> medium... verify
	tier({
		"data_retention_years": 2,
		"data_classification": "regulated",
		"remediation_cost": "high",
	}) == "medium"
}

test_tier_low_boundary if {
	# score = 10 + 10 + 5 = 25 -> low
	tier({
		"data_retention_years": 2,
		"data_classification": "internal",
		"remediation_cost": "high",
	}) == "low"
}

# --- batch scoring / priority matrix integration test -------------------------

sample_input := {"assets": [
	{
		"address": "module.hybrid_pqc_kms.aws_kms_key.pqc_signing",
		"data_retention_years": 10,
		"data_classification": "nss",
		"remediation_cost": "low",
	},
	{
		"address": "aws_kms_key.legacy_rsa_customer_pii",
		"data_retention_years": 10,
		"data_classification": "regulated",
		"remediation_cost": "high",
	},
	{
		"address": "aws_kms_key.internal_logging",
		"data_retention_years": 2,
		"data_classification": "internal",
		"remediation_cost": "high",
	},
]}

test_priority_matrix_buckets_correctly if {
	pm := priority_matrix with input as sample_input
	pm.critical == ["module.hybrid_pqc_kms.aws_kms_key.pqc_signing"]
	pm.high == ["aws_kms_key.legacy_rsa_customer_pii"]
	pm.low == ["aws_kms_key.internal_logging"]
}
