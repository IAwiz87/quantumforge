package quantumforge.scoring

import rego.v1

base_asset := {
	"asset_id": "aws_kms_key.example",
	"provider": "aws",
	"resource_type": "aws_kms_key",
	"crypto_function": "signing",
	"algorithm": "RSA_2048",
	"classification": "classical_only",
	"owner": "security-engineering",
	"environment": "production",
	"source": "terraform_plan",
	"observed_at": "2026-07-20T00:00:00Z",
	"secrecy_lifetime_years": 10,
	"data_classification": "nss",
	"impact": "mission_critical",
	"migration_deadline_months": 6,
	"remediation_effort": "high",
	"evidence_confidence": "high",
}

test_weight_boundaries if {
	hndl_weight(10) == 40
	hndl_weight(5) == 25
	hndl_weight(4) == 10
	classification_weight("nss") == 30
	classification_weight("public") == 0
	impact_weight("mission_critical") == 30
	impact_weight("informational") == 5
	deadline_weight(6) == 20
	deadline_weight(7) == 10
	deadline_weight(19) == 0
}

test_max_inherent_risk_and_urgency_cap if {
	inherent_risk_score(base_asset) == 100
	migration_urgency_score(base_asset) == 100
	tier(base_asset) == "critical"
}

test_low_risk_case if {
	asset := object.union(base_asset, {
		"secrecy_lifetime_years": 2,
		"data_classification": "public",
		"impact": "informational",
		"migration_deadline_months": 24,
	})
	inherent_risk_score(asset) == 15
	migration_urgency_score(asset) == 15
	tier(asset) == "low"
}

test_remediation_effort_does_not_change_inherent_risk if {
	low_effort := object.union(base_asset, {"remediation_effort": "low"})
	high_effort := object.union(base_asset, {"remediation_effort": "high"})
	inherent_risk_score(low_effort) == inherent_risk_score(high_effort)
}

test_confidence_is_reported_not_multiplied_into_risk if {
	low_confidence := object.union(base_asset, {"evidence_confidence": "low"})
	inherent_risk_score(low_confidence) == 100
	confidence_value(low_confidence.evidence_confidence) == 0.4
}

test_missing_metadata_is_invalid if {
	incomplete := object.remove(base_asset, {"impact", "evidence_confidence"})
	errors := metadata_errors(incomplete)
	"impact is missing or unsupported" in errors
	"evidence_confidence is missing or unsupported" in errors
	not is_valid(incomplete)
}

test_negative_values_are_invalid if {
	invalid := object.union(base_asset, {
		"secrecy_lifetime_years": -1,
		"migration_deadline_months": -1,
	})
	count(metadata_errors(invalid)) == 2
}

sample_input := {"assets": [
	base_asset,
	object.union(base_asset, {
		"asset_id": "aws_kms_key.business",
		"secrecy_lifetime_years": 5,
		"data_classification": "regulated",
		"impact": "business_critical",
		"migration_deadline_months": 12,
		"remediation_effort": "medium",
		"evidence_confidence": "medium",
	}),
	{
		"asset_id": "unknown.asset",
		"secrecy_lifetime_years": 2,
	},
]}

test_batch_assessment_separates_invalid_assets if {
	result := assessment with input as sample_input
	result.valid_asset_count == 2
	result.invalid_asset_count == 1
	result.priority_matrix.critical == ["aws_kms_key.example"]
	result.priority_matrix.high == ["aws_kms_key.business"]
	some invalid in result.invalid_inventory
	invalid.asset_id == "unknown.asset"
}
