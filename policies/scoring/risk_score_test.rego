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
	"migration_deadline_months": 3,
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
}

# --- Gap #1 + #3: deadline_pressure_score buckets, including overdue -------

test_deadline_pressure_score_buckets if {
	deadline_pressure_score(3) == 100
	deadline_pressure_score(6) == 85
	deadline_pressure_score(12) == 65
	deadline_pressure_score(24) == 45
	deadline_pressure_score(36) == 25
	deadline_pressure_score(60) == 10
	deadline_pressure_score(61) == 0
}

test_overdue_deadline_gets_maximum_pressure if {
	deadline_pressure_score(-1) == 100
	deadline_pressure_score(-600) == 100
}

test_max_inherent_risk_and_urgency_cap if {
	inherent_risk_score(base_asset) == 100
	migration_urgency_score(base_asset) == 100
	tier(base_asset) == "critical"
}

# Gap #1: the old model (min(100, inherent_risk_score + deadline_weight))
# collapsed every critical-tier asset (inherent_risk_score >= 80) to the same
# urgency score once its deadline fell inside the 0-6 month bucket, because
# 80 + 20 already saturates at 100. Two assets that are both maximally
# risky but have very different deadlines must now report different
# migration_urgency_score values.
test_urgency_differentiates_within_critical_tier if {
	near_term := base_asset # migration_deadline_months: 3 -> pressure 100
	far_out := object.union(base_asset, {
		"asset_id": "aws_kms_key.far-out-critical",
		"migration_deadline_months": 36, # pressure 25
	})

	inherent_risk_score(near_term) == 100
	inherent_risk_score(far_out) == 100
	tier(near_term) == "critical"
	tier(far_out) == "critical"

	migration_urgency_score(near_term) == 100
	migration_urgency_score(far_out) == 85
	migration_urgency_score(near_term) != migration_urgency_score(far_out)
}

test_low_risk_case if {
	asset := object.union(base_asset, {
		"secrecy_lifetime_years": 2,
		"data_classification": "public",
		"impact": "informational",
		"migration_deadline_months": 24,
	})
	inherent_risk_score(asset) == 15
	migration_urgency_score(asset) == 21
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

# Gap #3: an overdue migration_deadline_months is a valid, meaningful state
# (not an input error). Only secrecy_lifetime_years still rejects negative
# values.
test_negative_secrecy_lifetime_is_invalid if {
	invalid := object.union(base_asset, {"secrecy_lifetime_years": -1})
	count(metadata_errors(invalid)) == 1
}

test_negative_migration_deadline_is_valid_and_overdue if {
	overdue := object.union(base_asset, {"migration_deadline_months": -6})
	count(metadata_errors(overdue)) == 0
	is_valid(overdue)
	effective_deadline_months(overdue) == -6
	deadline_pressure_score(effective_deadline_months(overdue)) == 100
	migration_urgency_score(overdue) == 100
}

# --- Gap #2: calendar-anchored deadlines ------------------------------------

mock_now_before_deadline_ns := time.parse_rfc3339_ns("2029-07-05T00:00:00Z")

mock_now_after_deadline_ns := time.parse_rfc3339_ns("2031-01-01T00:00:00Z")

test_calendar_deadline_derives_months_remaining if {
	# 2030-01-01 (software_firmware_signing exclusive-use date) minus
	# 2029-07-05 is exactly 180 days == 6 months at the 30-day approximation.
	calendar_deadline_months("software_firmware_signing") == 6
		with time.now_ns as mock_now_before_deadline_ns
}

test_calendar_deadline_goes_negative_after_passing if {
	months := calendar_deadline_months("software_firmware_signing") with time.now_ns as mock_now_after_deadline_ns
	months < 0
	deadline_pressure_score(months) == 100
}

test_calendar_deadline_flows_into_effective_deadline_when_no_override if {
	asset := object.union(object.remove(base_asset, {"migration_deadline_months"}), {
		"regulatory_category": "software_firmware_signing",
	})
	is_valid(asset) with time.now_ns as mock_now_before_deadline_ns
	effective_deadline_months(asset) == 6 with time.now_ns as mock_now_before_deadline_ns
}

test_explicit_migration_deadline_overrides_regulatory_category if {
	# An org-specific deadline of 1 month must win over the much later
	# 2033 web_cloud_services regulatory floor.
	asset := object.union(base_asset, {
		"migration_deadline_months": 1,
		"regulatory_category": "web_cloud_services",
	})
	effective_deadline_months(asset) == 1
}

test_missing_both_deadline_inputs_is_invalid if {
	asset := object.remove(base_asset, {"migration_deadline_months"})
	errors := metadata_errors(asset)
	"migration_deadline_months must be a number, or regulatory_category must be set" in errors
	not is_valid(asset)
}

test_malformed_optional_enrichment_is_invalid if {
	asset := object.union(base_asset, {
		# The numeric deadline makes the category unnecessary for scoring, but
		# an explicitly supplied optional field must still satisfy the schema.
		"regulatory_category": "not_a_cnsa_category",
		"dependent_asset_count": 1.5,
	})
	errors := metadata_errors(asset)
	"regulatory_category is set but unsupported" in errors
	"dependent_asset_count must be a non-negative integer when set" in errors
	not is_valid(asset)
}

# --- Gap #4: classification/impact divergence (reported only) --------------

test_aligned_classification_and_impact_is_not_flagged if {
	classification_impact_divergence(base_asset) == 0
	not needs_divergence_review(base_asset)
}

test_divergent_classification_and_impact_is_flagged if {
	divergent := object.union(base_asset, {
		"data_classification": "public",
		"impact": "mission_critical",
	})
	classification_impact_divergence(divergent) == 3
	needs_divergence_review(divergent)

	# The flag is advisory only — it must never change inherent_risk_score,
	# which stays a plain sum of the three weights.
	inherent_risk_score(divergent) == (classification_weight("public") + impact_weight("mission_critical")) + hndl_weight(divergent.secrecy_lifetime_years)
}

# --- Gap #6: migration work queue (effort as tiebreaker only) --------------

queue_input := {"assets": [
	object.union(base_asset, {"asset_id": "queue.high-effort", "remediation_effort": "high"}),
	object.union(base_asset, {"asset_id": "queue.medium-effort", "remediation_effort": "medium"}),
	object.union(base_asset, {"asset_id": "queue.low-effort", "remediation_effort": "low"}),
	object.union(base_asset, {
		"asset_id": "queue.lower-risk-low-effort",
		"secrecy_lifetime_years": 2,
		"data_classification": "internal",
		"impact": "operational",
		"remediation_effort": "low",
	}),
]}

test_work_queue_uses_effort_only_as_tiebreaker if {
	queue := migration_work_queue with input as queue_input

	# All three "queue.*-effort" assets share identical inherent_risk_score
	# and migration_urgency_score, so effort alone decides their order:
	# lowest effort first.
	queue[0].asset_id == "queue.low-effort"
	queue[1].asset_id == "queue.medium-effort"
	queue[2].asset_id == "queue.high-effort"

	# The much lower-risk asset never jumps ahead of higher-risk assets just
	# because its remediation effort is also low.
	queue[3].asset_id == "queue.lower-risk-low-effort"
	queue[3].inherent_risk_score < queue[2].inherent_risk_score
}

test_duplicate_asset_ids_are_invalid_and_do_not_break_the_queue if {
	duplicate := object.union(base_asset, {
		"secrecy_lifetime_years": 2,
		"data_classification": "public",
		"impact": "informational",
		"migration_deadline_months": 60,
		"remediation_effort": "low",
	})
	result := assessment with input as {"assets": [base_asset, duplicate]}
	result.valid_asset_count == 0
	count(result.invalid_inventory) == 1
	count(result.migration_work_queue) == 0
	some invalid in result.invalid_inventory
	"asset_id must be unique within the inventory" in invalid.errors
}

# --- Gap #7: dependency-informed impact hint (advisory only) ---------------

test_high_fan_in_flags_impact_as_possibly_underrated if {
	asset := object.union(base_asset, {
		"impact": "operational",
		"dependent_asset_count": 30,
	})
	impact_may_be_underrated(asset)

	# Advisory only — the asset's own impact field is untouched.
	asset.impact == "operational"
}

test_low_fan_in_does_not_flag_impact if {
	asset := object.union(base_asset, {
		"impact": "business_critical",
		"dependent_asset_count": 2,
	})
	not impact_may_be_underrated(asset)
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

test_batch_assessment_includes_migration_work_queue if {
	result := assessment with input as sample_input
	count(result.migration_work_queue) == 2
	result.migration_work_queue[0].asset_id == "aws_kms_key.example"
	result.migration_work_queue[1].asset_id == "aws_kms_key.business"
}
