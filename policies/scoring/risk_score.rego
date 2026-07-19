# QuantumForge — Phase 2: Vulnerability Prioritization
#
# Risk, urgency, implementation effort, and evidence confidence are separate
# outputs. Delivery convenience must never lower the inherent risk of an asset.

package quantumforge.scoring

import rego.v1

classification_values := {"nss", "regulated", "internal", "public"}
impact_values := {"mission_critical", "business_critical", "operational", "informational"}
effort_values := {"low", "medium", "high"}
confidence_values := {"high", "medium", "low"}

hndl_weight(years) := 40 if years >= 10
hndl_weight(years) := 25 if {
	years >= 5
	years < 10
}
hndl_weight(years) := 10 if years < 5

classification_weight("nss") := 30
classification_weight("regulated") := 20
classification_weight("internal") := 10
classification_weight("public") := 0

impact_weight("mission_critical") := 30
impact_weight("business_critical") := 20
impact_weight("operational") := 10
impact_weight("informational") := 5

deadline_weight(months) := 20 if months <= 6
deadline_weight(months) := 10 if {
	months > 6
	months <= 18
}
deadline_weight(months) := 0 if months > 18

confidence_value("high") := 1.0
confidence_value("medium") := 0.7
confidence_value("low") := 0.4

valid_nonempty_string(value) if {
	is_string(value)
	trim_space(value) != ""
} else := false

valid_nonnegative_number(value) if {
	is_number(value)
	value >= 0
} else := false

metadata_checks(asset) := {
	"address must be a non-empty string": valid_nonempty_string(object.get(asset, "address", null)),
	"data_retention_years must be a non-negative number": valid_nonnegative_number(object.get(asset, "data_retention_years", null)),
	"data_classification is missing or unsupported": object.get(asset, "data_classification", null) in classification_values,
	"impact is missing or unsupported": object.get(asset, "impact", null) in impact_values,
	"migration_deadline_months must be a non-negative number": valid_nonnegative_number(object.get(asset, "migration_deadline_months", null)),
	"remediation_effort is missing or unsupported": object.get(asset, "remediation_effort", null) in effort_values,
	"evidence_confidence is missing or unsupported": object.get(asset, "evidence_confidence", null) in confidence_values,
}

metadata_errors(asset) := {message |
	some message, valid in metadata_checks(asset)
	not valid
}

is_valid(asset) if count(metadata_errors(asset)) == 0

inherent_risk_score(asset) := total if {
	is_valid(asset)
	total := hndl_weight(asset.data_retention_years) +
		classification_weight(asset.data_classification) +
		impact_weight(asset.impact)
}

# Compatibility alias for existing policy consumers.
score(asset) := inherent_risk_score(asset)

migration_urgency_score(asset) := min([100, raw]) if {
	raw := inherent_risk_score(asset) + deadline_weight(asset.migration_deadline_months)
}

tier(asset) := "critical" if inherent_risk_score(asset) >= 80
tier(asset) := "high" if {
	inherent_risk_score(asset) >= 60
	inherent_risk_score(asset) < 80
}
tier(asset) := "medium" if {
	inherent_risk_score(asset) >= 35
	inherent_risk_score(asset) < 60
}
tier(asset) := "low" if inherent_risk_score(asset) < 35

scored_inventory contains entry if {
	some asset in input.assets
	is_valid(asset)
	entry := {
		"address": asset.address,
		"inherent_risk_score": inherent_risk_score(asset),
		"migration_urgency_score": migration_urgency_score(asset),
		"tier": tier(asset),
		"remediation_effort": asset.remediation_effort,
		"evidence_confidence": confidence_value(asset.evidence_confidence),
	}
}

invalid_inventory contains entry if {
	some asset in input.assets
	errors := metadata_errors(asset)
	count(errors) > 0
	entry := {
		"address": object.get(asset, "address", "unknown"),
		"errors": sort(errors),
	}
}

priority_matrix := {
	"critical": sort([e.address | some e in scored_inventory; e.tier == "critical"]),
	"high": sort([e.address | some e in scored_inventory; e.tier == "high"]),
	"medium": sort([e.address | some e in scored_inventory; e.tier == "medium"]),
	"low": sort([e.address | some e in scored_inventory; e.tier == "low"]),
}

assessment := {
	"scored_inventory": scored_inventory,
	"invalid_inventory": invalid_inventory,
	"priority_matrix": priority_matrix,
	"valid_asset_count": count(scored_inventory),
	"invalid_asset_count": count(invalid_inventory),
}
