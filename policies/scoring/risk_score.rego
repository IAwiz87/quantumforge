# QuantumForge — Phase 2: Vulnerability Prioritization
#
# Converts a discovered crypto asset into a weighted risk score and tier,
# combining Harvest-Now-Decrypt-Later (HNDL) exposure, data classification,
# and remediation cost/complexity. Every scoring branch is unit-tested
# before being trusted for client-facing prioritization output.
#
# Input shape (per asset):
# {
#   "address": "...",
#   "data_retention_years": <number>,
#   "data_classification": "nss" | "regulated" | "internal",
#   "remediation_cost": "low" | "medium" | "high"
# }

package quantumforge.scoring

import rego.v1

# --- Weight tables ---------------------------------------------------------

hndl_weight(years) := 40 if years >= 10

hndl_weight(years) := 25 if {
	years >= 5
	years < 10
}

hndl_weight(years) := 10 if years < 5

classification_weight("nss") := 40

classification_weight("regulated") := 25

classification_weight("internal") := 10

remediation_cost_weight("low") := 20

remediation_cost_weight("medium") := 10

remediation_cost_weight("high") := 5

# --- Composite score ---------------------------------------------------------

score(asset) := total if {
	total := hndl_weight(asset.data_retention_years) +
		classification_weight(asset.data_classification) +
		remediation_cost_weight(asset.remediation_cost)
}

# --- Tier thresholds ---------------------------------------------------------

tier(asset) := "critical" if score(asset) >= 80

tier(asset) := "high" if {
	score(asset) >= 60
	score(asset) < 80
}

tier(asset) := "medium" if {
	score(asset) >= 35
	score(asset) < 60
}

tier(asset) := "low" if score(asset) < 35

# --- Batch scoring for a full inventory --------------------------------------
#
# Input for this rule is `{"assets": [...]}` — a wrapper around the list of
# assets produced (and enriched with retention/classification/cost metadata)
# from the Phase 1 discovery inventory.

scored_inventory contains entry if {
	some asset in input.assets
	entry := {
		"address": asset.address,
		"score": score(asset),
		"tier": tier(asset),
	}
}

priority_matrix := {
	"critical": [e.address | some e in scored_inventory; e.tier == "critical"],
	"high": [e.address | some e in scored_inventory; e.tier == "high"],
	"medium": [e.address | some e in scored_inventory; e.tier == "medium"],
	"low": [e.address | some e in scored_inventory; e.tier == "low"],
}
