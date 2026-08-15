# QuantumForge — Phase 2: Vulnerability Prioritization
#
# Risk, urgency, implementation effort, and evidence confidence are separate
# outputs. Delivery convenience must never lower the inherent risk of an asset.
#
# Weighting rationale, the deadline-pressure model, and worked examples are
# documented in docs/SCORING_METHODOLOGY.md — read that before changing any
# weight or bucket boundary below.

package quantumforge.scoring

import rego.v1

classification_values := {"nss", "regulated", "internal", "public"}
impact_values := {"mission_critical", "business_critical", "operational", "informational"}
effort_values := {"low", "medium", "high"}
confidence_values := {"high", "medium", "low"}

# CNSA 2.0 equipment categories (NSA CSA, updated May 2025) used to derive a
# calendar-anchored migration_deadline_months when an asset doesn't carry an
# explicit override. See regulatory_deadline_rfc3339 below for sources.
regulatory_category_values := {
	"software_firmware_signing",
	"web_cloud_services",
	"traditional_networking",
	"operating_systems",
	"niche_equipment",
	"custom_legacy",
}

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

# --- Deadline pressure (0-100), separate from inherent risk ----------------
#
# deadline_pressure_score is intentionally its own 0-100 scale rather than a
# small additive bonus. It blends into migration_urgency_score at a fixed
# 20% weight (see migration_urgency_score) instead of being added onto
# inherent_risk_score and clamped, so assets already at maximum inherent risk
# still separate from each other by deadline instead of all collapsing to
# the same capped value.
#
# A negative value means the deadline has already passed. It maps to the
# same maximum pressure as "due within 3 months" rather than being treated
# as invalid input — an overdue asset is the most urgent case, not an
# erroneous one (see valid_number/gap #3 in SCORING_METHODOLOGY.md).
deadline_pressure_score(months) := 100 if months <= 3

deadline_pressure_score(months) := 85 if {
	months > 3
	months <= 6
}

deadline_pressure_score(months) := 65 if {
	months > 6
	months <= 12
}

deadline_pressure_score(months) := 45 if {
	months > 12
	months <= 24
}

deadline_pressure_score(months) := 25 if {
	months > 24
	months <= 36
}

deadline_pressure_score(months) := 10 if {
	months > 36
	months <= 60
}

deadline_pressure_score(months) := 0 if months > 60

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

# Unlike valid_nonnegative_number, valid_number allows negative values. Used
# for migration_deadline_months, where a negative value is a meaningful,
# valid "overdue by N months" state rather than bad input.
valid_number(value) if {
	is_number(value)
} else := false

# --- Calendar-anchored deadlines (gap #2) -----------------------------------
#
# CNSA 2.0 "exclusively use CNSA 2.0 algorithms" dates by equipment category.
# Source: NSA CSA, "CNSA 2.0 Algorithms" (updated May 30, 2025):
# https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF
regulatory_deadline_rfc3339("software_firmware_signing") := "2030-01-01T00:00:00Z"
regulatory_deadline_rfc3339("traditional_networking") := "2030-01-01T00:00:00Z"
regulatory_deadline_rfc3339("web_cloud_services") := "2033-01-01T00:00:00Z"
regulatory_deadline_rfc3339("operating_systems") := "2033-01-01T00:00:00Z"
regulatory_deadline_rfc3339("niche_equipment") := "2033-01-01T00:00:00Z"
regulatory_deadline_rfc3339("custom_legacy") := "2033-01-01T00:00:00Z"

ns_per_day := ((86400 * 1000) * 1000) * 1000

# Approximate at 30 days/month. Documented rather than hidden, since it's
# only meant to place a date into one of deadline_pressure_score's buckets,
# not to report a precise day count.
months_between_ns(later_ns, earlier_ns) := ((later_ns - earlier_ns) / ns_per_day) / 30

calendar_deadline_months(category) := months if {
	category in regulatory_category_values
	deadline_ns := time.parse_rfc3339_ns(regulatory_deadline_rfc3339(category))
	months := months_between_ns(deadline_ns, time.now_ns())
}

# An explicit migration_deadline_months always wins over the regulatory
# calendar — it lets a team commit to an internal deadline tighter than the
# regulatory floor. Falling back to regulatory_category keeps the countdown
# from silently going stale: it's recomputed from time.now_ns() on every
# evaluation instead of being a hand-edited number that rots.
effective_deadline_months(asset) := asset.migration_deadline_months if {
	valid_number(object.get(asset, "migration_deadline_months", null))
} else := calendar_deadline_months(object.get(asset, "regulatory_category", null))

has_deadline_input(asset) if {
	valid_number(object.get(asset, "migration_deadline_months", null))
} else if {
	object.get(asset, "regulatory_category", null) in regulatory_category_values
} else := false

metadata_checks(asset) := {
	"asset_id must be a non-empty string": valid_nonempty_string(object.get(asset, "asset_id", null)),
	"secrecy_lifetime_years must be a non-negative number": valid_nonnegative_number(object.get(asset, "secrecy_lifetime_years", null)),
	"data_classification is missing or unsupported": object.get(asset, "data_classification", null) in classification_values,
	"impact is missing or unsupported": object.get(asset, "impact", null) in impact_values,
	"migration_deadline_months must be a number, or regulatory_category must be set": has_deadline_input(asset),
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
	total := (hndl_weight(asset.secrecy_lifetime_years) + classification_weight(asset.data_classification)) + impact_weight(asset.impact)
}

# Compatibility alias for existing policy consumers.
score(asset) := inherent_risk_score(asset)

# migration_urgency_score blends inherent risk (80%) with deadline pressure
# (20%) instead of adding deadline_weight onto inherent_risk_score and
# clamping at 100. The old additive-and-clamp model made deadline pressure
# invisible for any asset already scoring >= 80: 80 + up to 20 always hit the
# 100 ceiling, so two critical-tier assets with wildly different deadlines
# (one overdue, one three years out) reported identically, losing all
# sequencing power exactly where it matters most. The weighted blend keeps
# both signals visible across the whole scale, including inside the critical
# tier, while an asset that is maximally risky *and* maximally
# deadline-pressured still resolves to exactly 100.
migration_urgency_score(asset) := round(raw) if {
	is_valid(asset)
	raw := (inherent_risk_score(asset) * 0.8) + (deadline_pressure_score(effective_deadline_months(asset)) * 0.2)
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

# --- Classification/impact divergence (gap #4, reported, never scored) -----
#
# data_classification and impact are summed as independent inputs, but in
# practice they correlate — an NSS asset is almost always mission_critical.
# Summing both risks double-counting the common, aligned case. Rather than
# guess at a statistical correction with no real inventory data to validate
# it against, this flags only the *divergent* cases for human review instead
# of silently reweighting the score. A large gap between the two tiers
# (e.g. "public" classification but "mission_critical" impact, or the
# reverse) is exactly the case an additive model handles worst either way.
classification_tier_rank("nss") := 3
classification_tier_rank("regulated") := 2
classification_tier_rank("internal") := 1
classification_tier_rank("public") := 0

impact_tier_rank("mission_critical") := 3
impact_tier_rank("business_critical") := 2
impact_tier_rank("operational") := 1
impact_tier_rank("informational") := 0

classification_impact_divergence(asset) := gap if {
	is_valid(asset)
	gap := abs(classification_tier_rank(asset.data_classification) - impact_tier_rank(asset.impact))
}

# Also a total function for the same reason as impact_may_be_underrated
# below — it's used directly as a value inside scored_inventory's entry.
needs_divergence_review(asset) if {
	classification_impact_divergence(asset) >= 2
} else := false

# --- Dependency-informed impact hint (gap #7, advisory, never overrides) ---
#
# impact is currently a human judgment call. A durable fix needs a real
# dependency graph in the inventory schema (tracked under ROADMAP.md's
# discovery-coverage priority). As a first, low-cost increment: if an asset
# reports how many other inventoried assets depend on it
# (dependent_asset_count), flag when the manually assigned impact tier looks
# too low for that fan-in, so a reviewer can catch under-rated trust anchors
# (e.g. a signing key backing 40 certificates marked "operational") without
# the tool silently overriding anyone's judgment.
suggested_impact_floor(count) := "mission_critical" if count >= 25

suggested_impact_floor(count) := "business_critical" if {
	count >= 5
	count < 25
}

suggested_impact_floor(count) := "operational" if {
	count >= 1
	count < 5
}

suggested_impact_floor(count) := "informational" if count < 1

# A total function (defaults to false) rather than a partial rule — used
# directly as a value inside scored_inventory's entry object below, where an
# undefined value would silently drop the whole entry instead of reporting
# it with impact_may_be_underrated: false.
impact_may_be_underrated(asset) if {
	is_valid(asset)
	count := object.get(asset, "dependent_asset_count", null)
	is_number(count)
	count >= 0
	impact_tier_rank(suggested_impact_floor(count)) > impact_tier_rank(asset.impact)
} else := false

# Rounded to one decimal for display only — deadline_pressure_score and
# migration_urgency_score always consume the unrounded value from
# effective_deadline_months, so this rounding never affects scoring.
display_deadline_months(asset) := round(effective_deadline_months(asset) * 10) / 10

scored_inventory contains entry if {
	some asset in input.assets
	is_valid(asset)
	entry := {
		"asset_id": asset.asset_id,
		"inherent_risk_score": inherent_risk_score(asset),
		"migration_urgency_score": migration_urgency_score(asset),
		"effective_deadline_months": display_deadline_months(asset),
		"tier": tier(asset),
		"remediation_effort": asset.remediation_effort,
		"evidence_confidence": confidence_value(asset.evidence_confidence),
		"needs_divergence_review": needs_divergence_review(asset),
		"impact_may_be_underrated": impact_may_be_underrated(asset),
	}
}

invalid_inventory contains entry if {
	some asset in input.assets
	errors := metadata_errors(asset)
	count(errors) > 0
	entry := {
		"asset_id": object.get(asset, "asset_id", "unknown"),
		"errors": sort(errors),
	}
}

priority_matrix := {
	"critical": sort([e.asset_id | some e in scored_inventory; e.tier == "critical"]),
	"high": sort([e.asset_id | some e in scored_inventory; e.tier == "high"]),
	"medium": sort([e.asset_id | some e in scored_inventory; e.tier == "medium"]),
	"low": sort([e.asset_id | some e in scored_inventory; e.tier == "low"]),
}

# --- Migration work queue (gap #6 / roadmap: "PQC Migration Priority Matrix
# generator") ----------------------------------------------------------------
#
# priority_matrix buckets assets into tiers but doesn't rank within a tier.
# migration_work_queue produces a single, fully ordered work queue across all
# valid assets, sorted by:
#   1. inherent_risk_score, descending
#   2. migration_urgency_score, descending
#   3. remediation_effort, ascending (lower effort first) — used ONLY to
#      break ties between equally risky/urgent items, never to change the
#      underlying risk or urgency number itself
#   4. asset_id, ascending — final deterministic tiebreaker
#
# Rego's sort() is ascending-only, so the key encodes "higher is better" as
# "100 - value" for the two score dimensions, letting a single ascending
# sort produce the descending-by-risk/urgency, ascending-by-effort order.
effort_rank("low") := 0
effort_rank("medium") := 1
effort_rank("high") := 2

work_queue_sort_key(asset) := [
	100 - inherent_risk_score(asset),
	100 - migration_urgency_score(asset),
	effort_rank(asset.remediation_effort),
	asset.asset_id,
]

work_queue_keys := [work_queue_sort_key(asset) |
	some asset in input.assets
	is_valid(asset)
]

work_queue_entry(asset_id) := entry if {
	some asset in input.assets
	asset.asset_id == asset_id
	is_valid(asset)
	entry := {
		"asset_id": asset.asset_id,
		"inherent_risk_score": inherent_risk_score(asset),
		"migration_urgency_score": migration_urgency_score(asset),
		"tier": tier(asset),
		"remediation_effort": asset.remediation_effort,
	}
}

migration_work_queue := [work_queue_entry(key[3]) |
	some key in sort(work_queue_keys)
]

assessment := {
	"scored_inventory": scored_inventory,
	"invalid_inventory": invalid_inventory,
	"priority_matrix": priority_matrix,
	"migration_work_queue": migration_work_queue,
	"valid_asset_count": count(scored_inventory),
	"invalid_asset_count": count(invalid_inventory),
}
