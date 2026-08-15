# Governance and scoring

## Risk model

`policies/scoring/risk_score.rego` keeps decision dimensions separate:

- `inherent_risk_score` (0–100): HNDL exposure window, data classification, and business impact, summed
- `migration_urgency_score` (0–100): a weighted blend of `inherent_risk_score` (80%) and a separate 0–100 `deadline_pressure_score` (20%) — not an additive bonus clamped at 100, so two assets can share the same inherent risk yet still rank differently by how close their deadline is
- `remediation_effort`: `low`, `medium`, or `high`; it never reduces risk — the only place it affects ordering is as a tiebreaker in `migration_work_queue` between assets that already tie on risk and urgency
- `evidence_confidence`: `1.0`, `0.7`, or `0.4`; reported independently rather than multiplying risk downward
- `needs_divergence_review`: flags assets where `data_classification` and `impact` tiers diverge by 2+ levels, since the two are summed as if independent but correlate in practice — advisory only, never changes the score
- `impact_may_be_underrated`: flags assets whose optional `dependent_asset_count` suggests a higher blast radius than the manually assigned `impact` tier — advisory only, never overrides the manual value

The full weighting rationale, the deadline-pressure bucket boundaries, and worked examples are in [SCORING_METHODOLOGY.md](SCORING_METHODOLOGY.md).

An asset's deadline can come from either input: an explicit `migration_deadline_months` (which may be negative — an asset that has already missed its deadline is valid input, not an error), or an optional `regulatory_category` mapped to the CNSA 2.0 equipment-category calendar and recomputed from the current time on every evaluation so it never goes stale. An explicit `migration_deadline_months` always takes precedence when both are present.

`migration_work_queue` produces a single ranked list across all valid assets — sorted by `inherent_risk_score` descending, then `migration_urgency_score` descending, with `remediation_effort` used only to break ties — implementing the roadmap's migration-priority-matrix generator. `priority_matrix` still groups assets by tier for a coarser view.

Scoring consumes the same canonical inventory contract as discovery. Before scoring, enrich each asset with the schema-defined optional fields `secrecy_lifetime_years`, `data_classification`, `impact`, `migration_deadline_months` or `regulatory_category`, `remediation_effort`, and optionally `dependent_asset_count`. Results are keyed by `asset_id`. Missing, malformed, or unsupported enrichment appears in `invalid_inventory` and is not silently scored with optimistic defaults.

See [`examples/inventory/scoring-ready-inventory.json`](../examples/inventory/scoring-ready-inventory.json) and [`examples/inventory/calendar-anchored-inventory.json`](../examples/inventory/calendar-anchored-inventory.json) for schema-valid end-to-end inputs.

## Exceptions

`policies/governance/exceptions.rego` requires each exception to contain:

- unique ID and exact asset ID
- accountable owner and approver
- rationale and at least one compensating control
- RFC3339 creation and expiration timestamps
- creation no later than the assessment timestamp
- expiration later than both creation and the assessment timestamp

Duplicate exception IDs block the assessment. The deployment gate evaluates expiry using the current time when Open Policy Agent runs and ignores any `assessment_time` supplied in checked-in policy data, so a stored timestamp cannot keep an exception valid indefinitely. Standalone historical governance assessments may still supply `input.assessment_time` when they need to reproduce an earlier decision.

The Conftest gate reads exceptions only from the Rego data document `data.quantumforge_config`. Invalid or expired entries block deployment. See `examples/governance/exceptions.json`.

```bash
conftest test plan.json \
  --policy policies \
  --data examples/governance/exceptions.json
```

Exceptions are temporary control records, not risk reductions. The asset remains in the inventory and scoring output. Organizations should require independent approval and record renewals as new exception versions rather than changing historical evidence.
