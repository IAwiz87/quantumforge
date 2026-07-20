# Governance and scoring

## Risk model

`policies/scoring/risk_score.rego` keeps four decision dimensions separate:

- `inherent_risk_score` (0–100): exposure to data stolen now and decrypted after future quantum advances, data classification, and business impact
- `migration_urgency_score` (0–100): inherent risk plus a deadline-pressure weight
- `remediation_effort`: `low`, `medium`, or `high`; it never reduces risk
- `evidence_confidence`: `1.0`, `0.7`, or `0.4`; it is reported independently rather than multiplying risk downward

Scoring consumes the same canonical inventory contract as discovery. Before scoring, enrich each asset with the schema-defined optional fields `secrecy_lifetime_years`, `data_classification`, `impact`, `migration_deadline_months`, and `remediation_effort`. Results are keyed by `asset_id`. Missing, malformed, negative, or unsupported enrichment appears in `invalid_inventory` and is not silently scored with optimistic defaults.

See [`examples/inventory/scoring-ready-inventory.json`](../examples/inventory/scoring-ready-inventory.json) for a schema-valid end-to-end input.

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
