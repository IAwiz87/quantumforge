# Governance and scoring

## Risk model

`policies/scoring/risk_score.rego` keeps four decision dimensions separate:

- `inherent_risk_score` (0–100): harvest-now-decrypt-later exposure, data classification, and business impact
- `migration_urgency_score` (0–100): inherent risk plus a deadline-pressure weight
- `remediation_effort`: `low`, `medium`, or `high`; it never reduces risk
- `evidence_confidence`: `1.0`, `0.7`, or `0.4`; it is reported independently rather than multiplying risk downward

Required asset fields are validated. Missing, malformed, negative, or unsupported metadata appears in `invalid_inventory` and is not silently scored with optimistic defaults.

Example input:

```json
{
  "address": "aws_kms_key.release_signing",
  "data_retention_years": 10,
  "data_classification": "nss",
  "impact": "mission_critical",
  "migration_deadline_months": 6,
  "remediation_effort": "high",
  "evidence_confidence": "high"
}
```

## Exceptions

`policies/governance/exceptions.rego` requires each exception to contain:

- unique ID and exact asset ID
- accountable owner and approver
- rationale and at least one compensating control
- RFC3339 creation and expiration timestamps
- creation no later than the assessment timestamp
- expiration later than both creation and the assessment timestamp

Duplicate exception IDs fail closed. The evaluator must inject `assessment_time` at run start; a checked-in or user-editable stale timestamp is not an acceptable production control.

The Conftest gate accepts exceptions only from `data.quantumforge_config`. Invalid or expired entries fail closed. See `examples/governance/exceptions.json`.

```bash
conftest test plan.json \
  --policy policies \
  --data examples/governance/exceptions.json
```

Exceptions are temporary control records, not risk reductions. The asset remains in the inventory and scoring output. Organizations should require independent approval and record renewals as new exception versions rather than changing historical evidence.
