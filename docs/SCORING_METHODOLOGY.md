# Scoring methodology

This document exists so a reviewer or auditor can trace every weight and
bucket boundary in `policies/scoring/risk_score.rego` back to a rationale,
rather than treating them as arbitrary constants. It is the companion to
[GOVERNANCE.md](GOVERNANCE.md), which describes what the scoring dimensions
mean; this document explains why they're weighted the way they are.

## Framework anchor: NIST SP 800-30

The scoring model is a likelihood x impact risk model in the sense used by
[NIST SP 800-30, "Guide for Conducting Risk Assessments"](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-30r1.pdf):

- **Likelihood-side inputs** — how likely is it that this asset's
  cryptography is broken and exploited, and over what time horizon —
  are represented by the harvest-now-decrypt-later (HNDL) exposure window
  (`hndl_weight`, driven by `secrecy_lifetime_years`) and by `data_classification`
  (an NSS or regulated asset draws more attacker attention and sits under a
  harder regulatory deadline than an internal or public one).
- **Impact-side inputs** — how consequential is it if that break happens —
  are represented by `impact` (`impact_weight`), the blast radius/criticality
  of the asset.

`inherent_risk_score` sums these three weights rather than multiplying them,
which is a deliberate simplification versus a strict likelihood x impact
product: the underlying weights are ordinal tiers (four buckets each), not
calibrated probabilities or dollar-loss estimates, so a product would imply
more numeric precision than the inputs actually carry. The sum preserves
monotonicity (more exposure, more sensitive classification, or higher
impact each only ever raise the score) while staying auditable as
"add up the tier weights," which is easy to hand-verify during a review.

## Why HNDL exposure caps at 40 for `secrecy_lifetime_years >= 10`

Harvest-now-decrypt-later is the primary reason PQC migration is urgent
*before* a cryptographically relevant quantum computer exists: data
encrypted today with a vulnerable algorithm can be captured now and
decrypted retroactively once one exists. The bucket boundaries (`>=10`,
`5-10`, `<5` years) follow the horizon most PQC transition guidance
converges on: NIST's own transition timeline
([NIST IR 8547](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf))
treats the mid-2030s as the point where today's <=112-bit classical
algorithms (RSA-2048, ECC P-256) become disallowed, which is roughly a
decade out from when this model was written — so `secrecy_lifetime_years
>= 10` is treated as maximal HNDL exposure rather than continuing to scale
weight upward indefinitely for even longer secrecy requirements.

## Why classification and impact are summed, not multiplied — and the divergence flag

`classification_weight` (0/10/20/30 for public/internal/regulated/nss) and
`impact_weight` (5/10/20/30 for informational/operational/business_critical/
mission_critical) are both additive inputs into `inherent_risk_score`. In
practice these two correlate — an NSS asset is very often also
mission_critical — which risks double-counting the same underlying risk
signal for the common, aligned case.

This model does **not** attempt to correct for that correlation inside the
score itself. Discounting or interaction-term approaches require knowing the
actual correlation structure across a real inventory, and QuantumForge has
none to validate against yet — an unproven correction is worse than an
acknowledged simplification. Instead, `classification_impact_divergence` and
`needs_divergence_review` (in `risk_score.rego`) surface the cases where the
two tiers disagree by two or more levels (e.g. `public` classification but
`mission_critical` impact) for human review. This is exactly the case an
additive model handles worst either way, so flagging it for a person is more
honest than silently reweighting a score built on an unvalidated assumption.
If a future inventory shows a strong, stable correlation, revisit the sum
itself rather than just the flag.

## Migration urgency: an 80/20 blend, not additive-and-clamped

Earlier versions of this model computed
`migration_urgency_score = min(100, inherent_risk_score + deadline_weight)`.
That collapsed differentiation exactly where it mattered most: any asset
with `inherent_risk_score >= 80` (the "critical" tier) combined with any
deadline inside the old 0-6-month bucket (`deadline_weight` = 20) already
hit the 100 ceiling. Two critical-tier assets — one overdue, one three years
from its deadline — reported an identical urgency score, so the ranking
gave no signal for sequencing work inside the tier that most needs
sequencing.

The current model instead computes:

```
migration_urgency_score = round(0.8 * inherent_risk_score + 0.2 * deadline_pressure_score)
```

`deadline_pressure_score` is its own independent 0-100 scale (see bucket
table below), and the 80/20 split is a deliberate design choice, not a
fitted parameter: inherent risk (what's exposed, how sensitive, how
consequential) should dominate the ranking, while deadline pressure adds
meaningful separation without letting a merely soon-due but otherwise minor
asset outrank a maximally risky one. Because both terms are bounded to
[0, 100], the blended score is also always bounded to [0, 100], and an asset
that is both maximally risky *and* maximally deadline-pressured still
resolves to exactly 100 — the old model's "true worst case" behavior is
preserved, just no longer masking every other case in the same tier.

### `deadline_pressure_score` buckets

| Months remaining | Pressure |
|---|---|
| <= 3 (including any negative/overdue value) | 100 |
| 3 < months <= 6 | 85 |
| 6 < months <= 12 | 65 |
| 12 < months <= 24 | 45 |
| 24 < months <= 36 | 25 |
| 36 < months <= 60 | 10 |
| > 60 | 0 |

The buckets get coarser as the deadline gets farther out because precision
close to a deadline is operationally useful (quarterly sequencing) while
precision three-plus years out is not (nothing changes about this week's
work queue based on a five-year versus six-year deadline). A negative value
— the deadline has already passed — maps to the same maximum pressure as
"due within 3 months" rather than being rejected as invalid input: an
overdue asset is the most urgent case this model can represent, not an
erroneous one.

### Where the deadline number comes from

`effective_deadline_months` resolves an asset's deadline from either of two
inputs, in this precedence order:

1. An explicit `migration_deadline_months` on the asset, if present. This
   lets a team commit to an internal deadline tighter than the regulatory
   floor, and always wins when both inputs are supplied.
2. Otherwise, an optional `regulatory_category` mapped to a CNSA 2.0
   "exclusively use CNSA 2.0 algorithms" date
   ([NSA CSA, updated May 30, 2025](https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF)),
   converted to a months-remaining figure computed from the current time
   (`time.now_ns()`) on every policy evaluation. This is deliberately
   calendar-anchored rather than a hand-entered relative number, so the
   countdown can't silently go stale the way a manually maintained "months
   remaining" field would.

| `regulatory_category` | CNSA 2.0 exclusive-use date |
|---|---|
| `software_firmware_signing` | 2030-01-01 |
| `traditional_networking` | 2030-01-01 |
| `web_cloud_services` | 2033-01-01 |
| `operating_systems` | 2033-01-01 |
| `niche_equipment` | 2033-01-01 |
| `custom_legacy` | 2033-01-01 |

An asset with neither input is invalid input, not silently scored with an
optimistic default.

## Migration work queue: effort as a tiebreaker only

`migration_work_queue` ranks all valid assets by `inherent_risk_score`
descending, then `migration_urgency_score` descending, and only uses
`remediation_effort` to break ties between assets that are already equal on
both risk and urgency. This mirrors how `remediation_effort` behaves
everywhere else in the model — it is reported, and can help a team pick
which of two equally urgent items to start first, but it can never make a
lower-risk asset outrank a higher-risk one just because it happens to be
cheaper to fix. Optimizing a work queue purely for "easy wins first" is a
common anti-pattern in vulnerability management: it produces good-looking
throughput numbers while the highest-risk assets sit unaddressed.

## Impact-from-dependencies: an advisory hint, not a derivation

`impact` is currently a manual judgment call, which means it can be wrong —
typically too low, when a reviewer doesn't realize how many other assets
depend on the one in front of them (a signing key backing forty
certificates, marked "operational" because nobody added up the fan-in).
`impact_may_be_underrated`, driven by the optional `dependent_asset_count`
field, flags exactly that case using fixed count thresholds
(`>=25` suggests `mission_critical`, `>=5` suggests `business_critical`,
`>=1` suggests `operational`) without ever overriding the manually set
`impact` value. This is intentionally a minimal, advisory increment rather
than the full fan-in-based impact derivation a real dependency graph would
enable — that requires a dependency-graph field in the inventory schema,
which doesn't exist yet and is tracked under the discovery-coverage
priority in [ROADMAP.md](../ROADMAP.md).

## Worked example

An NSS asset with a 10-year secrecy requirement, `mission_critical` impact,
and a deadline 6 months out:

```
inherent_risk_score = hndl_weight(10) + classification_weight("nss") + impact_weight("mission_critical")
                    = 40 + 30 + 30
                    = 100                                     (tier: critical)

deadline_pressure_score(6) = 85                                (3 < 6 <= 6 bucket)

migration_urgency_score = round(0.8 * 100 + 0.2 * 85)
                        = round(80 + 17)
                        = 97
```

Compare against the same asset with a 3-year-out deadline instead:

```
deadline_pressure_score(36) = 25

migration_urgency_score = round(0.8 * 100 + 0.2 * 25)
                        = round(80 + 5)
                        = 85
```

Both assets tier as `critical` (inherent risk alone decides tier), but the
6-month deadline asset scores meaningfully higher urgency (97 vs. 85) —
exactly the differentiation the old additive-and-clamped model lost once
both assets crossed the 100-point ceiling.
