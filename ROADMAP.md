# QuantumForge Roadmap

QuantumForge expands measurement before remediation surface. New cloud deployment modules should not outrun the inventory, policy, test, and evidence systems needed to evaluate them.

This roadmap distills future work into concrete engineering items. Have an idea, or want to claim an item below? Open an issue or see [CONTRIBUTING.md](CONTRIBUTING.md) before starting a PR. Weighting rationale for the risk-scoring items lives in [docs/SCORING_METHODOLOGY.md](docs/SCORING_METHODOLOGY.md), not here.

## Shipped foundations

- [x] AWS Provider 6.x compatibility and committed lockfiles
- [x] Correct FIPS 204 ML-DSA terminology and pure-PQC KMS module naming
- [x] ALB-only listener contract with exact recommended PQ-TLS policy allowlist
- [x] Credential-free Terraform native mock tests
- [x] Fail-closed Terraform-plan inventory collection and compliance CI
- [x] Real AWS ML-DSA KMS sign/verify lifecycle harness
- [x] Real ALB hybrid PQ-TLS plus classical-fallback runtime harness
- [x] Separate inherent risk, migration urgency, remediation effort, and evidence confidence
- [x] Impact promoted to a first-class, co-primary scoring dimension alongside HNDL exposure and data classification (`impact_weight` in `risk_score.rego`)
- [x] Deadline pressure as an independent 0-100 scale blended into migration urgency (80/20), replacing the additive-and-clamped model that collapsed differentiation inside the critical tier
- [x] Calendar-anchored deadlines derived from CNSA 2.0 equipment categories, recomputed from the current time so a stale hand-entered "months remaining" field can't quietly rot
- [x] Overdue assets (`migration_deadline_months < 0`) as valid, maximally-urgent input rather than rejected input
- [x] Classification/impact divergence flagged for review rather than silently double-counted
- [x] Dependency-fan-in advisory hint for possibly-underrated `impact` values (`dependent_asset_count`)
- [x] `migration_work_queue`: a single ranked list across all valid assets by risk, then urgency, with remediation effort used only as a tiebreaker — the previously-unscheduled "PQC Migration Priority Matrix generator" (see Priority 2 below)
- [x] Owned, approved, expiring exception records
- [x] Attested evidence bundles and an S3 Object Lock publishing interface
- [x] Versioned vendor-neutral crypto-inventory schema

## Priority 1: discovery coverage

Expand source-specific collectors and converters into the canonical inventory schema. Unknown or incomplete evidence must remain visible — a failed collector cannot become an empty or compliant inventory.

1. **Cloud API collectors for keys, certificates, CAs, TLS policies, VPN/IPsec, and ownership tags** — extends beyond the current Terraform-plan-only collection to assets never provisioned through Terraform.
   - [ ] AWS: ACM, KMS custom key stores, and Secrets Manager rotation policies via the AWS SDK, populating `source: "cloud_api"` (already in the schema's `source` enum, currently only emitted in fixtures/design, not by a real collector)
   - [ ] Azure: Key Vault and Managed HSM inventory via the Azure SDK
   - [ ] GCP: Cloud KMS and Certificate Manager via the Cloud SDK
   - [ ] Carry ownership/environment tags into `metadata` rather than dropping them, matching the Terraform-plan collector's existing behavior
   - [ ] Add `policies/inventory/validate_test.rego` cases for the new collector outputs
2. **Cryptographic Bill of Materials (CBOM) and application dependency ingestion**
   - [ ] Define a CycloneDX-CBOM-to-inventory converter emitting `crypto_function: "library"` / `"protocol"` records with `source: "cbom"`
   - [ ] Handle unknown/unparseable CBOM entries as `classification: "unknown"`, never dropped
3. **Active and passive protocol observations**
   - [ ] Normalize TLS handshake captures (cipher suite, key exchange group) into the schema's `protocol` and `algorithm` fields
4. **Certificate expiry, signature, key-size, and chain metadata**
   - [ ] Populate `certificate_not_after` and `key_size_bits` from CA/certificate stores already discoverable via existing collectors, rather than requiring a new source
5. **Data-flow, environment, business impact, and secrecy-lifetime enrichment**
   - [ ] Build an enrichment step that fills `data_flow`, `secrecy_lifetime_years`, `data_classification`, and `impact` from ownership/CMDB records so these aren't purely manual entry
   - [ ] Feed `dependent_asset_count` (Priority-2-adjacent, see gap notes in `docs/SCORING_METHODOLOGY.md`) from the same enrichment pass once a real dependency graph exists
6. **SaaS and manual attestations with explicit confidence**
   - [ ] Structured attestation template mapping directly to `source: "manual_attestation"` plus a required `evidence_confidence`
7. **Kubernetes, container-image, and service-mesh inventory**
   - [ ] cert-manager and service-mesh mTLS certificate inventory, feeding the same schema ahead of any Kubernetes remediation module (see Priority 3)

## Priority 2: governance automation

- [x] Generate migration work queues from risk and urgency while keeping effort separate — implemented as `migration_work_queue` in `policies/scoring/risk_score.rego`, sorted by `inherent_risk_score` desc, then `migration_urgency_score` desc, with `remediation_effort` used only as a tiebreaker. This is the previously-unscheduled "PQC Migration Priority Matrix generator" (see the restored section below) — folded in here rather than left as a separate, disconnected idea.
- [ ] Require independent approval and immutable history for exceptions
  - [ ] `policies/governance/exceptions.rego` already requires owner/approver/rationale/compensating controls; add a check that `owner != approver` for a real independent-approval guarantee
  - [ ] Exception renewals must append a new record rather than mutate `expires_at` in place — add a test asserting the same `id` cannot appear twice with different `expires_at` values (distinct from the existing `duplicate_exception_ids` check, which only catches exact-ID collisions)
- [ ] Add policy/version metadata to every decision
  - [ ] Stamp `assessment.policy_version` (git SHA or semver) into `risk_score.rego`'s and `exceptions.rego`'s output objects so an old evidence bundle can be tied back to the exact policy version that produced it
- [ ] Add dashboards for inventory coverage, stale observations, unknown algorithms, and expiring exceptions
  - [ ] Start from `assessment.invalid_inventory`, `priority_matrix`, and `migration_work_queue` as the data source; no new Rego needed to start, just a rendering layer
- [ ] Add automated NIST Cryptographic Module Validation Program (CMVP) watchlist comparison after a stable machine-readable source and baseline snapshot exist (see restored section below for the specific source)

## Priority 3: platform remediation modules

Only add deployment modules when the target API is generally available and can be proven with a credential-free contract test plus a real isolated-platform lifecycle test.

| Candidate | Platform | Gate before implementation |
|---|---|---|
| Key Vault / Managed HSM PQ signing | Azure | GA resource API, Terraform support, isolated live verification |
| Cloud KMS PQ signing | GCP | GA algorithm, provider support, independent signature verification |
| PKCS#11/Vault signing | On-prem | defined supported HSM matrix and repeatable hardware/software harness |
| PQ-capable mTLS | Kubernetes/service mesh | interoperable CA, proxy, and client support |
| Hybrid IKE/IPsec | Network edge | standards and vendor interoperability test matrix |
| PQ artifact signing | Software supply chain | verifiable consumer support and trust-root lifecycle |

Azure, GCP, on-prem, SaaS, and application assets can already be represented in `schemas/crypto-inventory.schema.json`; representation does not imply deployable PQC support.

Every new Terraform module should follow the pattern already established by `hybrid-pqc-kms`/`hybrid-pqc-alb`:

- [ ] Variable `validation` blocks constrain inputs to NIST-approved algorithms/constructions — never rely on documentation alone
- [ ] `terraform validate` and `terraform fmt -check -recursive` clean before merge
- [ ] A discovery policy update so `policies/discovery/classify.rego` recognizes the new resource type
- [ ] A README module table entry and a Validation Status row

## Other Build Guide items not yet scheduled

Called out in the [PQC Readiness Program Build Guide](docs/PQC_Readiness_Program_Build_Guide.md) but not currently sequenced. Two of the four items previously listed here have moved: automated CMVP watchlist comparison is now tracked under Priority 2 above, and the Migration Priority Matrix generator is implemented (see Shipped foundations and Priority 2). The remaining two:

- **CBOM generation in CI** — wire CycloneDX-CBOM generation into `census.yml` rather than leaving it a manual step ahead of the CBOM ingestion work in Priority 1.
- **Executive crypto-census briefing generator** — auto-produce the board-ready "% of estate quantum-vulnerable" summary directly from `assessment` (inventory + scoring output), rather than a manually assembled deck.

CMVP watchlist comparison specifically means scripting the cross-reference against the [NIST CMVP Modules in Process list](https://csrc.nist.gov/projects/cryptographic-module-validation-program/modules-in-process/modules-in-process-list) instead of doing it manually — tracked as the last bullet under Priority 2.

## Contribution rule

Every new collector or module must include:

- exact algorithm/policy validation rather than substring matching
- deterministic offline tests
- malformed, missing, unknown, and deletion-state cases
- explicit ownership and evidence confidence
- live verification when claiming platform behavior
- unconditional cleanup and a cost estimate for paid tests
- updated inventory, policy, and evidence documentation

## Status legend

| Symbol | Meaning |
|---|---|
| [x] | Shipped |
| [ ] | Planned, not started |

This roadmap reflects current thinking and will shift as platform PQC support (especially Azure and GCP) matures and as discovery coverage expands. Open an issue if you want to propose reordering or adding an item.
