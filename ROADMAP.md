# QuantumForge Roadmap

This roadmap distills the future-enhancement items called out in the
companion [PQC Readiness Program Build Guide](docs/PQC_Readiness_Program_Build_Guide.md)
into concrete engineering work for this repo. Two areas are prioritized right
now: making the risk-scoring model reflect real-world **impact**, and
expanding module coverage beyond AWS.

Have an idea, or want to claim an item below? Open an issue or see
[CONTRIBUTING.md](CONTRIBUTING.md) before starting a PR.

---

## Priority 1 — Impact-Driven Risk Scoring

**Where we are today:** `policies/scoring/risk_score.rego` combines three
weighted inputs — HNDL exposure (`hndl_weight`), data classification
(`classification_weight`), and remediation cost (`remediation_cost_weight`) —
into a single 0–100 score that maps to Critical/High/Medium/Low tiers. It's
unit-tested (10/10 passing) and validated against the Build Guide's Phase 2
design, but it has a gap: **data classification is used as a stand-in for
impact**, and it isn't a good one. A "regulated" asset protecting a single
low-traffic internal endpoint and a "regulated" asset underpinning core
authentication for a production-facing service get the same classification
weight today, even though a successful harvest-now-decrypt-later compromise
of the second one is far more consequential.

**Planned change:** promote **Impact** to its own first-class, co-primary
scoring dimension — independent of classification — representing the
blast radius/criticality of the asset if its cryptography is broken.

- [ ] Add `impact_weight(tier)` to `risk_score.rego`, following the existing weight-function pattern:
  ```rego
  impact_weight("mission_critical") := 40
  impact_weight("business_critical") := 25
  impact_weight("operational")       := 10
  impact_weight("informational")     := 5
  ```
- [ ] Update `score(asset)` to treat Impact as co-primary alongside HNDL exposure, moving the model from a flat 3-factor sum toward a Likelihood × Impact–style structure (HNDL exposure ≈ how long the exposure window matters; Impact ≈ magnitude of consequence if it's exploited in that window).
- [ ] Re-derive and re-test the Critical/High/Medium/Low tier thresholds against the new maximum possible score — don't just bolt Impact onto the old thresholds unchanged.
- [ ] Add unit tests for every Impact boundary condition, plus regression tests confirming existing classification-only test cases still tier sensibly.
- [ ] Add an `impact` field to the mock plan fixtures in `examples/sandbox/` so the Conftest gate can reason about impact tier, not just algorithm choice.
- [ ] Update the README's Validation Status table and Rego test counts once merged.
- [ ] Document the scoring formula change in the Build Guide's Phase 2 section, since the current write-up describes the 3-factor version.

**Why this is next:** every other roadmap item below produces *more* assets
to score (more clouds, more resource types). Getting the scoring model right
before scaling out coverage means new modules inherit a better
prioritization signal instead of propagating the current gap.

---

## Priority 2 — Module Coverage Across Platforms & Environments

**Where we are today:** two Terraform modules, both AWS-only —
`hybrid-pqc-kms` (ML-DSA signing keys) and `hybrid-pqc-alb` (hybrid PQ-TLS
listeners). The Build Guide is explicit that AWS is the only platform with
concrete, Terraform-provisionable hybrid-PQC support as of this writing, and
flags Azure as "monitored roadmap item... not a deployable Terraform target"
until Key Vault/Managed HSM catch up to what SymCrypt already supports at
the library level.

**Planned modules**, roughly in the order they become viable:

| # | Module | Platform / Environment | Status |
|---|---|---|---|
| 1 | `hybrid-pqc-keyvault` | Azure Key Vault / Managed HSM | 🔜 Blocked — tracking Azure ML-KEM/ML-DSA GA for Key Vault & Managed HSM provisioning |
| 2 | `hybrid-pqc-cloudkms` | Google Cloud KMS | 🔜 Planned — evaluate Cloud KMS PQC algorithm support as it lands |
| 3 | `hybrid-pqc-hsm` | On-prem / self-hosted HSM & PKI (PKCS#11, HashiCorp Vault) | 🔜 Planned — for environments that can't move fully to a cloud KMS |
| 4 | `hybrid-pqc-mesh` | Kubernetes / service mesh mTLS (cert-manager + Istio/Linkerd) | 💡 Exploratory — waiting on broader CA tooling support for ML-DSA certs |
| 5 | `hybrid-pqc-vpn` | Site-to-site IPsec/IKEv2 tunnels | 💡 Exploratory — directly relevant to the NSS fielded-equipment 2030 phase-out deadline |
| 6 | `hybrid-pqc-signing` | CI/CD artifact signing (Sigstore/cosign) | 💡 Exploratory — post-quantum supply-chain provenance |
| 7 | `hybrid-pqc-tde` | Database encryption at rest (RDS / Cloud SQL / Azure SQL TDE) | 💡 Exploratory — cross-cloud key rotation tied into the same discovery/scoring policies |

Every new module should follow the pattern already established by
`hybrid-pqc-kms`/`hybrid-pqc-alb`:

- Variable `validation` blocks constrain inputs to NIST-approved
  algorithms/constructions — never rely on documentation alone.
- `terraform validate` and `terraform fmt -check -recursive` clean before merge.
- A discovery policy update so `policies/discovery/classify.rego` recognizes the new resource type.
- A README module table entry and a Validation Status row.

---

## Other Build Guide Items Not Yet Scheduled

Called out in the Build Guide but not currently sequenced:

- **Automated CMVP gap analysis** — script the cross-reference against the [NIST CMVP Modules in Process list](https://csrc.nist.gov/projects/cryptographic-module-validation-program/modules-in-process/modules-in-process-list) instead of doing it manually (Phase 2).
- **PQC Migration Priority Matrix generator** — auto-sequence remediation items against the CNSA 2.0 regulatory calendar directly from scored inventory output.
- **CBOM generation in CI** — wire CycloneDX-CBOM generation into `census.yml` rather than a manual step.
- **Executive crypto-census briefing generator** — auto-produce the board-ready "% of estate quantum-vulnerable" summary from inventory + scoring output.

---

## Status Legend

| Symbol | Meaning |
|---|---|
| ✅ | Shipped |
| 🔧 | In progress |
| 🔜 | Planned, not started |
| 💡 | Exploratory / not committed |

This roadmap reflects current thinking and will shift as platform PQC
support (especially Azure and GCP) matures and as the risk-scoring rework
lands. Open an issue if you want to propose reordering or adding an item.
