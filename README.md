# QuantumForge — PQC GRC Framework

A working, policy-as-code post-quantum cryptography readiness program: Terraform modules for hybrid-PQC AWS infrastructure, Rego/OPA policies for crypto discovery, risk scoring, and compliance gating, and GitHub Actions pipelines that turn all of it into continuously generated audit evidence.

This repo implements the four-phase QuantumForge program end to end:

| Phase | What lives here |
|---|---|
| 1. Discovery & Inventory | [`policies/discovery/`](policies/discovery/) — Rego classifier for crypto assets in Terraform plan/state JSON |
| 2. Vulnerability Prioritization | [`policies/scoring/`](policies/scoring/) — Rego risk-scoring engine (HNDL exposure × data classification × remediation cost) |
| 3. Cryptographic Agility Architecture | [`modules/hybrid-pqc-kms/`](modules/hybrid-pqc-kms/), [`modules/hybrid-pqc-alb/`](modules/hybrid-pqc-alb/), [`policies/hybrid/`](policies/hybrid/) — hybrid-PQC Terraform modules + Conftest crypto-agility gate |
| 4. Continuous Compliance | [`.github/workflows/`](.github/workflows/) — CI pipelines producing signed evidence bundles and a CMVP status monitor |

Every module, policy, and workflow in this repo has been validated (`terraform validate`, `opa test`, `conftest test` — see [Validation status](#validation-status) below) before being committed.

---

## Repository layout

```
quantumforge/
├── main.tf                      # root module wiring both hybrid-PQC modules
├── variables.tf, outputs.tf, versions.tf
├── modules/
│   ├── hybrid-pqc-kms/           # AWS KMS ML-DSA (FIPS 204) signing key module
│   └── hybrid-pqc-alb/           # AWS ALB/NLB hybrid post-quantum TLS listener module
├── policies/
│   ├── discovery/                # Phase 1 — crypto asset classifier + unit tests
│   ├── scoring/                  # Phase 2 — risk scoring engine + unit tests
│   └── hybrid/                   # Phase 3/4 — crypto-agility Conftest gate + unit tests
├── examples/sandbox/             # Mock Terraform plan JSON fixtures for exercising the gate without a live AWS account
├── watchlist/cmvp-watchlist.json # Phase 4 — libraries tracked against the NIST CMVP Modules in Process list
├── .github/workflows/
│   ├── census.yml                 # Phase 1 — PR-triggered crypto census + CBOM generation
│   ├── pqc-compliance-gate.yml    # Phase 3/4 — policy tests, Trivy/Checkov scans, Conftest gate, evidence bundle
│   └── cmvp-monitor.yml           # Phase 4 — scheduled CMVP status check
├── ingest/, reports/, evidence/   # CI output directories (gitignored, kept with .gitkeep)
```

---

## Prerequisites

Install locally before working with this repo (full detailed setup steps are in the companion PQC Readiness Program Build Guide document shared alongside this repo):

- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.8.0
- [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa) (`opa`)
- [Conftest](https://www.conftest.dev/install/) (`conftest`)
- AWS CLI v2, configured with credentials that can manage KMS and ELBv2 resources
- (Optional, for CBOM generation) Node.js + `npm install -g @cyclonedx/cdxgen`
- (Optional, for the full PQC test harness described in the build guide) WSL2/Linux with `liboqs` + `liboqs-python`

---

## Quick start

```bash
git clone <this-repo-url>
cd quantumforge

# 1. Unit-test every policy before trusting it
opa test -v policies/discovery/ policies/scoring/ policies/hybrid/

# 2. Validate the Terraform
terraform init
terraform validate

# 3. Plan against your own AWS account (requires real credentials)
terraform plan -out=tfplan
terraform show -json tfplan > plan.json

# 4. Run the crypto-agility gate against your plan
conftest test plan.json -p policies/hybrid/
```

By default `enable_hybrid_pqc_kms = true` and `enable_hybrid_pqc_alb = false` (the ALB module needs an existing load balancer/target group/certificate — see `variables.tf`). Flip `enable_hybrid_pqc_alb` to `true` and supply `existing_load_balancer_arn`, `existing_target_group_arn`, and `existing_acm_certificate_arn` to provision the hybrid-PQC listener too.

### Exercising the gate without AWS credentials

`examples/sandbox/` contains two hand-built plan-JSON fixtures so you can see the gate work without touching a real AWS account:

```bash
# Should FAIL — classical-only RSA signing key + classical TLS policy
conftest test examples/sandbox/mock-plan-classical-fail.json -p policies/hybrid/

# Should PASS — ML-DSA signing key + hybrid post-quantum TLS policy
conftest test examples/sandbox/mock-plan-hybrid-pass.json -p policies/hybrid/
```

---

## Module reference

### `modules/hybrid-pqc-kms`

Provisions an `aws_kms_key` with `key_usage = "SIGN_VERIFY"` and a post-quantum `customer_master_key_spec` (`ML_DSA_44` / `ML_DSA_65` / `ML_DSA_87` — enforced by a variable validation block). Keys are generated and protected inside FIPS 140-3 Security Level 3 validated HSMs by AWS KMS. Signing uses the `ML_DSA_SHAKE_256` algorithm (see the `signing_algorithm` output).

Asymmetric keys, including ML-DSA keys, do not support AWS-managed automatic rotation — `enable_key_rotation` is hardcoded `false` and key rotation must be handled operationally (provision a new key, dual-sign/verify during transition, retire the old key via the `deletion_window_in_days` grace period).

### `modules/hybrid-pqc-alb`

Provisions an `aws_lb_listener` on port 443 using AWS's hybrid post-quantum TLS security policy (`ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09` by default), which negotiates `X25519MLKEM768`, `SecP256r1MLKEM768`, or `SecP384r1MLKEM1024` hybrid key exchange with PQ-capable clients and falls back to classical TLS 1.2/1.3 for clients that don't yet support ML-KEM. A variable validation block requires any `ssl_policy` override to still contain `PQ` — this module exists specifically to enforce PQ-capable listeners; use a plain `aws_lb_listener` resource directly if you need a classical-only listener for some other purpose.

**Azure note:** Azure Key Vault / Managed HSM PQC support is still tracking through 2026 and is not yet available for direct Terraform provisioning as of this writing. There is intentionally no `hybrid-pqc-azure` module yet — track Azure readiness as a roadmap item rather than building against an unstable/unavailable API surface.

---

## Policy reference

### `policies/discovery` (package `quantumforge.discovery`)

Classifies `aws_kms_key` and `aws_lb_listener` resources found in a Terraform plan/state JSON document into `post_quantum` / `classical_only` / `symmetric` / `unknown` (KMS) or `hybrid_post_quantum` / `classical_only` (TLS listeners). Exposes an `inventory` (partial set of classified assets) and a `summary` (roll-up counts) rule — the latter is what the Phase 1 Executive Crypto-Census Briefing is built from.

### `policies/scoring` (package `quantumforge.scoring`)

Takes enriched asset metadata (`data_retention_years`, `data_classification`, `remediation_cost`) and produces a weighted `score` (0–100) and `tier` (`critical`/`high`/`medium`/`low`). `priority_matrix` buckets a full batch of assets by tier — this is the Phase 2 PQC Migration Priority Matrix.

### `policies/hybrid` (package `main`, for use with `conftest`)

The Phase 3/4 Crypto-Agility Gate. `deny` rules block:
- Any `aws_lb_listener` with `protocol = "HTTPS"` whose `ssl_policy` doesn't contain `PQ`
- Any `aws_kms_key` with `key_usage = "SIGN_VERIFY"` whose `customer_master_key_spec` isn't an `ML_DSA_*` spec

A `warn` rule flags `ML_DSA_44` (NIST security level 1) signing keys as a candidate for upgrade to `ML_DSA_65`/`ML_DSA_87` on National Security System assets. The gate fails safe: if no `data.config.enforce_cutover` override is supplied, `enforce_cutover` defaults to `true`.

---

## CI/CD pipelines

- **`census.yml`** — runs on every PR touching `.tf` or discovery-policy files; unit-tests the discovery policy, classifies the plan, regenerates the CBOM, and uploads both as artifacts.
- **`pqc-compliance-gate.yml`** — runs on every PR and push to `main`; unit-tests all three policy packages, runs Trivy and Checkov IaC scans, runs the Conftest crypto-agility gate against the real plan, regenerates the CBOM, and (on push to `main`) assembles a signed, 7-year-retention evidence bundle. Uses GitHub OIDC federation for AWS credentials — no static keys are stored in the repo. **Before this runs against a real AWS account**, provision an IAM role trusted for GitHub OIDC and set its ARN as the `QUANTUMFORGE_EVIDENCE_ROLE_ARN` repository secret, then uncomment the `configure-aws-credentials` step.
- **`cmvp-monitor.yml`** — scheduled weekly job scaffolding a check of the NIST CMVP Modules in Process list against `watchlist/cmvp-watchlist.json`. The actual diff-and-issue logic is left as a `workflow_dispatch`-testable stub (`if: false` on the issue-creation step) — wire in real diffing against a stored previous snapshot before enabling it in production.

---

## Validation status

Everything in this repo was validated before commit:

| Check | Result |
|---|---|
| `terraform validate` (`modules/hybrid-pqc-kms`) | ✅ Success |
| `terraform validate` (`modules/hybrid-pqc-alb`) | ✅ Success |
| `terraform validate` (root module) | ✅ Success |
| `terraform fmt -check -recursive` | ✅ Clean |
| `opa test policies/discovery/` | ✅ 10/10 passed |
| `opa test policies/scoring/` | ✅ 10/10 passed |
| `opa test policies/hybrid/` | ✅ 6/6 passed |
| `conftest test` against a classical-only mock plan | ✅ Correctly denies (2 failures) |
| `conftest test` against a hybrid-PQC mock plan | ✅ Correctly passes |
| GitHub Actions workflow YAML | ✅ Parses cleanly |

`terraform plan` against a real AWS account was not exercised in this environment since no AWS credentials are attached — the modules and root plan resolve correctly up to the point of needing live AWS API access (`aws_caller_identity` / KMS/ELB API calls).

---

## Standards & references

- NIST, [FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final)
- NIST, [FIPS 204 — Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- AWS KMS Developer Guide, [ML-DSA Keys in AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html)
- AWS Documentation, [Security Policies for Your Application Load Balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html) — hybrid PQ-TLS policy `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09`
- Terraform Registry, [`aws_kms_key` resource docs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) — `ML_DSA_44`/`ML_DSA_65`/`ML_DSA_87` key spec support
- NSA, [CNSA 2.0](https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF)
- NIST CSRC, [CMVP Modules in Process List](https://csrc.nist.gov/projects/cryptographic-module-validation-program/modules-in-process/modules-in-process-list)
- [Open Quantum Safe project](https://github.com/open-quantum-safe) — `liboqs` / `oqs-provider`
- [Open Policy Agent](https://github.com/open-policy-agent/opa) / [Conftest](https://github.com/open-policy-agent/conftest)

---

*Part of the QuantumForge PQC GRC Framework. This is the implementation repo for the companion PQC Readiness Program Build Guide document.*
