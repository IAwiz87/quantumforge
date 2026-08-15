# PQC Readiness Program — Full Build Guide
### From Bare Metal to a Functioning Post-Quantum Cryptographic Agility Practice

**Prepared for:** Enterprise / regulated-sector clients pursuing CNSA 2.0, NIST PQC (FIPS 203/204/205/206), and FIPS 140-3 readiness
**Methodology:** Policy-as-code (Rego/OPA), Terraform + Conftest infrastructure validation, and CI/CD-driven compliance evidence generation — the same automation backbone used across mature GRC engineering practices, here re-purposed end-to-end for post-quantum cryptographic migration.
**Scope of this document:** Everything needed to stand up the program from an empty workstation/repo to a continuously-evidenced, four-phase PQC readiness pipeline: prerequisite software, open-source tooling to import per phase, concrete configuration, and the phase-by-phase technical deliverables.

---

## Program Rationale


Three regulatory clocks are running simultaneously for any enterprise handling sensitive or regulated data:

- **CNSA 2.0** (NSA Commercial National Security Algorithm Suite 2.0): no enforcement before December 31, 2025; all new National Security System acquisitions must be CNSA 2.0-compliant by January 1, 2027; non-supporting fielded equipment phased out by December 31, 2030; full cryptographic enforcement across NSS by December 31, 2031; full quantum-resistance across NSS by 2035 per NSM-10 ([SafeLogic](https://www.safelogic.com/compliance/cnsa-2)). A 2026 federal PQC executive order accelerates the civilian-agency timeline further, requiring high-value-asset and high-impact systems to migrate key establishment by December 31, 2030 and digital signatures by December 31, 2031 ([White House, Executive Order 14412](https://www.whitehouse.gov/presidential-actions/2026/06/securing-the-nation-against-advanced-cryptographic-attacks/)).
- **NIST PQC algorithm standards**: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) were finalized August 2024 ([NIST](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards); [CSRC FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)). FIPS 206 (FN-DSA, Falcon-based) remains in draft as of this writing — track it, do not deploy it in production yet ([PostQuantum.com](https://postquantum.com/security-pqc/nist-third-round-pqc-signatures/); [DigiCert](https://www.digicert.com/blog/quantum-ready-fndsa-nears-draft-approval-from-nist)).
- **FIPS 140-3 / Cryptographic Module Validation Program (CMVP) validation lag**: as of early 2026 very few cryptographic modules have completed full CMVP validation with ML-KEM/ML-DSA support (AWS-LC is a notable exception — the first open-source crypto module with ML-KEM in an active FIPS 140-3 validation). Most vendors sit in the "Modules in Process" queue with 12+ month waits ([CIQ](https://ciq.com/blog/preparing-your-infrastructure-for-post-quantum-cryptography); [AWS](https://aws.amazon.com/security/post-quantum-cryptography/)). This validation gap is exactly why **hybrid classical+PQC architectures** (governed by NIST SP 800-227) are the practical near-term compliance posture.

This program operationalizes the transition using a policy-as-code and continuous-evidence toolchain: Rego/OPA for machine-readable control logic, Terraform+Conftest for pre-deployment infrastructure gating, and GitHub Actions (or equivalent CI) for tamper-evident, always-on compliance evidence. The four phases below take that toolchain from an empty repository to a fully operating PQC governance capability.


---

## Part 1 — Prerequisite Software & Environment Setup

This program assumes a primary Windows 11 / PowerShell 7+ workstation with Git Bash and WSL2 available (the standard advanced-practitioner stack), with cross-platform notes where relevant. Install everything below **before** starting Phase 1.

### 1.1 Core version control & shell tooling

| Tool | Purpose | Install (Windows/PowerShell) | Verify |
|---|---|---|---|
| **Git** | Version control for all policy/IaC repos | `winget install --id Git.Git -e` | `git --version` |
| **GitHub CLI** | Repo automation, Actions triggering, PR management from terminal | `winget install --id GitHub.cli -e` then `gh auth login` | `gh auth status` |
| **WSL2 + Ubuntu** | Required for compiling `liboqs`/`oqs-provider` (their C build toolchains are impractical natively on Windows) | `wsl --install -d Ubuntu` (run as Administrator, reboot when prompted) | `wsl --list --verbose` |
| **VS Code** | Primary IDE | `winget install --id Microsoft.VisualStudioCode -e` | Launch and confirm |
| **VS Code extensions** | Terraform + Rego syntax/linting | Install "HashiCorp Terraform" (`hashicorp.terraform`) and "Open Policy Agent" by Torin Sandall (`tsandall.opa`) from the Extensions marketplace | Extensions panel shows both active |

### 1.2 Infrastructure-as-Code toolchain

**Terraform**
```powershell
winget install --id Hashicorp.Terraform -e
terraform version
terraform -install-autocomplete   # optional, adds tab-completion to PowerShell profile
```
Manual fallback: download the Windows amd64 zip from [developer.hashicorp.com/terraform/install](https://developer.hashicorp.com/terraform/install), extract to `C:\terraform`, add that folder to your `PATH` environment variable (`System Properties > Environment Variables > Path > New`).

Configure a remote backend and provider block once, in a shared `versions.tf` used by every module in the program:
```hcl
terraform {
  required_version = ">= 1.8.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.2"   # 6.2+ supports ML_DSA_44/65/87 on aws_kms_key
    }
  }
  backend "s3" {
    bucket         = "your-org-tfstate"
    key            = "pqc-readiness/terraform.tfstate"
    region         = "us-east-1"
    use_lockfile    = true
    encrypt        = true
  }
}
```

**AWS CLI v2**
```powershell
winget install --id Amazon.AWSCLI -e
aws configure sso   # preferred over long-lived static keys for a compliance program
aws sts get-caller-identity
```

**Azure CLI**
```powershell
winget install --id Microsoft.AzureCLI -e
az login
az account show
```

### 1.3 Policy-as-code toolchain

**Open Policy Agent (OPA)** — no official winget package exists yet, so pull the binary directly:
```powershell
New-Item -ItemType Directory -Force -Path "C:\Tools\OPA"
Invoke-WebRequest -Uri "https://openpolicyagent.org/downloads/latest/opa_windows_amd64.exe" -OutFile "C:\Tools\OPA\opa.exe"
[Environment]::SetEnvironmentVariable("Path", "$env:Path;C:\Tools\OPA", "User")
# open a new PowerShell window, then:
opa version
```
A community Chocolatey package (`choco install open-policy-agent`) is also available if you already run Chocolatey.

**Conftest** — official Windows path is via Scoop:
```powershell
# one-time Scoop bootstrap if not already installed
Invoke-RestMethod get.scoop.sh | Invoke-Expression
scoop install conftest
conftest --version
```
Fallback (no Scoop): download the Windows binary from the [conftest releases page](https://github.com/open-policy-agent/conftest/releases) and place it on `PATH` manually, or `go install github.com/open-policy-agent/conftest@latest` if you have Go installed.

**Trivy** (infrastructure-as-code, container, and Cryptographic Bill of Materials scanner; it absorbed `tfsec`'s functionality, and `tfsec`'s own repository now redirects users to Trivy):
```powershell
winget install --id AquaSecurity.Trivy -e
trivy --version
```

**Checkov** (Python-based IaC policy scanner, complements Rego/Conftest with a large pre-built ruleset):
```powershell
pip install checkov
checkov --version
```

### 1.4 Post-quantum cryptography libraries (build inside WSL2 Ubuntu)

Native PQC algorithm libraries (`liboqs`, `oqs-provider`) require a C toolchain (`cmake`, `ninja`, `gcc`, `libssl-dev`) that is far simpler to satisfy inside WSL2 than on native Windows.

```bash
# inside WSL2 Ubuntu shell
sudo apt update && sudo apt install -y build-essential cmake ninja-build libssl-dev python3-pip git

# 1. Build liboqs (core PQC algorithm implementations)
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B liboqs/build -GNinja -DCMAKE_INSTALL_PREFIX=/opt/liboqs
cmake --build liboqs/build --parallel "$(nproc)"
sudo cmake --install liboqs/build

# 2. Build oqs-provider (plugs PQC algorithms into OpenSSL 3.x as a provider)
git clone --depth 1 https://github.com/open-quantum-safe/oqs-provider.git
cmake -S oqs-provider -B oqs-provider/build -GNinja \
  -DOPENSSL_ROOT_DIR=/usr \
  -Dliboqs_DIR=/opt/liboqs/lib/cmake/liboqs
cmake --build oqs-provider/build --parallel "$(nproc)"
sudo cmake --install oqs-provider/build

# 3. Register the provider with OpenSSL (edit /etc/ssl/openssl.cnf — add under [provider_sect]):
#    oqsprovider = oqsprovider_sect
#    [oqsprovider_sect]
#    activate = 1
openssl list -providers          # confirm "oqsprovider" appears
openssl list -kem-algorithms      # confirm ML-KEM variants are listed
```

Python bindings for scripting test harnesses (Phase 3):
```bash
pip install liboqs-python
```

### 1.5 CBOM / OSCAL / compliance-as-code tooling

```bash
# CBOM generation (Node-based, works on Windows or WSL2)
npm install -g @cyclonedx/cdxgen

# CycloneDX CLI for merging/diffing/validating BOMs
# download platform binary from https://github.com/CycloneDX/cyclonedx-cli/releases

# OSCAL compliance-as-code (Python)
pip install compliance-trestle

# NIST's own OSCAL CLI (Java-based; requires JRE 11+)
# download from https://github.com/usnistgov/oscal-cli/releases
```

### 1.6 Environment sanity check

Run this once everything above is installed to confirm the full toolchain is ready before Phase 1 begins:
```powershell
git --version; gh --version; terraform version; aws --version; az --version
opa version; conftest --version; trivy --version; checkov --version
wsl -e bash -c "openssl list -providers && python3 -c 'import oqs; print(oqs.get_enabled_kem_mechanisms())'"
```

---

## Part 2 — Open-Source Tooling Directory

Every tool below is real, actively maintained, and mapped to the phase(s) where it is imported. GitHub star counts are current as of this program's compilation and indicate maturity/community trust, not a quality guarantee — vet license and maintenance cadence before production use.

| Tool | Phase(s) | Purpose | Repo |
|---|---|---|---|
| **liboqs** (2,991★) | 1, 3 | C library implementing FIPS 203/204/205 (and draft) algorithms; the core PQC primitive engine everything else builds on | [open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs) |
| **oqs-provider** (484★) | 1, 3 | OpenSSL 3 provider exposing liboqs algorithms to any OpenSSL-linked application/protocol stack — this is what makes discovery and hybrid-TLS testing possible without patching every client | [open-quantum-safe/oqs-provider](https://github.com/open-quantum-safe/oqs-provider) |
| **liboqs-python / -go / -rust / -java** | 3 | Language bindings for building algorithm test harnesses and CI validation scripts | [liboqs-python](https://github.com/open-quantum-safe/liboqs-python) · [liboqs-go](https://github.com/open-quantum-safe/liboqs-go) · [liboqs-rust](https://github.com/open-quantum-safe/liboqs-rust) · [liboqs-java](https://github.com/open-quantum-safe/liboqs-java) |
| **PQClean** (945★) | 3 | Clean, portable, side-channel-conscious reference implementations — useful as a correctness/interoperability cross-check against liboqs | [PQClean/PQClean](https://github.com/PQClean/PQClean) |
| **CIRCL** (1,688★) | 3 | Cloudflare's crypto library with production-hardened PQC (used in Cloudflare's own PQC TLS rollout) — reference for Go-based services | [cloudflare/circl](https://github.com/cloudflare/circl) |
| **AWS-LC** (798★) | 1, 3 | FIPS 140-3 validated crypto library; first open-source module with ML-KEM in an active FIPS validation — reference architecture for what a validated hybrid module looks like | [aws/aws-lc](https://github.com/aws/aws-lc) |
| **OQS-OpenSSH** (234★) | 3 | PQC-enabled OpenSSH fork — used to test hybrid key exchange on SSH-based administrative access paths, not just TLS | [open-quantum-safe/openssh](https://github.com/open-quantum-safe/openssh) |
| **CBOMkit** (112★) + **CBOMkit-action** (15★) | 1 | Cryptography Bill of Materials generation/analysis toolkit, plus a ready-made GitHub Action for CI integration | [cbomkit/cbomkit](https://github.com/cbomkit/cbomkit) · [cbomkit/cbomkit-action](https://github.com/cbomkit/cbomkit-action) |
| **cdxgen** (1,011★) | 1 | General-purpose CycloneDX/CBOM generator, multi-language, drop-in CLI for CI pipelines | [CycloneDX/cdxgen](https://github.com/CycloneDX/cdxgen) |
| **cyclonedx-cli** (516★) | 1, 4 | Merge/diff/convert/validate BOM documents — used to diff CBOMs release-over-release and flag newly introduced non-agile crypto | [CycloneDX/cyclonedx-cli](https://github.com/CycloneDX/cyclonedx-cli) |
| **OPA** (11,952★) | 1, 2, 3, 4 | The Rego policy engine underpinning every phase's classification, scoring, and gating logic | [open-policy-agent/opa](https://github.com/open-policy-agent/opa) |
| **Conftest** (3,217★) | 1, 3, 4 | Runs Rego policies against structured config (Terraform plan JSON, Kubernetes manifests, CBOM JSON) — the connective tissue between OPA and IaC | [open-policy-agent/conftest](https://github.com/open-policy-agent/conftest) |
| **Regula** (965★) | 1, 2 | Pre-built Rego policy library for Terraform/CloudFormation/K8s across AWS/Azure/GCP — a starting policy set to fork rather than write from zero | [fugue/regula](https://github.com/fugue/regula) |
| **Trivy** (36,804★) | 1, 4 | Unified IaC/container/SBOM/vulnerability scanner; absorbed tfsec's misconfiguration-scanning capability | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) |
| **Checkov** (8,852★) | 1, 4 | Python-based IaC scanner with a very large built-in policy set; runs alongside Rego/Conftest for defense-in-depth | [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) |
| **Terrascan** (5,207★) | 1 | Additional IaC scanner, useful as a second-opinion cross-check on discovery-phase findings | [tenable/terrascan](https://github.com/tenable/terrascan) |
| **compliance-trestle** (261★) | 4 | OSCAL compliance-as-code Python toolkit — maps control evidence to NIST SP 800-53 control IDs in machine-readable OSCAL format | [oscal-compass/compliance-trestle](https://github.com/oscal-compass/compliance-trestle) |
| **oscal-cli** (67★) + **oscal-content** (448★) | 4 | NIST's own OSCAL validator, plus official SP 800-53 OSCAL catalog content to map controls against | [usnistgov/oscal-cli](https://github.com/usnistgov/oscal-cli) · [usnistgov/oscal-content](https://github.com/usnistgov/oscal-content) |
| **ComplianceAsCode/content** (2,758★) | 4 | SCAP/Bash/Ansible security-automation content — useful reference set for host-level crypto configuration hardening checks | [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content) |
| **InSpec** (3,081★) | 4 | Auditing/testing framework for writing human-readable compliance checks that also execute as code | [inspec/inspec](https://github.com/inspec/inspec) |
| **Heimdall2** (254★) | 4 | Aggregates and visualizes results from Trivy/Checkov/InSpec/OPA scans in one compliance dashboard | [mitre/heimdall2](https://github.com/mitre/heimdall2) |
| **Terratest** (7,930★) | 3 | Go library for writing automated tests against real provisioned Terraform infrastructure — used to validate hybrid-PQC modules actually establish the expected key exchange, not just that `terraform apply` succeeds | [gruntwork-io/terratest](https://github.com/gruntwork-io/terratest) |
| **PQCA working groups** | reference | Post-Quantum Cryptography Alliance (Linux Foundation) — governance/landscape repos, useful for tracking industry-wide readiness-tracking methodology and algorithm-adoption consensus, not directly importable tooling | [github.com/pqca](https://github.com/pqca) |

---

## Part 3 — Phase-by-Phase Program

### Phase 1 — Discovery & Inventory: Automated Crypto-Census

**Objective:** Build a machine-readable, coverage-tracked inventory of cryptographic algorithms, keys, certificates, protocols, libraries, applications, and data flows before remediation is scoped. No single collector should be described as complete.

**Technical approach:** Cryptographic discovery has two complementary data sources, and a mature inventory process pulls from both:
1. **Infrastructure-as-code plans** — Terraform plan JSON exposes supported managed resources without copying secrets from state. The current adapter covers representative AWS KMS, certificate, TLS, API Gateway, CloudFront, and VPN resources and preserves unsupported values as `unknown`.
2. **Vendor-neutral source converters** — certificate stores, protocol scans, package/dependency analysis, application inventories, SaaS exports, and data-flow catalogs must be normalized into `schemas/crypto-inventory.schema.json`. `scripts/generate-cbom.py` records the repository's enforced cryptographic allowlists; it is not a substitute for runtime or source-code discovery.

Collected records are normalized into the versioned inventory envelope and classified by shared policy. Coverage metadata and `unknown` values remain visible so missing collectors cannot be mistaken for a clean estate.

**Setup steps:**
1. Initialize and validate the repository using the committed lockfile:
   ```bash
   terraform init -backend=false -lockfile=readonly
   terraform validate
   ```
2. In an authorized environment, collect a Terraform plan rather than copying state:
   ```bash
   terraform plan -refresh=false -out=ingest/tfplan
   terraform show -json ingest/tfplan > ingest/tfplan.json
   ```
3. Run the tested classifier and emit a versioned inventory plus explicit assessment status:
   ```bash
   ./scripts/run-census.sh ingest/tfplan.json reports/census
   check-jsonschema \
     --schemafile schemas/crypto-inventory.schema.json \
     reports/census/iac-inventory.json
   ```
4. Run every Rego regression test before trusting the generated inventory or deployment gate:
   ```bash
   opa test -v policies/
   ```
5. Generate the repository policy CBOM and validate that it is non-empty:
   ```bash
   ./scripts/generate-cbom.py reports/quantumforge-policy.cdx.json
   jq -e '.bomFormat == "CycloneDX" and (.components | length > 0)' \
     reports/quantumforge-policy.cdx.json
   ```
6. Add separate, tested source converters for dependencies, certificates, protocols, applications, SaaS, and data flows. Validate every converter output against `schemas/crypto-inventory.schema.json` before merging it into an environment inventory. The pull request's generated test plan proves framework behavior only; it is not an environment assessment.

**Client-ready deliverables:**

| # | Deliverable | Standard Addressed |
|---|---|---|
| 1 | **Cryptographic Asset Inventory Report** — schema-validated, adapter-derived inventory with explicit collector coverage and unknowns | CNSA 2.0 scoping; FIPS 140-3 module boundary identification |
| 2 | **Crypto Bill of Materials (CBOM)** — CycloneDX JSON for enforced repository algorithms and policies, extended only when tested source/runtime adapters are available | Ongoing crypto-agility baseline |
| 3 | **Algorithm Risk Register** — every discovered asset scored against CNSA 2.0 categories, FIPS 203/204/205 applicability, and Harvest-Now-Decrypt-Later (HNDL) exposure | CNSA 2.0; NIST SP 800-227 §4 deployment conditions |
| 4 | **Executive Cryptographic Inventory Briefing** — board-ready summary translating the inventory into "% of estate quantum-vulnerable" and "days to CNSA 2.0 milestone" language | Client governance reporting |

---

### Phase 2 — Vulnerability Prioritization: Risk Mapping

**Objective:** Convert the raw inventory into a prioritized, deadline-anchored remediation roadmap.

**Technical approach:** Discovery-phase policies answer "what is it?" — Phase 2 policies answer "how urgently does it need to move?" Enrich the same schema-valid canonical asset records with secrecy lifetime, data classification, impact, migration deadline, and remediation effort. The risk model combines HNDL exposure, data classification, and business impact. Migration deadline, remediation effort, and evidence confidence remain separate outputs. A difficult migration must never appear less risky merely because it is expensive. Missing metadata is invalid rather than receiving an optimistic default. Every scoring function is unit-tested with `opa test` before it is trusted for client-facing prioritization output.

**Setup steps:**
1. Extend the Phase 1 repo with a scoring module (`policies/scoring/risk_score.rego`):
   ```rego
   package quantumforge.scoring

   import rego.v1

   hndl_weight(years) := 40 if years >= 10
   hndl_weight(years) := 25 if years >= 5; years < 10
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
   deadline_weight(months) := 10 if months > 6; months <= 18
   deadline_weight(months) := 0 if months > 18

   inherent_risk_score(asset) := total if {
       total := hndl_weight(asset.secrecy_lifetime_years) +
                 classification_weight(asset.data_classification) +
                 impact_weight(asset.impact)
   }

   migration_urgency_score(asset) := min([100,
       inherent_risk_score(asset) + deadline_weight(asset.migration_deadline_months)
   ])

   tier(asset) := "critical" if migration_urgency_score(asset) >= 80
   tier(asset) := "high" if migration_urgency_score(asset) >= 60; migration_urgency_score(asset) < 80
   tier(asset) := "medium" if migration_urgency_score(asset) >= 35; migration_urgency_score(asset) < 60
   tier(asset) := "low" if migration_urgency_score(asset) < 35
   ```

   > **Note:** this snippet is the Phase 2 origin design and is kept as-written for history. The shipped `policies/scoring/risk_score.rego` has since evolved past it — `deadline_weight`'s additive-and-clamped formula collapsed differentiation once `inherent_risk_score` hit 80, so `migration_urgency_score` is now an explicit 80/20 blend against a separate `deadline_pressure_score` scale, deadlines can be calendar-anchored to a `regulatory_category` instead of only a hand-entered `migration_deadline_months`, and `tier` is now derived from `inherent_risk_score` rather than the blended urgency score. See [docs/SCORING_METHODOLOGY.md](SCORING_METHODOLOGY.md) for the current model and rationale.

2. Write unit tests covering boundary conditions on every tier threshold before deployment:
   ```bash
   opa test -v policies/scoring/
   ```
3. Add the schema-defined risk-enrichment fields to the Phase 1 assets, validate the enriched envelope, and produce a tiered priority list:
   ```bash
   check-jsonschema --schemafile schemas/crypto-inventory.schema.json reports/risk-input.json
   opa eval --format raw -d policies -i reports/risk-input.json \
     "data.quantumforge.scoring.assessment" > reports/priority-tiers.json
   ```
4. Cross-reference each asset's current CMVP module dependency against the [NIST CMVP Modules in Process list](https://csrc.nist.gov/projects/cryptographic-module-validation-program/modules-in-process/modules-in-process-list) to flag which remediation items are gated on a vendor's pending validation rather than the client's own engineering effort.

**Client-ready deliverables:**

| # | Deliverable | Standard Addressed |
|---|---|---|
| 1 | **Risk-Scored Rego Policy Library** — weighted scoring function producing Critical/High/Medium/Low tiers, unit-tested before deployment | Internal risk taxonomy aligned to CNSA 2.0 exposure categories |
| 2 | **PQC Migration Priority Matrix** — remediation items sequenced against the regulatory calendar: no-enforcement baseline (Dec 31, 2025), new NSS acquisition mandate (Jan 1, 2027), fielded-equipment phase-out (Dec 31, 2030), full NSS enforcement (Dec 31, 2031), full quantum-resistance (2035 per NSM-10), and the accelerated civilian key-establishment (Dec 31, 2030) / signature (Dec 31, 2031) deadlines | [CNSA 2.0 timeline](https://www.safelogic.com/compliance/cnsa-2); [2026 PQC EO](https://www.centerforcybersecuritypolicy.org/insights-and-research/from-strategy-to-implementation-the-white-house-accelerates-the-federal-transition-to-post-quantum-cryptography) |
| 3 | **FIPS 140-3 Module Gap Analysis** — cross-references current CMVP certificate numbers against the "Modules in Process" queue for ML-KEM/ML-DSA support | FIPS 140-3 / CMVP validation status |
| 4 | **Quantified Risk Briefing Deck** — board-level dollar exposure estimates, compliance-deadline countdowns, contractual crypto clauses at risk | Client governance / audit readiness |

---

### Phase 3 — Cryptographic Agility Architecture: Hybrid-PQC Testing

**Objective:** Design, provision, and validate PQC infrastructure. Keep pure post-quantum signing distinct from hybrid classical-plus-PQC key establishment.

**Technical approach:** This is where discovery and prioritization convert into provisioned infrastructure. AWS KMS ML-DSA is pure FIPS 204 post-quantum signing. The ELB policy is hybrid ML-KEM plus classical key establishment for migration compatibility. The policy gate therefore uses exact service-supported algorithm and policy allowlists rather than claiming that every resource implements a hybrid combiner.

As of this writing, real hybrid-PQC capability exists concretely on AWS and should be the primary target for production Terraform modules:
- **AWS KMS** supports ML-DSA signing keys natively via `key_spec = "ML_DSA_44" | "ML_DSA_65" | "ML_DSA_87"` on `aws_kms_key`, using the `ML_DSA_SHAKE_256` signing algorithm, generated and protected inside FIPS 140-3 Level 3 validated HSMs ([AWS KMS docs](https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html)).
- **AWS Application Load Balancers** support hybrid post-quantum TLS on `HTTPS` listeners through policies such as `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09`, which offers `X25519MLKEM768` and classical compatibility. This repository's deployment module is ALB-only. Network Load Balancers use `TLS` listeners and require a separate implementation and runtime validation.
- **AWS ACM, Secrets Manager, and KMS API endpoints** already support ML-KEM hybrid key agreement on non-FIPS endpoints across all commercial regions ([AWS announcement](https://aws-news.com/article/2025-04-07-ml-kem-post-quantum-tls-now-supported-in-aws-kms-acm-and-secrets-manager)).
- **Azure** is behind AWS here: SymCrypt (Azure's underlying crypto library) gained ML-KEM/ML-DSA support in late 2024, but Azure Key Vault and Managed HSM PQC support is still tracking through 2026 and is not yet available for direct Terraform provisioning. Treat Azure PQC as a monitored roadmap item in this phase, not a deployable Terraform target — document readiness but do not promise client-facing Azure PQC infrastructure yet.

**Setup steps:**
1. Add a pure post-quantum signing module to the Terraform repo (`modules/pqc-kms-signing/main.tf`):
   ```hcl
   resource "aws_kms_key" "pqc_signing" {
     description              = "ML-DSA post-quantum signing key"
     key_usage                = "SIGN_VERIFY"
     customer_master_key_spec = "ML_DSA_65"   # FIPS 204 security category 3
     deletion_window_in_days  = 30
     enable_key_rotation      = false          # asymmetric keys cannot auto-rotate
   }

   resource "aws_kms_alias" "pqc_signing" {
     name          = "alias/pqc-readiness-signing"
     target_key_id = aws_kms_key.pqc_signing.key_id
   }
   ```
2. Add a hybrid-PQC TLS listener module (`modules/hybrid-pqc-alb/main.tf`):
   ```hcl
   resource "aws_lb_listener" "https_pqc" {
     load_balancer_arn = aws_lb.this.arn
     port              = 443
     protocol          = "HTTPS"
     ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
     certificate_arn   = var.acm_certificate_arn

     default_action {
       type             = "forward"
       target_group_arn = var.target_group_arn
     }
   }
   ```
3. Use the committed Conftest gate (`policies/hybrid/combiner.rego`). It exact-allowlists AWS ML-DSA parameter sets and versioned ALB PQ policies, rejects malformed plan input, and evaluates governed exception expiry against OPA's runtime clock:
   ```bash
   opa test -v policies/
   conftest test tfplan.json --policy policies/
   ```
4. Run the full plan-to-gate pipeline:
   ```bash
   terraform init
   terraform plan -out=tfplan
   terraform show -json tfplan > tfplan.json
   conftest test tfplan.json --policy policies/
   ```
5. In the isolated AWS sandbox, run the guarded KMS lifecycle to create `ML_DSA_65`, sign and verify through KMS, independently verify with OpenSSL, and require `PendingDeletion` cleanup evidence:
   ```bash
   QUANTUMFORGE_ALLOW_LIVE_AWS_TESTS=1 \
   QUANTUMFORGE_EXPECTED_ACCOUNT_ID="$EXPECTED_SANDBOX_ACCOUNT" \
   ./scripts/aws/kms-lifecycle-test.sh build/live-kms
   ```
6. Run the guarded ALB lifecycle and require real `X25519MLKEM768` plus classical `X25519` handshakes before cleanup can pass:
   ```bash
   QUANTUMFORGE_ALLOW_LIVE_AWS_TESTS=1 \
   QUANTUMFORGE_EXPECTED_ACCOUNT_ID="$EXPECTED_SANDBOX_ACCOUNT" \
   ./scripts/aws/alb-pqtls-lifecycle-test.sh build/live-alb
   ```

**Client-ready deliverables:**

| # | Deliverable | Standard Addressed |
|---|---|---|
| 1 | **AWS PQC Terraform Modules** — pure FIPS 204 ML-DSA signing plus an ALB-only hybrid PQ-TLS listener, with their different cryptographic contracts explicit | FIPS 204; AWS hybrid PQ-TLS service policy |
| 2 | **Conftest Crypto-Agility Gate** — exact service allowlists, malformed-input rejection, and owner-approved expiring exceptions for Terraform plans | CNSA 2.0 forward posture; crypto-agility governance |
| 3 | **Live AWS Runtime Evidence Harness** — isolated KMS sign/verify and independent OpenSSL verification plus ALB hybrid/classical negotiation and cleanup evidence | FIPS 204 algorithm use; AWS service runtime behavior |
| 4 | **Crypto-Agility Reference Architecture Document** — abstracted crypto-provider boundary design so future algorithm swaps require configuration changes, not re-architecture | Crypto-agility principle underlying CNSA 2.0 and NSM-10 |

---

### Phase 4 — Continuous Compliance: IaC Validation

**Objective:** Operationalize PQC posture as a continuously evidenced, audit-ready control rather than a one-time project.

**Technical approach:** Every prior phase produces artifacts (inventory JSON, risk scores, Terraform plans, policy test results) that are valuable to an auditor only when they are complete, timestamped, attributable, and retrievable. The credential-free gate validates every pull request, trusted pushes to `main` attest complete bundles, and a separate protected workflow performs live AWS tests. Optional S3 Object Lock publication provides the long-term immutable-retention interface; OSCAL mapping can then connect evidence to formal controls such as SP 800-53 and SOC 2.

**Setup steps:**
1. Use `.github/workflows/pqc-compliance-gate.yml` for pull requests and pushes. This workflow is deliberately credential-free, has only `contents: read`, checks out without persisting the GitHub token, and fails when Terraform, policy, scanner, schema, CBOM, or evidence generation fails.
2. Keep AWS credentials out of pull-request execution. Run `.github/workflows/aws-live-pqc-validation.yml` only by manual dispatch from `main`, behind the protected `quantumforge-aws-sandbox` environment. Use the main-only cleanup environment, named `quantumforge-aws-sandbox-janitor`, for post-job checks and hourly removal of expired test resources. These jobs receive job-scoped `id-token: write` and use GitHub OpenID Connect (OIDC) to assume a dedicated sandbox role.
3. Build evidence with `scripts/build-evidence.py`, attest the complete ZIP with GitHub artifact attestations, retain the ordinary workflow copy for only 30 days, and optionally publish the attested bundle with `scripts/publish-evidence-s3.sh` to a separately administered S3 Object Lock bucket. GitHub artifact retention alone is not a seven-year record system.
4. Map evidence artifacts to formal controls with `compliance-trestle`, generating OSCAL assessment-results documents that reference the CI-produced evidence bundle by commit SHA:
   ```bash
   trestle init
   trestle author profile-generate -n pqc-readiness -o pqc-readiness-profile
   # populate implemented-requirements referencing SC-12 (key management) and SC-13 (cryptographic protection)
   trestle validate -f pqc-readiness-profile/profile.json
   ```
5. Use `.github/workflows/cmvp-reference-capture.yml` to validate the repository's pinned watchlist and retrieve a checksummed copy of NIST's Modules in Process PDF every week. It does not claim to parse status changes or open issues until a tested collector is added.
6. Feed accumulated evidence bundles into Heimdall2 for a rolling compliance dashboard the client's GRC/security team can review without opening individual JSON artifacts.

**Client-ready deliverables:**

| # | Deliverable | Standard Addressed |
|---|---|---|
| 1 | **PQC Framework Validation Gate** — credential-free module mocks, static scans, generated policy-test plans, normalized synthetic inventory, and an attested validation bundle on protected `main` pushes; not an environment posture assessment | Continuous control-software verification |
| 2 | **OSCAL-Mapped Evidence Registry** — evidence bundles mapped via compliance-trestle to SP 800-53 control IDs (SC-12 key management, SC-13 cryptographic protection), consumable by any OSCAL-compatible GRC platform | SP 800-53 SC-12/SC-13; CNSA 2.0 audit trail |
| 3 | **CMVP Reference Capture** — scheduled retrieval and checksum of NIST's Modules in Process PDF plus watchlist schema validation; deterministic status comparison remains roadmap work | CMVP reference provenance |
| 4 | **Quarterly PQC Compliance Attestation Report** — a planned report built only from real environment assessments, current CMVP analysis, trusted attestations, and immutable records | CNSA 2.0; FIPS 140-3; client contractual assurance |

---

## Part 4 — Master Build Sequence (Bare Metal → Functioning Program)

Follow this sequence exactly on a fresh workstation/repo to stand up the entire program end to end:

1. **Install prerequisites** (Part 1, sections 1.1–1.6). Run the sanity-check block at the end of 1.6 and confirm every tool reports a version before proceeding.
2. **Bootstrap the repository structure:**
   ```
   pqc-readiness-program/
   ├── modules/
   │   ├── pqc-kms-signing/
   │   └── hybrid-pqc-alb/
   ├── policies/
   │   ├── discovery/
   │   ├── scoring/
   │   ├── hybrid/
   │   └── tests/
   ├── ingest/
   ├── reports/
   ├── evidence/
   ├── versions.tf
   └── .github/workflows/
       ├── pqc-compliance-gate.yml
       └── aws-live-pqc-validation.yml
   ```
3. **Phase 1 — stand up discovery:** validate the Terraform plan adapter, add schema-validated collectors for each authorized source, generate the policy CBOM, and record explicit coverage gaps. Confirm the report never equates unsupported sources with no assets.
4. **Phase 2 — layer in scoring:** write and unit-test the risk-scoring policy, run it against the Phase 1 inventory, cross-reference CMVP status, and produce the first Priority Matrix.
5. **Phase 3 — provision and validate PQC infrastructure:** author the pure ML-DSA `pqc-kms-signing` module and the hybrid key-establishment `hybrid-pqc-alb` module, test Terraform contracts with native mock providers, and run the isolated AWS lifecycle scripts to prove KMS sign/verify plus real ALB PQ-capable and classical-fallback TLS negotiation.
6. **Phase 4 — close the loop with continuous evidence:** deploy `pqc-compliance-gate.yml`, confirm it produces a synthetic-test evidence ZIP on a test PR, and verify that a protected `main` push attests the exact ZIP. Configure immutable S3 retention separately when required.
7. **First environment assessment:** collect an authorized Terraform plan, run the inventory collector `scripts/run-census.sh` with environment scope, validate the normalized inventory, run policy/scanner checks, and preserve the resulting evidence. Do not substitute the PR's generated test plan for this assessment.
8. **Ongoing operation:** every PR revalidates framework behavior. Environment collectors, quarterly reports, and CMVP status comparison require separately scheduled, tested operational processes as those collectors are implemented.

---

## Standards & References

- NIST, [NIST Releases First 3 Finalized Post-Quantum Encryption Standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards), August 2024
- NIST CSRC, [FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final)
- NIST CSRC, [CMVP Modules in Process List](https://csrc.nist.gov/projects/cryptographic-module-validation-program/modules-in-process/modules-in-process-list)
- PostQuantum.com, [NIST Selects 9 Third-Round PQC Signature Candidates](https://postquantum.com/security-pqc/nist-third-round-pqc-signatures/) — FIPS 206 (FN-DSA) status
- DigiCert, [Quantum-Ready FN-DSA (FIPS 206) Nears Draft Approval from NIST](https://www.digicert.com/blog/quantum-ready-fndsa-nears-draft-approval-from-nist)
- NSA, [Announcing the Commercial National Security Algorithm Suite 2.0](https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF)
- SafeLogic, [CNSA 2.0 Compliance Requirements, Algorithms & Timelines](https://www.safelogic.com/compliance/cnsa-2)
- White House, [Executive Order 14412 — Securing the Nation Against Advanced Cryptographic Attacks](https://www.whitehouse.gov/presidential-actions/2026/06/securing-the-nation-against-advanced-cryptographic-attacks/), June 22, 2026
- CIQ, [Preparing Your Infrastructure for Post-Quantum Cryptography](https://ciq.com/blog/preparing-your-infrastructure-for-post-quantum-cryptography) — CMVP validation-lag evidence
- AWS, [Post-Quantum Cryptography at AWS](https://aws.amazon.com/security/post-quantum-cryptography/)
- AWS Security Blog, [How to Create Post-Quantum Signatures Using AWS KMS and ML-DSA](https://aws.amazon.com/blogs/security/how-to-create-post-quantum-signatures-using-aws-kms-and-ml-dsa/), June 13, 2025
- AWS KMS Developer Guide, [ML-DSA Keys in AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html)
- AWS Documentation, [Security Policies for Your Application Load Balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html) — `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09` hybrid PQ-TLS policy
- AWS News, [ML-KEM Post-Quantum TLS Now Supported in AWS KMS, ACM, and Secrets Manager](https://aws-news.com/article/2025-04-07-ml-kem-post-quantum-tls-now-supported-in-aws-kms-acm-and-secrets-manager)
- Terraform Registry, [`aws_kms_key` Resource Documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) — `ML_DSA_44`/`ML_DSA_65`/`ML_DSA_87` key spec support
- NIST SP 800-227, *Recommendations for Key-Encapsulation Mechanisms* (analysis on file from prior session work)
- GitHub repositories cited throughout Part 2 (see table for direct links)

---

*This document supersedes and expands the original 4-phase outline. The technical backbone — Rego/OPA policy authoring, Terraform+Conftest plan gating, and CI/CD evidence pipelines — remains the same discipline used across mature GRC engineering practice, now fully specified with installable tooling, working code, and a bare-metal build sequence.*
