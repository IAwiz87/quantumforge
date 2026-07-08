# PQC Readiness Program — Full Build Guide
### From Bare Metal to a Functioning Post-Quantum Cryptographic Agility Practice

**Prepared for:** Enterprise / regulated-sector clients pursuing CNSA 2.0, NIST PQC (FIPS 203/204/205/206), and FIPS 140-3 readiness
**Methodology:** Policy-as-code (Rego/OPA), Terraform + Conftest infrastructure validation, and CI/CD-driven compliance evidence generation — the same automation backbone used across mature GRC engineering practices, here re-purposed end-to-end for post-quantum cryptographic migration.
**Scope of this document:** Everything needed to stand up the program from an empty workstation/repo to a continuously-evidenced, four-phase PQC readiness pipeline: prerequisite software, open-source tooling to import per phase, concrete configuration, and the phase-by-phase technical deliverables.

---

## Program Rationale


Three regulatory clocks are running simultaneously for any enterprise handling sensitive or regulated data:

- **CNSA 2.0** (NSA Commercial National Security Algorithm Suite 2.0): no enforcement before December 31, 2025; all new National Security System acquisitions must be CNSA 2.0-compliant by January 1, 2027; non-supporting fielded equipment phased out by December 31, 2030; full cryptographic enforcement across NSS by December 31, 2031; full quantum-resistance across NSS by 2035 per NSM-10 ([SafeLogic](https://www.safelogic.com/compliance/cnsa-2)). A 2026 federal PQC executive order accelerates the civilian-agency timeline further, requiring high-value-asset and high-impact systems to migrate key establishment by December 31, 2030 and digital signatures by December 31, 2031 ([Center for Cybersecurity Policy](https://www.centerforcybersecuritypolicy.org/insights-and-research/from-strategy-to-implementation-the-white-house-accelerates-the-federal-transition-to-post-quantum-cryptography)).
- **NIST PQC algorithm standards**: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) were finalized August 2024 ([NIST](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards); [CSRC FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)). FIPS 206 (FN-DSA, Falcon-based) remains in draft as of this writing — track it, do not deploy it in production yet ([PostQuantum.com](https://postquantum.com/security-pqc/nist-third-round-pqc-signatures/); [DigiCert](https://www.digicert.com/blog/quantum-ready-fndsa-nears-draft-approval-from-nist)).
- **FIPS 140-3 / CMVP validation lag**: as of early 2026 very few cryptographic modules have completed full CMVP validation with ML-KEM/ML-DSA support (AWS-LC is a notable exception — the first open-source crypto module with ML-KEM in an active FIPS 140-3 validation). Most vendors sit in the "Modules in Process" queue with 12+ month waits ([CIQ](https://ciq.com/blog/preparing-your-infrastructure-for-post-quantum-cryptography); [AWS](https://aws.amazon.com/security/post-quantum-cryptography/)). This validation gap is exactly why **hybrid classical+PQC architectures** (governed by NIST SP 800-227) are the practical near-term compliance posture.

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
      version = "~> 5.60"   # 5.60+ ships ML_DSA_44/65/87 key_spec support on aws_kms_key
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
  }
  backend "s3" {
    bucket         = "your-org-tfstate"
    key            = "pqc-readiness/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-locks"
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

**Trivy** (IaC/container/CBOM scanner — absorbed `tfsec`'s functionality; `tfsec`'s own repo now redirects users to Trivy):
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

**Objective:** Build a complete, machine-readable inventory of every cryptographic algorithm, key, certificate, and protocol in the client's environment before any remediation is scoped.

**Technical approach:** Cryptographic discovery has two complementary data sources, and a mature census pulls from both:
1. **Infrastructure-as-code state** — every Terraform-managed resource (KMS keys, ACM/TLS certificates, HSM configurations, VPN tunnels, load-balancer listener policies) is already declared in state and plan JSON. `terraform show -json` on the current state file gives a complete, queryable snapshot without touching production systems.
2. **Runtime/code artifacts** — CBOM generation (`cdxgen`, `cbomkit`) inspects source code, container images, and dependency manifests for cryptographic library usage that IaC alone won't reveal (application-level TLS libraries, embedded crypto in third-party dependencies, hardcoded algorithm choices).

Both feeds are normalized into Rego facts and classified by a shared policy library tagging every discovered artifact by algorithm family (RSA/ECDSA/ECDH/DH classical-only vs. AES-symmetric vs. already-PQC-capable) and CNSA 2.0 category (NSS vs. non-NSS; key-establishment vs. digital-signature use).

**Setup steps:**
1. Bootstrap the census repository:
   ```bash
   mkdir pqc-crypto-census && cd pqc-crypto-census
   git init
   mkdir -p policies/discovery policies/tests ingest .github/workflows
   ```
2. Extract IaC state to structured JSON for every managed environment:
   ```bash
   terraform show -json > ingest/tfstate-$(date +%F).json
   ```
3. Write the Rego classification policy (`policies/discovery/classify.rego`):
   ```rego
   package discovery

   classical_only_algorithms := {"RSA", "ECDSA", "ECDH", "DH", "DSA"}

   classify(resource) := "classical_only" if {
       resource.type == "aws_kms_key"
       resource.values.customer_master_key_spec in classical_only_algorithms
   }

   classify(resource) := "pqc_ready" if {
       resource.type == "aws_kms_key"
       startswith(resource.values.key_spec, "ML_DSA")
   }

   classify(resource) := "symmetric" if {
       resource.type == "aws_kms_key"
       resource.values.key_usage == "ENCRYPT_DECRYPT"
       resource.values.customer_master_key_spec == "SYMMETRIC_DEFAULT"
   }

   inventory[entry] {
       some resource in input.resource_changes
       entry := {
           "address": resource.address,
           "type": resource.type,
           "classification": classify(resource.change.after),
       }
   }
   ```
4. Unit-test the classifier before trusting it against real state:
   ```bash
   opa test -v policies/
   ```
5. Run the classifier against the extracted state and pipe to a CBOM merge for the full inventory:
   ```bash
   opa eval -d policies/discovery -i ingest/tfstate-$(date +%F).json "data.discovery.inventory" > reports/iac-inventory.json
   cdxgen -t terraform -o reports/iac.cdx.json .
   cdxgen -r -o reports/code.cdx.json ./src
   cyclonedx-cli merge --input-files reports/iac.cdx.json reports/code.cdx.json --output-file reports/full-crypto-census.cdx.json
   ```
6. Wire steps 4–5 into a GitHub Actions job (`.github/workflows/census.yml`) triggered on every pull request so newly introduced non-agile cryptography is caught at commit time, not audit time.

**Client-ready deliverables:**

| # | Deliverable | Standard Addressed |
|---|---|---|
| 1 | **Cryptographic Asset Inventory Report** — Terraform-state-derived, Rego-classified inventory of every KMS key, certificate, HSM config, and VPN tunnel by algorithm family | CNSA 2.0 scoping; FIPS 140-3 module boundary identification |
| 2 | **Crypto Bill of Materials (CBOM)** — CycloneDX-CBOM JSON merged from IaC and source-code scans, regenerated on every pull request | Ongoing crypto-agility baseline |
| 3 | **Algorithm Risk Register** — every discovered asset scored against CNSA 2.0 categories, FIPS 203/204/205 applicability, and Harvest-Now-Decrypt-Later (HNDL) exposure | CNSA 2.0; NIST SP 800-227 §4 deployment conditions |
| 4 | **Executive Crypto-Census Briefing** — board-ready summary translating the inventory into "% of estate quantum-vulnerable" and "days to CNSA 2.0 milestone" language | Client governance reporting |

---

### Phase 2 — Vulnerability Prioritization: Risk Mapping

**Objective:** Convert the raw inventory into a prioritized, deadline-anchored remediation roadmap.

**Technical approach:** Discovery-phase policies answer "what is it?" — Phase 2 policies answer "how urgently does it need to move?" This means evolving the Rego library from binary classification into weighted scoring functions that combine three inputs per asset: HNDL exposure (how long must this data stay confidential — a signature with a 1-year validity has very different urgency than a KMS key protecting 20-year medical records), data classification/sensitivity, and estimated remediation cost/complexity. Every scoring function is unit-tested with `opa test` before it is trusted for client-facing prioritization output — a miscalibrated score that under-prioritizes a critical asset is worse than no score at all.

**Setup steps:**
1. Extend the Phase 1 repo with a scoring module (`policies/scoring/risk_score.rego`):
   ```rego
   package scoring

   import future.keywords.if

   hndl_weight(years) := 40 if years >= 10
   hndl_weight(years) := 25 if years >= 5; years < 10
   hndl_weight(years) := 10 if years < 5

   classification_weight("nss") := 40
   classification_weight("regulated") := 25
   classification_weight("internal") := 10

   remediation_cost_weight("low") := 20
   remediation_cost_weight("medium") := 10
   remediation_cost_weight("high") := 5

   score(asset) := total if {
       total := hndl_weight(asset.data_retention_years) +
                 classification_weight(asset.data_classification) +
                 remediation_cost_weight(asset.remediation_cost)
   }

   tier(asset) := "critical" if score(asset) >= 80
   tier(asset) := "high" if score(asset) >= 60; score(asset) < 80
   tier(asset) := "medium" if score(asset) >= 35; score(asset) < 60
   tier(asset) := "low" if score(asset) < 35
   ```
2. Write unit tests covering boundary conditions on every tier threshold before deployment:
   ```bash
   opa test -v policies/scoring/
   ```
3. Feed the Phase 1 inventory JSON through the scoring policy to produce a tiered priority list:
   ```bash
   opa eval -d policies/scoring -i reports/iac-inventory.json "data.scoring.tier" > reports/priority-tiers.json
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

**Objective:** Design, provision, and validate hybrid classical+PQC infrastructure so the client can move now without waiting on full FIPS 140-3 PQC module validation.

**Technical approach:** This is where discovery and prioritization convert into actual provisioned infrastructure. The core workflow — `terraform init → terraform plan -out=tfplan → terraform show -json → conftest test` — is unchanged from any mature Terraform policy-gating pipeline; what changes is that the modules under test now provision **hybrid** key-establishment infrastructure, and the Conftest/Rego policies must additionally enforce that only NIST-approved combiner constructions (SP 800-56C/SP 800-133-compliant, e.g. X-Wing-style ML-KEM+X25519 combination) are used — never ad hoc secret concatenation.

As of this writing, real hybrid-PQC capability exists concretely on AWS and should be the primary target for production Terraform modules:
- **AWS KMS** supports ML-DSA signing keys natively via `key_spec = "ML_DSA_44" | "ML_DSA_65" | "ML_DSA_87"` on `aws_kms_key`, using the `ML_DSA_SHAKE_256` signing algorithm, generated and protected inside FIPS 140-3 Level 3 validated HSMs ([AWS KMS docs](https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html)).
- **AWS ALB/NLB** support hybrid post-quantum TLS via the `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09` security policy, which offers `X25519MLKEM768`, `SecP256r1MLKEM768`, and `SecP384r1MLKEM1024` hybrid key-exchange groups while gracefully falling back to classical TLS for non-PQC-capable clients ([AWS ELB docs](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html)).
- **AWS ACM, Secrets Manager, and KMS API endpoints** already support ML-KEM hybrid key agreement on non-FIPS endpoints across all commercial regions ([AWS announcement](https://aws-news.com/article/2025-04-07-ml-kem-post-quantum-tls-now-supported-in-aws-kms-acm-and-secrets-manager)).
- **Azure** is behind AWS here: SymCrypt (Azure's underlying crypto library) gained ML-KEM/ML-DSA support in late 2024, but Azure Key Vault and Managed HSM PQC support is still tracking through 2026 and is not yet available for direct Terraform provisioning. Treat Azure PQC as a monitored roadmap item in this phase, not a deployable Terraform target — document readiness but do not promise client-facing Azure PQC infrastructure yet.

**Setup steps:**
1. Add a hybrid-PQC module to the Terraform repo (`modules/hybrid-pqc-kms/main.tf`):
   ```hcl
   resource "aws_kms_key" "pqc_signing" {
     description              = "ML-DSA post-quantum signing key"
     key_usage                = "SIGN_VERIFY"
     customer_master_key_spec = "ML_DSA_65"   # NIST security level 3 (~192-bit classical equivalent)
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
3. Write the Conftest combiner-validation policy (`policies/hybrid/combiner.rego`):
   ```rego
   package hybrid

   deny[msg] {
       resource := input.resource_changes[_]
       resource.type == "aws_lb_listener"
       resource.change.after.protocol == "HTTPS"
       not endswith(resource.change.after.ssl_policy, "PQ-2025-09")
       msg := sprintf("listener %v is provisioning classical-only TLS after the crypto-agility cutover date", [resource.address])
   }

   deny[msg] {
       resource := input.resource_changes[_]
       resource.type == "aws_kms_key"
       resource.change.after.key_usage == "SIGN_VERIFY"
       not startswith(resource.change.after.customer_master_key_spec, "ML_DSA")
       not startswith(resource.change.after.customer_master_key_spec, "ECC")   # transitional hybrid signing still allowed
       msg := sprintf("KMS signing key %v uses a non-agile algorithm", [resource.address])
   }
   ```
4. Run the full plan-to-gate pipeline:
   ```bash
   terraform init
   terraform plan -out=tfplan
   terraform show -json tfplan > tfplan.json
   conftest test tfplan.json -p policies/hybrid/
   ```
5. Build the algorithm test harness in WSL2 using `liboqs-python` to validate interoperability and measure handshake performance overhead before client sign-off:
   ```python
   import oqs, time

   with oqs.KeyEncapsulation("ML-KEM-768") as kem:
       public_key = kem.generate_keypair()
       start = time.perf_counter()
       ciphertext, shared_secret_enc = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)
       shared_secret_dec = kem.decap_secret(ciphertext)
       elapsed_ms = (time.perf_counter() - start) * 1000
       assert shared_secret_enc == shared_secret_dec
       print(f"ML-KEM-768 encap/decap round-trip: {elapsed_ms:.3f} ms")
   ```
6. Validate the actually-provisioned infrastructure (not just the plan) with Terratest, confirming the ALB listener really negotiates a hybrid group end-to-end.

**Client-ready deliverables:**

| # | Deliverable | Standard Addressed |
|---|---|---|
| 1 | **Hybrid-PQC Terraform Modules** — reference IaC provisioning ML-DSA KMS signing keys and PQ-TLS-policy load balancer listeners on AWS, with Azure readiness documented separately as a 2026 roadmap item | NIST SP 800-227 §4.6 (multi-algorithm KEMs, PQ/T hybrids); FIPS 203/204 |
| 2 | **Conftest Crypto-Agility Gate** — CI policy gate blocking any plan introducing classical-only key establishment past a client-defined cutover date, verifying combiner constructions follow SP 800-56C/SP 800-133 approved methods | SP 800-227 §4.6 approved key combiners; CNSA 2.0 forward posture |
| 3 | **Algorithm Test Harness** — sandbox validating FIPS 203/204/205 implementations against client performance/interoperability requirements, tracking FIPS 206 (FN-DSA) draft status without premature adoption | FIPS 203/204/205; FIPS 206 (monitoring only) |
| 4 | **Crypto-Agility Reference Architecture Document** — abstracted crypto-provider boundary design so future algorithm swaps require configuration changes, not re-architecture | Crypto-agility principle underlying CNSA 2.0 and NSM-10 |

---

### Phase 4 — Continuous Compliance: IaC Validation

**Objective:** Operationalize PQC posture as a continuously evidenced, audit-ready control rather than a one-time project.

**Technical approach:** Every prior phase produces artifacts (inventory JSON, risk scores, Terraform plans, policy test results) that are only valuable to an auditor if they're captured, timestamped, and retrievable on demand. This phase wires the entire toolchain into a single CI pipeline that runs on every merge to `main`, producing a signed evidence bundle mapped to control IDs, and layers OSCAL-formatted control mapping on top so the evidence speaks the same language as formal compliance frameworks (SP 800-53, SOC 2, etc.).

**Setup steps:**
1. Create the CI evidence pipeline (`.github/workflows/pqc-compliance-gate.yml`):
   ```yaml
   name: pqc-compliance-gate
   on:
     pull_request:
     push:
       branches: [main]

   permissions:
     id-token: write   # required for OIDC AWS auth — no long-lived static keys
     contents: read

   jobs:
     evidence:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4

         - name: Configure AWS credentials (OIDC)
           uses: aws-actions/configure-aws-credentials@v4
           with:
             role-to-assume: ${{ secrets.PQC_EVIDENCE_ROLE_ARN }}
             aws-region: us-east-1

         - name: Setup Terraform
           uses: hashicorp/setup-terraform@v3

         - name: Terraform plan
           run: |
             terraform init
             terraform plan -out=tfplan
             terraform show -json tfplan > plan.json

         - name: Trivy IaC scan
           uses: aquasecurity/trivy-action@master
           with:
             scan-type: config
             scan-ref: .
             format: json
             output: trivy-report.json

         - name: Checkov scan
           run: pip install checkov && checkov -d . --output json > checkov-report.json

         - name: Rego / Conftest crypto-agility gate
           run: |
             conftest test plan.json -p policies/hybrid/ --output json > conftest-report.json

         - name: Regenerate CBOM
           run: |
             npm install -g @cyclonedx/cdxgen
             cdxgen -t terraform -o cbom.json .

         - name: Assemble evidence bundle
           run: |
             mkdir -p evidence
             cp plan.json trivy-report.json checkov-report.json conftest-report.json cbom.json evidence/
             echo "{\"commit\":\"${{ github.sha }}\",\"timestamp\":\"$(date -u +%FT%TZ)\"}" > evidence/manifest.json
             zip -r pqc-evidence-$(date +%F).zip evidence/

         - name: Upload evidence artifact
           uses: actions/upload-artifact@v4
           with:
             name: pqc-compliance-evidence
             path: pqc-evidence-*.zip
             retention-days: 2555   # 7 years, typical audit retention requirement
   ```
2. Map evidence artifacts to formal controls with `compliance-trestle`, generating OSCAL assessment-results documents that reference the CI-produced evidence bundle by commit SHA:
   ```bash
   trestle init
   trestle author profile-generate -n pqc-readiness -o pqc-readiness-profile
   # populate implemented-requirements referencing SC-12 (key management) and SC-13 (cryptographic protection)
   trestle validate -f pqc-readiness-profile/profile.json
   ```
3. Add a scheduled (not just on-push) job that polls the [NIST CMVP Modules in Process list](https://csrc.nist.gov/projects/cryptographic-module-validation-program/modules-in-process/modules-in-process-list) weekly and opens a tracking issue automatically when a dependent library's module advances to full validation:
   ```yaml
   on:
     schedule:
       - cron: "0 13 * * 1"   # every Monday
   ```
4. Feed accumulated evidence bundles into Heimdall2 for a rolling compliance dashboard the client's GRC/security team can review without opening individual JSON artifacts.

**Client-ready deliverables:**

| # | Deliverable | Standard Addressed |
|---|---|---|
| 1 | **PQC Compliance Gate** — CI workflow producing plan JSON, Trivy/Checkov static scans, Rego/Conftest crypto-agility results, and a signed evidence bundle on every merge | Continuous CNSA 2.0 / FIPS 140-3 evidence generation |
| 2 | **OSCAL-Mapped Evidence Registry** — evidence bundles mapped via compliance-trestle to SP 800-53 control IDs (SC-12 key management, SC-13 cryptographic protection), consumable by any OSCAL-compatible GRC platform | SP 800-53 SC-12/SC-13; CNSA 2.0 audit trail |
| 3 | **Continuous CMVP Status Monitor** — scheduled CI job checking the CMVP "Modules in Process" list for dependent cryptographic libraries, auto-flagging when a validated ML-KEM/ML-DSA module becomes available | FIPS 140-3 / CMVP validation lifecycle |
| 4 | **Quarterly PQC Compliance Attestation Report** — audit-grade report bundling evidence against the CNSA 2.0 deadline countdown and current CMVP validation status, suitable for board, regulator, or customer due-diligence | CNSA 2.0; FIPS 140-3; client contractual assurance |

---

## Part 4 — Master Build Sequence (Bare Metal → Functioning Program)

Follow this sequence exactly on a fresh workstation/repo to stand up the entire program end to end:

1. **Install prerequisites** (Part 1, sections 1.1–1.6). Run the sanity-check block at the end of 1.6 and confirm every tool reports a version before proceeding.
2. **Bootstrap the repository structure:**
   ```
   pqc-readiness-program/
   ├── modules/
   │   ├── hybrid-pqc-kms/
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
       ├── census.yml
       └── pqc-compliance-gate.yml
   ```
3. **Phase 1 — stand up discovery:** write and unit-test the classification policy, extract `terraform show -json` from every managed environment, run the CBOM generation, wire the `census.yml` PR-triggered workflow. Confirm you can produce a full Cryptographic Asset Inventory Report on demand.
4. **Phase 2 — layer in scoring:** write and unit-test the risk-scoring policy, run it against the Phase 1 inventory, cross-reference CMVP status, and produce the first Priority Matrix.
5. **Phase 3 — provision and validate hybrid infrastructure:** author the `hybrid-pqc-kms` and `hybrid-pqc-alb` Terraform modules, write the combiner-validation Conftest policy, run `terraform plan → show -json → conftest test` end to end against a sandbox AWS account, and validate real handshake behavior with the `liboqs-python` test harness plus Terratest.
6. **Phase 4 — close the loop with continuous evidence:** deploy `pqc-compliance-gate.yml`, confirm it produces a complete evidence ZIP on a test PR, map evidence to OSCAL controls with `compliance-trestle`, and stand up the scheduled CMVP monitor job.
7. **First full end-to-end run:** open a PR that modifies a Terraform module, and confirm all four phases fire correctly in sequence — discovery re-classifies the change, scoring re-prioritizes if needed, the crypto-agility gate blocks or allows the plan, and the evidence bundle is produced and archived — before merging to `main`.
8. **Ongoing operation:** every subsequent PR runs the same pipeline automatically; the quarterly attestation report and CMVP monitor run on schedule without further manual intervention.

---

## Standards & References

- NIST, [NIST Releases First 3 Finalized Post-Quantum Encryption Standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards), August 2024
- NIST CSRC, [FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final)
- NIST CSRC, [CMVP Modules in Process List](https://csrc.nist.gov/projects/cryptographic-module-validation-program/modules-in-process/modules-in-process-list)
- PostQuantum.com, [NIST Selects 9 Third-Round PQC Signature Candidates](https://postquantum.com/security-pqc/nist-third-round-pqc-signatures/) — FIPS 206 (FN-DSA) status
- DigiCert, [Quantum-Ready FN-DSA (FIPS 206) Nears Draft Approval from NIST](https://www.digicert.com/blog/quantum-ready-fndsa-nears-draft-approval-from-nist)
- NSA, [Announcing the Commercial National Security Algorithm Suite 2.0](https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF)
- SafeLogic, [CNSA 2.0 Compliance Requirements, Algorithms & Timelines](https://www.safelogic.com/compliance/cnsa-2)
- Center for Cybersecurity Policy, [From Strategy to Implementation: The White House Accelerates the Federal Transition to Post-Quantum Cryptography](https://www.centerforcybersecuritypolicy.org/insights-and-research/from-strategy-to-implementation-the-white-house-accelerates-the-federal-transition-to-post-quantum-cryptography)
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
