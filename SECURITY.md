# Security Policy


QuantumForge is a policy-as-code framework for post-quantum cryptography (PQC)
readiness. Because it provisions cryptographic infrastructure and gates
deployments on crypto-agility policy, security issues here can have outsized
impact — please report them responsibly.

## Supported Versions

QuantumForge does not yet cut tagged releases; `main` is the actively
maintained line and receives all security fixes.

| Branch | Supported |
|--------|-----------|
| `main` | ✅ |
| any fork / tag prior to a fix | ❌ |

Once the project starts tagging releases, this table will be updated to
reflect which versions receive backported fixes.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, use GitHub's private reporting flow:

1. Go to the [Security tab](https://github.com/IAwiz87/quantumforge/security) of this repository.
2. Click **"Report a vulnerability"** to open a private security advisory.
3. Include as much detail as you can:
   - Affected file(s)/module(s) (e.g. `modules/pqc-kms-signing`, a specific `.rego` policy, a workflow file)
   - Steps to reproduce, or a minimal Terraform/OPA example that demonstrates the issue
   - Impact assessment (what a successful exploit would let an attacker do)
   - Any suggested remediation, if you have one

You should expect an initial acknowledgment within **5 business days**. This
is a personal open-source project maintained outside of full-time work, so
fix timelines will vary with severity — critical issues (e.g. a policy gate
that can be bypassed, or a module that silently provisions non-compliant
crypto) will be prioritized over documentation or tooling nits.

If you believe an issue requires urgent, out-of-band attention, note that
clearly in the advisory description.

## Scope

**In scope:**

- Terraform modules in `modules/` (`pqc-kms-signing`, `hybrid-pqc-alb`) and the root module — misconfigurations that could provision weaker-than-intended cryptography, overly permissive IAM, or insecure defaults
- Rego policies in `policies/` (`discovery`, `scoring`, `hybrid`, `governance`, `inventory`) — logic errors that would allow a `deny` rule to be bypassed, misclassify an asset, accept an expired exception, or under-score real risk
- GitHub Actions workflows in `.github/workflows/` — supply-chain issues (e.g. unpinned actions, script injection via untrusted PR input), secret handling, or OpenID Connect (OIDC) role-assumption misconfigurations
- The Conftest compliance gate and its generated test plans in `examples/sandbox/`

**Out of scope:**

- Vulnerabilities in upstream tools this project depends on (Terraform, OPA, Conftest, the AWS provider, Trivy, Checkov) — please report those to the respective upstream projects
- AWS service-level vulnerabilities — report to AWS Security ([aws.amazon.com/security/vulnerability-reporting](https://aws.amazon.com/security/vulnerability-reporting/))
- Issues that require an attacker to already have `apply`-level AWS credentials or write access to this repository (that's the trust boundary this project assumes)
- Findings from automated scanners without a demonstrated, concrete impact in this codebase

## Disclosure Policy

This project follows coordinated disclosure:

- Please give a reasonable window to investigate and ship a fix before any public disclosure — 90 days is a good default, shorter for actively-exploited issues, longer if we're both waiting on an upstream fix.
- Credit will be given in the advisory and release notes unless you ask to remain anonymous.
- There is no bug bounty program; this is an independent project, not a funded product.

## Security Design Notes

For context when evaluating reports, some intentional design decisions:

- **No AWS credentials in pull requests.** The PR compliance workflow has only `contents: read` and does not receive OIDC authority. The separate live workflow is manual, restricted to `main`, protected by the `quantumforge-aws-sandbox` environment, and uses job-scoped GitHub OIDC rather than long-lived access keys. A second main-only environment, named `quantumforge-aws-sandbox-janitor`, runs the post-job and hourly expired-resource cleanup safety net without granting PR authority.
- **Fail-safe policy default.** `policies/hybrid/combiner.rego` defaults `enforce_cutover` to `true`, meaning ambiguous or missing configuration blocks non-compliant crypto by default rather than allowing it through.
- **Asymmetric KMS keys cannot auto-rotate.** `pqc-kms-signing` intentionally sets `enable_key_rotation = false` because AWS KMS does not support automatic rotation for `SIGN_VERIFY` asymmetric keys — this is a platform constraint, not an oversight, and rotation must be handled operationally (re-key + policy cutover).
- **Mock plans are generated test data.** Everything under `examples/sandbox/` uses fictitious ARNs and account IDs for policy unit testing. They do not correspond to any real AWS account or resource.

## Using This Repo Securely

If you deploy QuantumForge's modules in your own environment:

- Review every `terraform plan` before `apply` — this repo does not apply changes on your behalf.
- Scope the protected live workflow role referenced by `QUANTUMFORGE_AWS_ROLE_ARN` to the isolated sandbox. Apply the exact OIDC subject/audience boundary and least-privilege permissions templates under `docs/aws/`; do not grant the role to pull-request jobs or add Object Lock administration/deletion rights.
- Do not commit `.tfstate`, `.tfvars` with real values, or any AWS credentials — `.gitignore` excludes common cases, but double-check before pushing forks or branches.
- Treat the `evidence/`, `ingest/`, and `reports/` directories as sensitive once populated by CI — they may contain infrastructure and compliance details you don't want public.

---

*Questions about this policy that aren't a vulnerability report? Open a regular [GitHub issue](https://github.com/IAwiz87/quantumforge/issues).*
