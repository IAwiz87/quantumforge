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
   - Affected file(s)/module(s) (e.g. `modules/hybrid-pqc-kms`, a specific `.rego` policy, a workflow file)
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

- Terraform modules in `modules/` (`hybrid-pqc-kms`, `hybrid-pqc-alb`) and the root module — misconfigurations that could provision weaker-than-intended cryptography, overly permissive IAM, or insecure defaults
- Rego policies in `policies/` (`discovery`, `scoring`, `hybrid`) — logic errors that would allow a `deny` rule to be bypassed, misclassify an asset, or under-score real risk
- GitHub Actions workflows in `.github/workflows/` — supply-chain issues (e.g. unpinned actions, script injection via untrusted PR input), secret handling, or OIDC role-assumption misconfigurations
- The Conftest compliance gate and its mock-plan fixtures in `examples/sandbox/`

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

- **No static AWS credentials.** CI workflows are wired for OIDC federation (`aws-actions/configure-aws-credentials` with a role ARN via the `QUANTUMFORGE_EVIDENCE_ROLE_ARN` secret) rather than long-lived access keys. The credential step is commented out until a real least-privilege role is supplied — it will not silently run with no credentials configured.
- **Fail-safe policy default.** `policies/hybrid/combiner.rego` defaults `enforce_cutover` to `true`, meaning ambiguous or missing configuration blocks non-compliant crypto by default rather than allowing it through.
- **Asymmetric KMS keys cannot auto-rotate.** `hybrid-pqc-kms` intentionally sets `enable_key_rotation = false` because AWS KMS does not support automatic rotation for `SIGN_VERIFY` asymmetric keys — this is a platform constraint, not an oversight, and rotation must be handled operationally (re-key + policy cutover).
- **Mock plan fixtures are synthetic.** Everything under `examples/sandbox/` uses fictitious ARNs and account IDs for policy unit testing — they do not correspond to any real AWS account or resource.

## Using This Repo Securely

If you deploy QuantumForge's modules in your own environment:

- Review every `terraform plan` before `apply` — this repo does not apply changes on your behalf.
- Scope the CI role referenced by `QUANTUMFORGE_EVIDENCE_ROLE_ARN` to the minimum permissions needed for evidence collection, not broad account access.
- Do not commit `.tfstate`, `.tfvars` with real values, or any AWS credentials — `.gitignore` excludes common cases, but double-check before pushing forks or branches.
- Treat the `evidence/`, `ingest/`, and `reports/` directories as sensitive once populated by CI — they may contain infrastructure and compliance details you don't want public.

---

*Questions about this policy that aren't a vulnerability report? Open a regular [GitHub issue](https://github.com/IAwiz87/quantumforge/issues).*
