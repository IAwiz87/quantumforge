# Contributing to QuantumForge

Thanks for considering a contribution to QuantumForge. This is a
policy-as-code framework for post-quantum cryptography (PQC) readiness —
Terraform modules, OPA/Rego policies, and CI pipelines all need to stay
correct and testable, so this guide covers how changes are expected to be
made and verified.


By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).


## Ways to Contribute

- **Bug reports** — something in a module, policy, or workflow behaves incorrectly
- **Feature requests** — a new hybrid-PQC module, a new policy rule, a new CI check
- **Documentation** — README clarity, the [Build Guide](docs/PQC_Readiness_Program_Build_Guide.md), inline comments
- **New Terraform modules** — e.g. Azure Key Vault PQC support once it reaches GA (currently tracked as roadmap-only)
- **New/expanded Rego policies** — additional crypto-agility rules, better risk-scoring heuristics, new discovery classifiers

Please do **not** open a public issue for a security vulnerability — see [SECURITY.md](SECURITY.md) for the private reporting process instead.

## Development Setup

You'll need:

- [Terraform](https://developer.hashicorp.com/terraform/downloads) (validated against the version pinned in `versions.tf`)
- [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa) for Rego unit tests
- [Conftest](https://www.conftest.dev/install/) for the compliance-gate tests against mock Terraform plans
- Optionally, an AWS account with credentials configured if you want to exercise `terraform plan` against real infrastructure (not required for policy/module development — `terraform validate` and `opa test` don't need AWS credentials)

```bash
git clone https://github.com/IAwiz87/quantumforge.git
cd quantumforge
terraform init
terraform validate
opa test policies/ -v
```

## Project Structure

```
quantumforge/
├── main.tf, variables.tf, outputs.tf, versions.tf   # root module
├── modules/
│   ├── hybrid-pqc-kms/     # AWS KMS asymmetric signing keys (ML-DSA)
│   └── hybrid-pqc-alb/     # ALB listener enforcing hybrid PQ-TLS
├── policies/
│   ├── discovery/          # package quantumforge.discovery — crypto asset classification
│   ├── scoring/            # package quantumforge.scoring — HNDL risk scoring
│   └── hybrid/             # package main — Conftest compliance gate
├── examples/sandbox/       # mock Terraform plan JSON fixtures for policy testing
├── .github/workflows/      # census, compliance-gate, cmvp-monitor
└── docs/                   # companion Build Guide + banner
```

## Making Changes

### Terraform (modules or root)

- Run `terraform fmt -recursive` before committing — CI checks formatting.
- Run `terraform validate` in both the changed module directory and the root.
- If you add a new variable, add a `validation` block where it constrains something security-relevant (e.g. restrict a KMS key spec to approved PQC algorithms, the way `hybrid-pqc-kms` and `hybrid-pqc-alb` already do) — don't rely on documentation alone to prevent misconfiguration.
- Update the README's module tables and the Validation Status section if behavior or defaults change.

### Rego Policies

- Every package uses `import rego.v1` — keep this in any new `.rego` file so it behaves consistently whether run under standalone `opa` or under Conftest's embedded OPA version.
- Every new or changed rule needs an accompanying `_test.rego` file with both a positive and negative test case (i.e., a case where the rule should fire and one where it shouldn't).
- Run `opa test policies/<package>/ -v` and confirm all tests pass before opening a PR.
- If you touch `policies/hybrid/combiner.rego`, also run Conftest against both mock plans in `examples/sandbox/` to confirm the gate still denies classical-only crypto and passes hybrid-PQC configs:
  ```bash
  conftest test examples/sandbox/mock-plan-classical-fail.json -p policies/hybrid   # expect failures
  conftest test examples/sandbox/mock-plan-hybrid-pass.json -p policies/hybrid      # expect pass
  ```

### GitHub Actions Workflows

- Validate YAML syntax before committing (e.g. `python -c "import yaml; yaml.safe_load(open('.github/workflows/<file>.yml'))"`).
- Do not add steps that require static AWS credentials — this project uses OIDC federation exclusively (see `SECURITY.md`).
- Pin third-party actions to a specific version or SHA where practical.

## Testing Checklist

Before opening a PR, confirm locally:

- [ ] `terraform fmt -check -recursive` is clean
- [ ] `terraform validate` passes for every module you touched, plus the root
- [ ] `opa test policies/` passes with no failures
- [ ] `conftest test` still produces the expected pass/deny results against both mock plans (if you touched policy logic)
- [ ] Any new workflow YAML parses cleanly
- [ ] README / Build Guide updated if you changed behavior, defaults, or added a module/policy

## Commit Messages

Keep commit messages short and descriptive of *what changed and why* — e.g. `Add SLH-DSA support to hybrid-pqc-kms key spec validation` rather than `update module`. Conventional Commits prefixes (`feat:`, `fix:`, `docs:`, `chore:`) are welcome but not required.

## Submitting a Pull Request

1. Fork the repo and create a branch off `main` (`git checkout -b feature/short-description`).
2. Make your changes, following the guidance above.
3. Fill out the PR template completely, including the testing checklist.
4. Open the PR against `main`. CI (crypto census + compliance gate) will run automatically.
5. Respond to review feedback — for policy or module changes, be ready to explain the security reasoning behind the change, not just that it "works."

## License

By contributing, you agree that your contributions will be licensed under this project's [MIT License](LICENSE).
