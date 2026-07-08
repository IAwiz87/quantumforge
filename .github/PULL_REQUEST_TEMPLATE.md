## Description

<!-- What does this PR change, and why? Link any related issue(s). -->

Fixes/Relates to #

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New Terraform module or module feature
- [ ] New or updated Rego policy
- [ ] CI/workflow change (`.github/workflows/`)
- [ ] Documentation only (README, Build Guide, comments)
- [ ] Breaking change (changes existing module inputs/outputs or policy behavior)
- [ ] Other:

## What Changed

<!-- Summarize the change. For policy or module changes, briefly explain the security
     reasoning — e.g. "restricts key spec to ML-DSA variants to prevent classical
     fallback" — not just what the diff does mechanically. -->

## Testing Performed

- [ ] `terraform fmt -check -recursive` — clean
- [ ] `terraform validate` — passes (list which module(s)/root: )
- [ ] `opa test policies/` — all tests pass
- [ ] `conftest test` against both mock plans — expected pass/deny results confirmed (if policy logic changed)
- [ ] New/changed workflow YAML parses cleanly
- [ ] Tested `terraform plan` against real AWS (optional — note if done, and against what)

<!-- Paste relevant command output below if useful, e.g. opa test summary or conftest results. -->

```
paste test output here
```

## Documentation

- [ ] README updated (module tables, Validation Status, etc.) if behavior/defaults changed
- [ ] Build Guide (`docs/PQC_Readiness_Program_Build_Guide.md`) updated if program design changed
- [ ] N/A — no user-facing behavior changed

## Checklist

- [ ] No AWS credentials, `.tfstate`, or real ARNs/account IDs are included in this PR
- [ ] New Rego rules have accompanying `_test.rego` cases (positive and negative)
- [ ] New Terraform variables have `validation` blocks where they constrain security-relevant inputs
- [ ] I have read [CONTRIBUTING.md](../CONTRIBUTING.md) and [SECURITY.md](../SECURITY.md)
