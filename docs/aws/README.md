# AWS live-workflow role boundary

These JSON documents are deployment templates for the protected GitHub Actions role. They contain placeholders and are not applied automatically by this repository.

1. Replace `${AWS_ACCOUNT_ID}` and `${AWS_REGION}` with the isolated sandbox values.
2. Apply `github-oidc-trust-policy.json` as the role trust policy. Keep the exact GitHub `aud` and both environment-scoped `sub` values; do not replace them with wildcards or a pull-request subject.
3. Replace `${EVIDENCE_BUCKET}` only when immutable publication is enabled. Otherwise remove the three S3 `Allow` statements and retain the global S3 `Deny` statement.
4. Apply `live-validation-permissions-boundary.json` both as the role policy and as its permissions boundary. Keep approval on the manual live-test environment. Keep the main-only cleanup environment, named `quantumforge-aws-sandbox-janitor`, automatic so expired-resource cleanup is never queued behind approval. Retain the account-ID runtime guard in both.
5. Validate the rendered policies with IAM Access Analyzer before deployment, then exercise KMS and ALB cleanup in the sandbox.

Example validation:

```bash
aws accessanalyzer validate-policy \
  --policy-type IDENTITY_POLICY \
  --policy-document file://rendered-permissions.json

aws accessanalyzer validate-policy \
  --policy-type RESOURCE_POLICY \
  --validate-policy-resource-type AWS::IAM::AssumeRolePolicyDocument \
  --policy-document file://rendered-trust.json
```

IAM Access Analyzer may recommend a branch-form GitHub subject because it does not fully model environment-form subjects. The environment subject in this template is intentionally exact and follows GitHub's documented OIDC subject format. Treat any `ERROR` or other unexpected warning as a blocker.

The boundary deliberately excludes credential creation, IAM administration, broad KMS wildcards, S3 deletion, Object Lock reconfiguration, and retention bypass. If a provider upgrade requires another API action, add that exact action only after reviewing CloudTrail evidence from the isolated sandbox.
