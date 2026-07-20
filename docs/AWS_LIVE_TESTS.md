# Live AWS validation

Pull requests never need AWS credentials. Live tests run only from the manually triggered `aws-live-pqc-validation` workflow in the protected `quantumforge-aws-sandbox` environment. Tag-based cleanup also runs in the separately protected `quantumforge-aws-sandbox-janitor` environment after each test and hourly for expired fixtures.

## Safety controls

- `QUANTUMFORGE_ALLOW_LIVE_AWS_TESTS=1` is mandatory.
- `QUANTUMFORGE_EXPECTED_ACCOUNT_ID` must match `sts:GetCallerIdentity` or the scripts refuse to create resources.
- A workflow-level concurrency group prevents overlapping live test runs.
- Both scripts use cleanup traps. A successful test is changed to a failure if cleanup does not complete.
- An independent `if: always()` cleanup job finds the current run by tags, and `.github/workflows/aws-live-pqc-janitor.yml` removes expired fixtures hourly if a runner is lost or forcibly canceled.
- Resources are tagged with `project=quantumforge`, `environment=integration-test`, a run identifier, and an RFC3339 expiration one hour after creation.
- Terraform state and generated private keys remain in a temporary directory and are deleted at exit.
- The ALB fixture has no EC2 instances, NAT gateways, or registered targets.

## Repository configuration

Create `quantumforge-aws-sandbox` with approval protection for manual tests. Create `quantumforge-aws-sandbox-janitor` restricted to `main` without a delayed approval gate so scheduled cleanup cannot be blocked. Define the role and account as repository variables so both environments receive them:

| Variable | Required | Purpose |
|---|---:|---|
| `QUANTUMFORGE_AWS_ROLE_ARN` | yes | GitHub OIDC role in the isolated sandbox |
| `QUANTUMFORGE_AWS_ACCOUNT_ID` | yes | Account guardrail checked before every live run |
| `QUANTUMFORGE_EVIDENCE_BUCKET` | no | **Repository variable** naming an S3 Object Lock bucket with at least seven years of default retention; its presence enables the trusted-main publication job |

The OIDC trust policy must restrict `aud` to `sts.amazonaws.com` and `sub` to the two exact protected-environment subjects in `docs/aws/github-oidc-trust-policy.json`. Do not grant the role to forked or pull-request workflows.

Apply `docs/aws/live-validation-permissions-boundary.json` after substituting the sandbox account and region. Pre-provision the standard `AWSServiceRoleForElasticLoadBalancing` service-linked role in a fresh sandbox; the workflow role intentionally lacks `iam:CreateServiceLinkedRole`. If immutable publication is enabled, also substitute the dedicated evidence bucket; otherwise remove the three S3 allow statements while retaining the global explicit deny. Use the document as a permissions boundary as well as the reviewed role policy so later attachments cannot add broad AWS or Object Lock administration. The template exact-lists the KMS, ACM, VPC, security-group, ELBv2, tag-discovery, and immutable-evidence actions used by the fixtures and janitor, requires QuantumForge tags where the service exposes request/resource tag conditions, confines ELBv2 resources by name, and explicitly denies evidence deletion, retention bypass, bucket-policy changes, and Object Lock reconfiguration.

If immutable publication is enabled, grant only the evidence prefix in the selected bucket: `s3:GetBucketObjectLockConfiguration`, `s3:PutObject`, `s3:PutObjectRetention`, `s3:GetObject`, `s3:GetObjectVersion`, and `s3:GetObjectRetention`. The boundary requires `COMPLIANCE` mode and at least 2,555 remaining retention days whenever object retention is set. The workflow role must not be able to suspend Object Lock, shorten retention, alter bucket policy, or delete retained versions.

## Independent cleanup

`scripts/aws/cleanup-expired-live-resources.sh --run-id <run-id>` removes resources from one run without Terraform state. With no run ID it selects only expired QuantumForge integration-test tags. KMS keys are accepted only in `PendingDeletion`; all other selected resources must be absent before the script exits successfully. The hourly janitor caps ordinary ALB orphan cost to approximately one additional billed hour if both the primary trap and post-job cleanup are lost.

## KMS lifecycle

```bash
AWS_PROFILE=sandbox \
AWS_REGION=us-east-1 \
QUANTUMFORGE_ALLOW_LIVE_AWS_TESTS=1 \
QUANTUMFORGE_EXPECTED_ACCOUNT_ID=123456789012 \
./scripts/aws/kms-lifecycle-test.sh build/live-kms
```

The test:

1. Plans and applies `tests/live/kms` with AWS Provider 6.x.
2. Creates an `ML_DSA_65` `SIGN_VERIFY` key through `modules/pqc-kms-signing`.
3. Signs and verifies a payload through AWS KMS.
4. Retrieves the DER public key and independently verifies the signature with OpenSSL 3.5.7.
5. Destroys Terraform resources and requires the key to enter `PendingDeletion` with the minimum seven-day window.

AWS does not allow immediate KMS key deletion. Pending-deletion keys cannot be used, are deleted after the waiting period, and are not billed while pending deletion.

## ALB runtime negotiation

```bash
AWS_PROFILE=sandbox \
AWS_REGION=us-east-1 \
QUANTUMFORGE_ALLOW_LIVE_AWS_TESTS=1 \
QUANTUMFORGE_EXPECTED_ACCOUNT_ID=123456789012 \
./scripts/aws/alb-pqtls-lifecycle-test.sh build/live-alb
```

The test creates two public subnets, an internet-facing ALB, an empty target group, an imported one-day self-signed certificate, and the module's HTTPS listener. It then requires both of these TLS 1.3 handshakes:

- PQ-capable client: `X25519MLKEM768`
- Classical compatibility client: `X25519`

Successful resource creation alone does not pass the test. The negotiated groups must appear in the OpenSSL transcript. The listener is explicitly an **Application Load Balancer HTTPS listener**. Network Load Balancers use `protocol = "TLS"` and are outside this Terraform module's contract.

## Cost guardrail

At published `us-east-1` list prices, a KMS key costs $1/month prorated hourly, or roughly $0.0014 for one hour, plus negligible test API requests. It is unbilled after entering `PendingDeletion`. An ALB is billed for at least one full hour at $0.0225, plus LCU usage and public IPv4 charges (typically two addresses at $0.005 each per hour). A successful low-traffic test should ordinarily remain below **$0.05**, but AWS pricing can change. Keep the job timeout and account-level budget alert enabled.
