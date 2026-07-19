# Live AWS validation

Pull requests never need AWS credentials. Live tests run only from the manually triggered `aws-live-pqc-validation` workflow in the protected `quantumforge-aws-sandbox` environment.

## Safety controls

- `QUANTUMFORGE_ALLOW_LIVE_AWS_TESTS=1` is mandatory.
- `QUANTUMFORGE_EXPECTED_ACCOUNT_ID` must match `sts:GetCallerIdentity` or the scripts refuse to create resources.
- A workflow-level concurrency group prevents overlapping live test runs.
- Both scripts use cleanup traps. A successful test is changed to a failure if cleanup does not complete.
- Resources are tagged with `project=quantumforge`, `environment=integration-test`, a run identifier, and an automatic-cleanup marker.
- Terraform state and generated private keys remain in a temporary directory and are deleted at exit.
- The ALB fixture has no EC2 instances, NAT gateways, or registered targets.

## Repository configuration

Create a GitHub environment named `quantumforge-aws-sandbox` with approval protection, then define these repository or environment variables:

| Variable | Required | Purpose |
|---|---:|---|
| `QUANTUMFORGE_AWS_ROLE_ARN` | yes | GitHub OIDC role in the isolated sandbox |
| `QUANTUMFORGE_AWS_ACCOUNT_ID` | yes | Account guardrail checked before every live run |
| `QUANTUMFORGE_EVIDENCE_BUCKET` | no | S3 Object Lock bucket with at least seven years of default retention |

The OIDC trust policy should restrict `sub` to this repository and the `quantumforge-aws-sandbox` environment. Do not grant the role to forked pull-request workflows.

The KMS job needs only identity lookup plus KMS create, tag, alias, describe, public-key, sign, verify, disable, alias deletion, and schedule-deletion actions. The optional ALB job additionally needs temporary ACM certificate, VPC networking, security-group, and ELBv2 lifecycle actions. Scope permissions to the sandbox account and require the `project=quantumforge` tag where AWS supports tag conditions.

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
