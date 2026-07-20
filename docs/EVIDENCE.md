# Evidence integrity and retention

QuantumForge distinguishes evidence completeness, integrity, provenance, and retention. A ZIP file is not automatically signed evidence, and a GitHub Actions artifact is not a seven-year record system.

## Assessment states

Every collection run must use one of these explicit states:

| State | Meaning |
|---|---|
| `assessment_complete` | Collection and required analysis completed and assets were assessed |
| `no_assets_found` | Collection completed successfully and found zero in-scope assets |
| `collection_failed` | Required collection or analysis failed; never interpret this as an empty inventory |
| `not_assessed` | No valid assessment was executed for the scope |

The Terraform-plan inventory collector, `scripts/run-census.sh`, emits `collection_failed` before returning nonzero if its input is absent, malformed, or cannot be evaluated. `scripts/build-evidence.py` refuses to bundle `collection_failed` or `not_assessed` results.

The pull-request workflow evaluates generated test plans and marks them with `assessment_scope: synthetic_fixture`. Its artifact proves framework behavior, not the cryptographic posture of an AWS account. Environment assessments must run the inventory collector against a real collected plan, retain `assessment_scope: environment`, and satisfy the same schema and evidence checks.

## Bundle integrity

`scripts/build-evidence.py INPUT_DIR OUTPUT_ZIP [offline|kms|alb]`:

1. Requires every artifact for the selected validation mode, called an evidence profile, to exist and be non-empty.
2. Rejects incomplete assessment states.
3. Creates `manifest.json` with the commit, workflow identity, verified-account flag, region, file sizes, and SHA-256 digest of each evidence object.
4. Produces a ZIP and a separate SHA-256 checksum.

The offline profile includes the source plan, explicit assessment status, normalized inventory, inventory-collection summary, schema-valid risk enrichment, risk assessment, Checkov, Trivy infrastructure-as-code and secret reports, Conftest report, and a non-empty Cryptographic Bill of Materials. It requires inventory, summary, status, enrichment, and scored asset IDs/counts to agree, with no invalid scored assets. KMS and ALB profiles require successful runtime assertions plus semantic cleanup evidence (`PendingDeletion` with the seven-day KMS window, or complete ALB/certificate deletion).

Live bundles deliberately omit Terraform plans/state, account IDs, resource ARNs, ALB endpoints, private keys, and connection strings. Environment-assessment inputs must pseudonymize those identifiers before bundling; generated test plans may retain clearly fake placeholder IDs. The builder blocks publication if an environment or required live-evidence file contains one of the forbidden identifier patterns. Raw provider logs remain only on the temporary workflow runner and are not uploaded as failure artifacts.

Protected jobs triggered from `main`, including the live validation workflow, use `actions/attest-build-provenance` to create a keyless Sigstore-backed GitHub artifact attestation for each complete bundle. This signed statement links the bundle to the workflow and commit that created it. Pull-request jobs intentionally have no OpenID Connect (OIDC) or attestation authority. Verify a downloaded bundle with:

```bash
gh attestation verify quantumforge-kms-<run-id>.zip --repo <owner>/quantumforge
```

A manifest alone detects accidental modification but does not establish signer identity. The GitHub attestation supplies workflow provenance.

## Seven-year retention

The normal GitHub artifact copy is intentionally retained for only 30 days. Long-term evidence is uploaded only when `QUANTUMFORGE_EVIDENCE_BUCKET` is configured.

`scripts/publish-evidence-s3.sh` refuses to upload unless:

- S3 Object Lock is enabled; and
- the bucket's default retention is at least seven years / 2,555 days.

It then uploads the bundle in `COMPLIANCE` mode with an explicit seven-year retain-until date, SHA-256 metadata, and S3 checksum validation. Provision this bucket separately so a test workflow cannot weaken or delete its retention controls. Apply least privilege, versioning, access logging, encryption, and separate administrative ownership.

If no compliant bucket is configured, the workflow still creates an attested short-term artifact but does **not** claim seven-year retention.
