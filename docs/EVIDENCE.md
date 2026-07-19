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

`scripts/run-census.sh` emits `collection_failed` before returning nonzero if its plan input is absent, malformed, or cannot be evaluated. `scripts/build-evidence.py` refuses to bundle `collection_failed` or `not_assessed` results.

## Bundle integrity

`scripts/build-evidence.py INPUT_DIR OUTPUT_ZIP [offline|kms|alb]`:

1. Requires every artifact for the selected evidence profile to exist and be non-empty.
2. Rejects incomplete assessment states.
3. Creates `manifest.json` with the commit, workflow identity, AWS account/region context, file sizes, and SHA-256 digest of each evidence object.
4. Produces a ZIP and a separate SHA-256 checksum.

Trusted `main` and live workflows use `actions/attest-build-provenance` to create a keyless Sigstore-backed GitHub artifact attestation for each complete bundle. Pull-request jobs intentionally have no OIDC or attestation authority. Verify a downloaded bundle with:

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
