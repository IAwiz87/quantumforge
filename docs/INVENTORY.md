# Vendor-neutral cryptographic inventory

The inventory is the canonical record of cryptographic assets. Cloud deployment modules can read or produce inventory records, but they do not define the cross-platform format.

`schemas/crypto-inventory.schema.json` defines a versioned inventory containing assets from:

- AWS, Azure, and GCP
- on-premises infrastructure
- SaaS dependencies
- application libraries and protocols

Every record requires ownership, environment, observation source and time, evidence confidence, algorithm, cryptographic function, and an explicit classification. `unknown` is a valid first-class state and is never counted as compliant.

Validate the example:

```bash
check-jsonschema \
  --schemafile schemas/crypto-inventory.schema.json \
  examples/inventory/mixed-platform-inventory.json
```

`policies/inventory/validate.rego` rejects duplicate asset IDs and produces provider, classical-only, unknown, and low-confidence coverage metrics.

## Terraform plan inventory collector

`policies/discovery/classify.rego` currently normalizes these AWS resource types from Terraform plan JSON:

- KMS keys
- ALB/NLB listeners
- ACM certificates
- ACM Private CA certificate authorities
- CloudFront distributions
- API Gateway v1/v2 domain names
- Site-to-Site VPN connections

Exact, versioned allowlists classify known AWS ML-DSA specs and recommended hybrid PQ-TLS policies. Provider-managed or incomplete data is classified `unknown`, not clean.

Run and validate the collector with the command below. The script and output directory retain the earlier term `census`, but their purpose is Terraform-plan inventory collection.

```bash
./scripts/run-census.sh tfplan.json reports/census
check-jsonschema \
  --schemafile schemas/crypto-inventory.schema.json \
  reports/census/iac-inventory.json
```

The collector emits the standard `{schema_version, assets}` document, normalizes KMS `SIGN_VERIFY` to `signing`, carries Terraform tags into metadata, and records one observation timestamp for the full collection. Missing owner or environment tags remain explicit as `unassigned` or `unknown`; downstream enrichment should resolve them rather than silently dropping the assets.

Risk enrichment remains inside the same schema through optional `secrecy_lifetime_years`, `data_classification`, `impact`, `migration_deadline_months` (or the calendar-anchored `regulatory_category` alternative), `remediation_effort`, and `dependent_asset_count` fields. `examples/inventory/scoring-ready-inventory.json` and `examples/inventory/calendar-anchored-inventory.json` demonstrate assets that can be validated and scored without discarding information during conversion. See [docs/GOVERNANCE.md](GOVERNANCE.md) and [docs/SCORING_METHODOLOGY.md](SCORING_METHODOLOGY.md) for what each field feeds into.

## Next inventory data sources

Prioritize discovery over new deployment modules:

1. cloud API collectors for certificates, keys, TLS policies, VPN/IPsec, and ownership tags
2. Cryptographic Bill of Materials (CBOM) and application-library ingestion
3. network protocol observations
4. certificate and CA metadata
5. data-flow and secrecy-lifetime enrichment
6. SaaS/manual attestations with confidence levels

Only after these records normalize into the same schema should additional Azure, GCP, or on-prem deployment modules expand the remediation layer.
