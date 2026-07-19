# Vendor-neutral cryptographic inventory

The inventory is the product boundary. Cloud deployment modules are adapters, not the canonical data model.

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

## Terraform discovery adapter

`policies/discovery/classify.rego` currently normalizes these AWS resource types from Terraform plan JSON:

- KMS keys
- ALB/NLB listeners
- ACM certificates
- ACM Private CA certificate authorities
- CloudFront distributions
- API Gateway v1/v2 domain names
- Site-to-Site VPN connections

Exact, versioned allowlists classify known AWS ML-DSA specs and recommended hybrid PQ-TLS policies. Provider-managed or incomplete data is classified `unknown`, not clean.

## Next adapters

Prioritize discovery over new deployment modules:

1. cloud API collectors for certificates, keys, TLS policies, VPN/IPsec, and ownership tags
2. CBOM/application-library ingestion
3. network protocol observations
4. certificate and CA metadata
5. data-flow and secrecy-lifetime enrichment
6. SaaS/manual attestations with confidence levels

Only after these records normalize into the same schema should additional Azure, GCP, or on-prem deployment modules expand the remediation layer.
