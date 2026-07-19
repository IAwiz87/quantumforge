# QuantumForge Roadmap

QuantumForge expands measurement before remediation surface. New cloud deployment modules should not outrun the inventory, policy, test, and evidence systems needed to evaluate them.

## Shipped foundations

- [x] AWS Provider 6.x compatibility and committed lockfiles
- [x] Correct FIPS 204 ML-DSA terminology and pure-PQC KMS module naming
- [x] ALB-only listener contract with exact recommended PQ-TLS policy allowlist
- [x] Credential-free Terraform native mock tests
- [x] Fail-closed census and compliance CI
- [x] Real AWS ML-DSA KMS sign/verify lifecycle harness
- [x] Real ALB hybrid PQ-TLS plus classical-fallback runtime harness
- [x] Separate inherent risk, migration urgency, remediation effort, and evidence confidence
- [x] Owned, approved, expiring exception records
- [x] Attested evidence bundles and an S3 Object Lock publishing interface
- [x] Versioned vendor-neutral crypto-inventory schema

## Priority 1: discovery coverage

Expand collectors and adapters into the canonical inventory schema:

1. cloud API collectors for keys, certificates, CAs, TLS policies, VPN/IPsec, and ownership tags
2. CBOM and application dependency ingestion
3. active and passive protocol observations
4. certificate expiry, signature, key-size, and chain metadata
5. data-flow, environment, business impact, and secrecy-lifetime enrichment
6. SaaS and manual attestations with explicit confidence
7. Kubernetes, container-image, and service-mesh inventory

Unknown or incomplete evidence must remain visible. A failed collector cannot become an empty or compliant inventory.

## Priority 2: governance automation

- generate migration work queues from risk and urgency while keeping effort separate
- require independent approval and immutable history for exceptions
- add policy/version metadata to every decision
- add dashboards for inventory coverage, stale observations, unknown algorithms, and expiring exceptions
- add automated CMVP watchlist comparison after a stable machine-readable source and baseline snapshot exist

## Priority 3: platform remediation modules

Only add deployment modules when the target API is generally available and can be proven with a credential-free contract test plus a real isolated-platform lifecycle test.

| Candidate | Platform | Gate before implementation |
|---|---|---|
| Key Vault / Managed HSM PQ signing | Azure | GA resource API, Terraform support, isolated live verification |
| Cloud KMS PQ signing | GCP | GA algorithm, provider support, independent signature verification |
| PKCS#11/Vault signing | On-prem | defined supported HSM matrix and repeatable hardware/software harness |
| PQ-capable mTLS | Kubernetes/service mesh | interoperable CA, proxy, and client support |
| Hybrid IKE/IPsec | Network edge | standards and vendor interoperability test matrix |
| PQ artifact signing | Software supply chain | verifiable consumer support and trust-root lifecycle |

Azure, GCP, on-prem, SaaS, and application assets can already be represented in `schemas/crypto-inventory.schema.json`; representation does not imply deployable PQC support.

## Contribution rule

Every new collector or module must include:

- exact algorithm/policy validation rather than substring matching
- deterministic offline tests
- malformed, missing, unknown, and deletion-state cases
- explicit ownership and evidence confidence
- live verification when claiming platform behavior
- unconditional cleanup and a cost estimate for paid tests
- updated inventory, policy, and evidence documentation
