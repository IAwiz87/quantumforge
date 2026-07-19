#!/usr/bin/env python3
"""Generate a non-empty CycloneDX CBOM from QuantumForge's enforced allowlists."""

from __future__ import annotations

import argparse
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAMESPACE = uuid.UUID("7dc2e9c1-0e85-4f32-a356-77bc46a049f4")


def properties(**values: str) -> list[dict[str, str]]:
    return [
        {"name": f"quantumforge:{key.replace('_', '-')}", "value": value}
        for key, value in values.items()
    ]


def component(name: str, standard: str, classification: str, source: str, kind: str) -> dict:
    ref = f"crypto:{kind}:{name}"
    return {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": name,
        "version": standard,
        "properties": properties(
            standard=standard,
            classification=classification,
            source=source,
            asset_type=kind,
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    kms_path = ROOT / "modules/pqc-kms-signing/variables.tf"
    alb_path = ROOT / "modules/hybrid-pqc-alb/variables.tf"
    kms_text = kms_path.read_text()
    alb_text = alb_path.read_text()

    key_specs = sorted(set(re.findall(r'"(ML_DSA_(?:44|65|87))"', kms_text)))
    policies = sorted(set(re.findall(r'"(ELBSecurityPolicy-[^"]+-PQ-2025-09)"', alb_text)))
    if key_specs != ["ML_DSA_44", "ML_DSA_65", "ML_DSA_87"]:
        raise SystemExit(f"unexpected ML-DSA allowlist: {key_specs}")
    if len(policies) < 4:
        raise SystemExit(f"expected at least four exact hybrid PQ-TLS policies, found: {policies}")

    components = [
        component(
            spec.replace("_", "-"),
            "FIPS 204",
            "post_quantum",
            str(kms_path.relative_to(ROOT)),
            "algorithm",
        )
        for spec in key_specs
    ]
    components.extend(
        component(
            policy,
            "AWS ELB PQ-TLS 2025-09",
            "hybrid_post_quantum",
            str(alb_path.relative_to(ROOT)),
            "security-policy",
        )
        for policy in policies
    )
    for group, standard in (
        ("X25519MLKEM768", "FIPS 203 + X25519 hybrid"),
        ("SecP256r1MLKEM768", "FIPS 203 + secp256r1 hybrid"),
        ("SecP384r1MLKEM1024", "FIPS 203 + secp384r1 hybrid"),
    ):
        components.append(
            component(
                group,
                standard,
                "hybrid_post_quantum",
                "AWS ELB security policy",
                "key-establishment-group",
            )
        )

    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    identity = "|".join(sorted(item["bom-ref"] for item in components))
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(NAMESPACE, identity)}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "quantumforge-cbom-generator",
                    "version": "1.0.0",
                }]
            },
            "component": {
                "type": "application",
                "name": "quantumforge",
                "version": "repository",
            },
        },
        "components": sorted(components, key=lambda item: item["bom-ref"]),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"output": str(args.output), "components": len(components)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
