#!/usr/bin/env python3
"""Build a complete evidence manifest and ZIP bundle.

Every required assessment artifact must exist and be non-empty. The manifest
records SHA-256 digests and explicit assessment status so a failed collection
cannot be presented as a clean assessment.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

REQUIRED_BY_PROFILE = {
    "offline": (
        "assessment-status.json",
        "plan.json",
        "iac-inventory.json",
        "census-summary.json",
        "risk-input.json",
        "risk-assessment.json",
        "trivy-report.json",
        "trivy-secret-report.json",
        "checkov-report.json",
        "conftest-report.json",
        "cbom.json",
    ),
    "kms": (
        "assessment-status.json",
        "kms-verify.json",
        "openssl-verify.log",
        "key-cleanup-status.json",
    ),
    "alb": (
        "assessment-status.json",
        "pq-handshake.log",
        "classical-handshake.log",
        "cleanup-status.json",
    ),
}
ALLOWED_COMPLETE = {"assessment_complete", "no_assets_found"}
FORBIDDEN_LIVE_EVIDENCE = re.compile(
    r"arn:aws|\b\d{12}\b|\b(?:\d{1,3}\.){3}\d{1,3}\b|\.amazonaws\.com|"
    r"BEGIN [A-Z ]*PRIVATE KEY|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|"
    r"(?:aws_access_key_id|aws_secret_access_key|aws_session_token)\s*[=:]\s*\S+|"
    r"://[^:@/\s]+:[^@\s/]+@",
    re.IGNORECASE,
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    if len(sys.argv) not in (3, 4):
        print("usage: build-evidence.py INPUT_DIR OUTPUT_ZIP [offline|kms|alb]", file=sys.stderr)
        return 2

    source = Path(sys.argv[1]).resolve()
    output = Path(sys.argv[2]).resolve()
    profile = sys.argv[3] if len(sys.argv) == 4 else "offline"
    if profile not in REQUIRED_BY_PROFILE:
        raise SystemExit(f"unknown evidence profile: {profile}")
    required = REQUIRED_BY_PROFILE[profile]
    missing = [
        name
        for name in required
        if not (source / name).is_file() or not (source / name).stat().st_size
    ]
    if missing:
        raise SystemExit(f"required evidence missing or empty: {', '.join(missing)}")

    status_doc = json.loads((source / "assessment-status.json").read_text())
    status = status_doc.get("status")
    if status not in ALLOWED_COMPLETE:
        raise SystemExit(f"refusing to bundle incomplete assessment status: {status!r}")

    if profile == "offline":
        inventory = json.loads((source / "iac-inventory.json").read_text())
        summary = json.loads((source / "census-summary.json").read_text())
        assets = inventory.get("assets")
        if inventory.get("schema_version") != "1.0.0" or not isinstance(assets, list):
            raise SystemExit("offline inventory is not a versioned assets envelope")
        counts = (len(assets), summary.get("total_assets"), status_doc.get("total_assets"))
        if len(set(counts)) != 1:
            raise SystemExit(f"offline inventory/status asset counts disagree: {counts}")
        if status_doc.get("assessment_scope") not in {"environment", "synthetic_fixture"}:
            raise SystemExit("offline assessment_status has an invalid assessment_scope")
        risk_input = json.loads((source / "risk-input.json").read_text())
        risk_assessment = json.loads((source / "risk-assessment.json").read_text())
        inventory_ids = {asset.get("asset_id") for asset in assets}
        risk_assets = risk_input.get("assets")
        scored_assets = risk_assessment.get("scored_inventory")
        if not isinstance(risk_assets, list):
            raise SystemExit("risk input is not an assets envelope")
        if not isinstance(scored_assets, list):
            raise SystemExit("risk assessment has no scored inventory")
        risk_ids = {asset.get("asset_id") for asset in risk_assets}
        scored_ids = {asset.get("asset_id") for asset in scored_assets}
        if (
            None in inventory_ids
            or None in risk_ids
            or None in scored_ids
            or len(inventory_ids) != len(assets)
            or len(risk_ids) != len(risk_assets)
            or len(scored_ids) != len(scored_assets)
        ):
            raise SystemExit("inventory or risk asset IDs are missing or duplicated")
        if inventory_ids != risk_ids or risk_ids != scored_ids:
            raise SystemExit("inventory, risk input, and scored inventory asset IDs disagree")
        if (
            risk_assessment.get("valid_asset_count") != len(assets)
            or risk_assessment.get("invalid_asset_count") != 0
        ):
            raise SystemExit("risk assessment is incomplete or contains invalid assets")
    elif profile == "kms":
        cleanup = json.loads((source / "key-cleanup-status.json").read_text())
        verification = json.loads((source / "kms-verify.json").read_text())
        if cleanup.get("KeyState") != "PendingDeletion" or not cleanup.get("DeletionDate"):
            raise SystemExit("KMS cleanup evidence does not prove PendingDeletion")
        if verification.get("SignatureValid") is not True:
            raise SystemExit("KMS verification evidence is not successful")
        if (
            status_doc.get("account_verified") is not True
            or status_doc.get("key_spec") != "ML_DSA_65"
            or status_doc.get("kms_verify") is not True
            or status_doc.get("openssl_verify") is not True
        ):
            raise SystemExit("KMS assessment does not prove ML_DSA_65 dual verification")
        assessed_at = datetime.fromisoformat(status_doc["timestamp"].replace("Z", "+00:00"))
        deletion_at = datetime.fromisoformat(cleanup["DeletionDate"].replace("Z", "+00:00"))
        deletion_window = deletion_at - assessed_at
        if not timedelta(days=6, hours=23) <= deletion_window <= timedelta(days=7, hours=1):
            raise SystemExit(
                "KMS deletion window evidence is outside the expected seven-day window"
            )
    elif profile == "alb":
        cleanup = json.loads((source / "cleanup-status.json").read_text())
        if (
            cleanup.get("terraform_destroyed") is not True
            or cleanup.get("certificate_deleted") is not True
        ):
            raise SystemExit("ALB cleanup evidence is incomplete")
        if (
            status_doc.get("account_verified") is not True
            or status_doc.get("ssl_policy")
            != "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
            or status_doc.get("pq_group") != "X25519MLKEM768"
            or status_doc.get("classical_fallback_group") != "X25519"
        ):
            raise SystemExit("ALB assessment does not contain the required policy and groups")

    scan_for_private_identifiers = profile in {"kms", "alb"} or (
        profile == "offline" and status_doc.get("assessment_scope") == "environment"
    )
    if scan_for_private_identifiers:
        for name in required:
            content = (source / name).read_text(errors="ignore")
            if FORBIDDEN_LIVE_EVIDENCE.search(content):
                raise SystemExit(
                    f"evidence contains a forbidden account/resource identifier: {name}"
                )

    artifacts = [
        {
            "path": name,
            "sha256": sha256(source / name),
            "size_bytes": (source / name).stat().st_size,
        }
        for name in sorted(required)
    ]
    manifest = {
        "schema_version": "1.0.0",
        "evidence_profile": profile,
        "assessment_status": status,
        "assessment_scope": status_doc.get("assessment_scope", "live_runtime"),
        "evidence_purpose": (
            "framework_validation"
            if status_doc.get("assessment_scope") == "synthetic_fixture"
            else "environment_or_runtime_assessment"
        ),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repository": os.getenv("GITHUB_REPOSITORY", "local"),
        "commit": os.getenv("GITHUB_SHA", "local"),
        "workflow": os.getenv("GITHUB_WORKFLOW", "local"),
        "run_id": os.getenv("GITHUB_RUN_ID", "local"),
        "aws_account_verified": status_doc.get("account_verified", False),
        "aws_region": os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "not_assessed")),
        "artifacts": artifacts,
    }
    manifest_path = source / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for name in sorted((*required, "manifest.json")):
            bundle.write(source / name, arcname=f"evidence/{name}")

    checksum_path = output.with_suffix(output.suffix + ".sha256")
    checksum_path.write_text(f"{sha256(output)}  {output.name}\n")
    print(json.dumps({"bundle": str(output), "sha256": sha256(output), "status": status}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
