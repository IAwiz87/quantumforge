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
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

REQUIRED_BY_PROFILE = {
    "offline": (
        "assessment-status.json",
        "plan.json",
        "trivy-report.json",
        "checkov-report.json",
        "conftest-report.json",
        "cbom.json",
    ),
    "kms": (
        "assessment-status.json",
        "plan.json",
        "kms-verify.json",
        "openssl-verify.log",
        "key-cleanup-status.json",
    ),
    "alb": (
        "assessment-status.json",
        "plan.json",
        "pq-handshake.log",
        "classical-handshake.log",
        "cleanup-status.json",
    ),
}
ALLOWED_COMPLETE = {"assessment_complete", "no_assets_found"}


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
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repository": os.getenv("GITHUB_REPOSITORY", "local"),
        "commit": os.getenv("GITHUB_SHA", "local"),
        "workflow": os.getenv("GITHUB_WORKFLOW", "local"),
        "run_id": os.getenv("GITHUB_RUN_ID", "local"),
        "aws_account_id": os.getenv("AWS_ACCOUNT_ID", "not_assessed"),
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
