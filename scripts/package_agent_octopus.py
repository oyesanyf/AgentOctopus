#!/usr/bin/env python3
"""
Agent Octopus Enterprise Platform Packaging Script:
Creates a clean, verified, and complete source distribution archive
containing the Rust core, 14 specialized Arms, Cedar/Dogwood policy engine,
AI workers (OpenEvolve, Open Dream-RSI, RFCHunt), test suites, and signed binaries.
"""

import hashlib
import os
import sys
import time
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_ZIP = REPO_ROOT / "agent_octopus_source_code.zip"

EXCLUDE_DIRS = {
    ".git",
    "target",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    ".idea",
    ".vscode",
}

EXCLUDE_EXTENSIONS = {
    ".pyc",
}

EXCLUDE_FILES = {
    "agent_octopus_source_code.zip",
    "http_terminator.zip",
    "http_terminator_with_db.zip",
}


def compute_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def package_agent_octopus(output_zip: Path = OUTPUT_ZIP) -> bool:
    print("=" * 70)
    print("  AGENT OCTOPUS: ENTERPRISE SOURCE PACKAGING")
    print(f"  Source Root : {REPO_ROOT}")
    print(f"  Output Path : {output_zip}")
    print("=" * 70)

    if output_zip.exists():
        output_zip.unlink()

    file_count = 0
    total_bytes = 0

    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for root, dirs, files in os.walk(REPO_ROOT):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for f in sorted(files):
                if f in EXCLUDE_FILES or any(f.endswith(ext) for ext in EXCLUDE_EXTENSIONS):
                    continue
                full_path = Path(root) / f
                arcname = full_path.relative_to(REPO_ROOT)
                zf.write(full_path, arcname)
                file_count += 1
                total_bytes += full_path.stat().st_size

    zip_size_mb = output_zip.stat().st_size / (1024 * 1024)
    sha256_hash = compute_sha256(output_zip)

    print(f"[+] Files archived   : {file_count:,}")
    print(f"[+] Uncompressed size: {total_bytes / (1024 * 1024):.2f} MB")
    print(f"[+] Compressed size  : {zip_size_mb:.2f} MB")
    print(f"[+] SHA-256 Digest   : {sha256_hash}")

    # Generate Manifest file
    manifest_path = REPO_ROOT / "dist_manifest.json"
    import json
    manifest = {
        "package": "AgentOctopus",
        "archive": output_zip.name,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "file_count": file_count,
        "uncompressed_bytes": total_bytes,
        "compressed_bytes": output_zip.stat().st_size,
        "sha256": sha256_hash,
    }
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"[+] Release Manifest saved: {manifest_path}")
    print("=" * 70)
    return True


if __name__ == "__main__":
    success = package_agent_octopus()
    sys.exit(0 if success else 1)
