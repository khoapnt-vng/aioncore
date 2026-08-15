#!/usr/bin/env python3
"""Assemble a deterministic, self-describing AionCore release bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime
from pathlib import Path


class BundleAssemblyError(ValueError):
    """Raised when bundle inputs violate the release contract."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_built_at(value: str) -> None:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise BundleAssemblyError("builtAt must be UTC RFC3339 with second precision")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise BundleAssemblyError("builtAt is not a valid UTC timestamp") from error


def validate_lineage(document: dict) -> dict:
    summary_fields = (
        "schemaVersion",
        "minimumSupportedVersion",
        "latestVersion",
        "entryCount",
        "fingerprint",
    )
    required = {
        *summary_fields,
        "entries",
    }
    if set(document) != required or document.get("schemaVersion") != 1 or not isinstance(document.get("entries"), list):
        raise BundleAssemblyError("invalid migration lineage shape")
    entries = document["entries"]
    if document["entryCount"] != len(entries):
        raise BundleAssemblyError("migration lineage entry count mismatch")
    compact = json.dumps(entries, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if document["fingerprint"] != hashlib.sha256(compact).hexdigest():
        raise BundleAssemblyError("migration lineage fingerprint mismatch")
    return {key: document[key] for key in summary_fields}


def expected_binary_name(target: str) -> str:
    return "aioncore.exe" if "windows" in target else "aioncore"


def validate_officecli(managed_resources: Path, target: str) -> None:
    office_directory = managed_resources / "office"
    expected_name = "officecli.exe" if "windows" in target else "officecli"
    expected = office_directory / expected_name
    if office_directory.is_symlink() or not office_directory.is_dir():
        raise BundleAssemblyError(f"required OfficeCLI directory missing for target: {target}")
    if expected.is_symlink() or not expected.is_file():
        raise BundleAssemblyError(f"required OfficeCLI binary missing for target: {target}")
    if {path.name for path in office_directory.iterdir()} != {expected_name}:
        raise BundleAssemblyError(f"required OfficeCLI directory has unexpected members for target: {target}")


def copy_managed_resources(source: Path, destination: Path) -> None:
    destination.mkdir()
    source_root = source.resolve(strict=True)
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(source_root)
            except (OSError, ValueError) as error:
                raise BundleAssemblyError(f"managed resource symlink escapes its root: {path}") from error
            if not resolved.is_file():
                raise BundleAssemblyError(f"managed resource symlink must resolve to a regular file: {path}")
            relative = path.relative_to(source)
            output = destination / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(resolved, output)
            continue
        relative = path.relative_to(source)
        if relative.parts[0] == ".staging":
            continue
        output = destination / relative
        if path.is_dir():
            output.mkdir(exist_ok=True)
        elif path.is_file():
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, output)
        else:
            raise BundleAssemblyError(f"unsupported managed resource: {path}")


def serialize_json(document: dict) -> bytes:
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def assemble_bundle(
    *,
    binary: Path,
    lineage: Path,
    managed_resources: Path,
    output: Path,
    repository: str,
    version: str,
    source_commit: str,
    target: str,
    built_at: str,
) -> None:
    binary = Path(binary)
    lineage = Path(lineage)
    managed_resources = Path(managed_resources)
    output = Path(output)
    validate_built_at(built_at)
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise BundleAssemblyError("sourceCommit must be a lowercase 40-character Git SHA")
    if not repository or not version or not target:
        raise BundleAssemblyError("repository, version, and target are required")
    if binary.is_symlink() or not binary.is_file() or binary.name not in {"aioncore", "aioncore.exe"}:
        raise BundleAssemblyError("binary must be a regular aioncore or aioncore.exe file")
    if binary.name != expected_binary_name(target):
        raise BundleAssemblyError("binary name does not match target")
    if lineage.is_symlink() or not lineage.is_file():
        raise BundleAssemblyError("lineage must be a regular file")
    if managed_resources.is_symlink() or not managed_resources.is_dir():
        raise BundleAssemblyError("managed resources must be a regular directory")
    validate_officecli(managed_resources, target)
    if output.exists() or output.is_symlink():
        raise BundleAssemblyError(f"output already exists: {output}")
    if not output.parent.is_dir():
        raise BundleAssemblyError(f"output parent does not exist: {output.parent}")

    lineage_document = json.loads(lineage.read_text(encoding="utf-8"))
    lineage_summary = validate_lineage(lineage_document)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        shutil.copy2(binary, temporary / binary.name)
        shutil.copy2(lineage, temporary / "migration-lineage.json")
        copy_managed_resources(managed_resources, temporary / "managed-resources")

        payload_paths = sorted(
            path.relative_to(temporary).as_posix()
            for path in temporary.rglob("*")
            if path.is_file()
        )
        files = [
            {
                "path": relative,
                "sha256": sha256_file(temporary / relative),
                "size": (temporary / relative).stat().st_size,
            }
            for relative in payload_paths
        ]
        manifest = {
            "schemaVersion": 1,
            "repository": repository,
            "version": version,
            "sourceCommit": source_commit,
            "target": target,
            "builtAt": built_at,
            "migrationLineage": lineage_summary,
            "files": files,
        }
        manifest_path = temporary / "bundle-manifest.json"
        manifest_path.write_bytes(serialize_json(manifest))

        checksum_paths = payload_paths + ["bundle-manifest.json"]
        checksum_lines = [f"{sha256_file(temporary / relative)}  {relative}" for relative in sorted(checksum_paths)]
        (temporary / "SHA256SUMS").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
        os.replace(temporary, output)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--lineage", required=True, type=Path)
    parser.add_argument("--managed-resources", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--built-at", required=True)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        assemble_bundle(
            binary=args.binary,
            lineage=args.lineage,
            managed_resources=args.managed_resources,
            output=args.output,
            repository=args.repository,
            version=args.version,
            source_commit=args.source_commit,
            target=args.target,
            built_at=args.built_at,
        )
        return 0
    except (BundleAssemblyError, OSError, json.JSONDecodeError) as error:
        print(f"bundle assembly error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
