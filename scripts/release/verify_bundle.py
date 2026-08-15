#!/usr/bin/env python3
"""Independently verify an assembled AionCore release bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
import re
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath


class BundleError(ValueError):
    """Raised when a bundle violates the verification contract."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict:
    def reject_duplicate_keys(pairs):
        document = {}
        for key, value in pairs:
            if key in document:
                raise BundleError(f"duplicate JSON key: {key}")
            document[key] = value
        return document

    try:
        document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BundleError(f"invalid JSON file: {path.name}") from error
    if not isinstance(document, dict):
        raise BundleError(f"JSON root must be an object: {path.name}")
    return document


def validate_timestamp(value) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise BundleError("invalid builtAt timestamp")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise BundleError("invalid builtAt timestamp") from error


def normalized_manifest_path(raw) -> str:
    if (
        not isinstance(raw, str)
        or not raw
        or "\\" in raw
        or PurePosixPath(raw).is_absolute()
        or ".." in raw.split("/")
        or re.match(r"^[A-Za-z]:", raw)
    ):
        raise BundleError(f"unsafe manifest path: {raw}")
    normalized = posixpath.normpath(raw)
    if normalized in {"", "."}:
        raise BundleError(f"unsafe manifest path: {raw}")
    return normalized


def assert_no_symlinks(bundle: Path) -> None:
    if bundle.is_symlink():
        raise BundleError("bundle is a symlink")
    for path in bundle.rglob("*"):
        if path.is_symlink():
            raise BundleError(f"bundle contains symlink: {path.relative_to(bundle).as_posix()}")


def verify_lineage(bundle: Path, manifest: dict) -> None:
    lineage = load_json(bundle / "migration-lineage.json")
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
    if set(lineage) != required or lineage.get("schemaVersion") != 1 or not isinstance(lineage.get("entries"), list):
        raise BundleError("invalid migration lineage shape")
    if lineage["entryCount"] != len(lineage["entries"]):
        raise BundleError("lineage entry count mismatch")
    compact = json.dumps(lineage["entries"], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if lineage["fingerprint"] != hashlib.sha256(compact).hexdigest():
        raise BundleError("lineage fingerprint mismatch")
    expected_summary = {key: lineage[key] for key in summary_fields}
    if manifest.get("migrationLineage") != expected_summary:
        raise BundleError("manifest migration lineage mismatch")


def validate_manifest_files(manifest: dict) -> dict[str, dict]:
    files = manifest.get("files")
    if not isinstance(files, list):
        raise BundleError("manifest files must be an array")
    seen = {}
    raw_paths = []
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise BundleError("invalid manifest file entry")
        raw = entry["path"]
        normalized = normalized_manifest_path(raw)
        if normalized in seen:
            raise BundleError(f"duplicate normalized manifest path: {normalized}")
        seen[normalized] = entry
        raw_paths.append(raw)
        if raw != normalized:
            raise BundleError(f"unsafe manifest path: {raw}")
        if not isinstance(entry["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise BundleError(f"invalid manifest hash: {raw}")
        if not isinstance(entry["size"], int) or entry["size"] < 0:
            raise BundleError(f"invalid manifest size: {raw}")
    if raw_paths != sorted(raw_paths):
        raise BundleError("manifest files must be sorted")
    return seen


def parse_checksums(path: Path) -> dict[str, str]:
    checksums = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise BundleError("invalid SHA256SUMS") from error
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            raise BundleError("invalid SHA256SUMS line")
        digest, raw = match.groups()
        normalized = normalized_manifest_path(raw)
        if raw != normalized or normalized in checksums:
            raise BundleError("invalid or duplicate SHA256SUMS path")
        checksums[normalized] = digest
    if list(checksums) != sorted(checksums):
        raise BundleError("SHA256SUMS paths must be sorted")
    return checksums


def verify_bundle(*, bundle: Path, repository: str, version: str, source_commit: str, target: str) -> None:
    bundle = Path(bundle)
    if not bundle.is_dir():
        raise BundleError("bundle directory does not exist")
    assert_no_symlinks(bundle)

    manifest_path = bundle / "bundle-manifest.json"
    manifest = load_json(manifest_path)
    required_manifest = {
        "schemaVersion",
        "repository",
        "version",
        "sourceCommit",
        "target",
        "builtAt",
        "migrationLineage",
        "files",
    }
    if set(manifest) != required_manifest or manifest.get("schemaVersion") != 1:
        raise BundleError("invalid bundle manifest shape")
    if manifest["repository"] != repository:
        raise BundleError("repository mismatch")
    if manifest["version"] != version:
        raise BundleError("version mismatch")
    if manifest["sourceCommit"] != source_commit:
        raise BundleError("source commit mismatch")
    if manifest["target"] != target:
        raise BundleError("target mismatch")
    validate_timestamp(manifest["builtAt"])

    binary_name = "aioncore.exe" if "windows" in target else "aioncore"
    expected_top = {binary_name, "migration-lineage.json", "managed-resources", "bundle-manifest.json", "SHA256SUMS"}
    actual_top = {path.name for path in bundle.iterdir()}
    if actual_top != expected_top or not (bundle / "managed-resources").is_dir():
        raise BundleError("bundle top-level member set mismatch")

    verify_lineage(bundle, manifest)
    entries = validate_manifest_files(manifest)

    actual_payloads = {
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file()
        and path.relative_to(bundle).as_posix() not in {"bundle-manifest.json", "SHA256SUMS"}
    }
    if set(entries) != actual_payloads:
        raise BundleError("payload inventory mismatch")
    for relative, entry in entries.items():
        path = bundle / relative
        if path.stat().st_size != entry["size"] or sha256_file(path) != entry["sha256"]:
            raise BundleError(f"payload hash mismatch: {relative}")

    checksums = parse_checksums(bundle / "SHA256SUMS")
    expected_checksum_paths = actual_payloads | {"bundle-manifest.json"}
    if set(checksums) != expected_checksum_paths:
        raise BundleError("checksum coverage mismatch")
    for relative, expected_hash in checksums.items():
        if sha256_file(bundle / relative) != expected_hash:
            raise BundleError(f"checksum mismatch: {relative}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--target", required=True)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        verify_bundle(
            bundle=args.bundle,
            repository=args.repository,
            version=args.version,
            source_commit=args.source_commit,
            target=args.target,
        )
        return 0
    except BundleError as error:
        print(f"bundle verification error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
