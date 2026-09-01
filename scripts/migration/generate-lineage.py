#!/usr/bin/env python3
"""Generate and verify deterministic AionCore migration lineage."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path


SCHEMA_VERSION = 1
MINIMUM_SUPPORTED_VERSION = 19
MIGRATION_FILENAME = re.compile(r"^(\d{3})_(.+)\.sql$")


class LineageError(ValueError):
    """Raised when migration inputs violate the lineage contract."""


def build_lineage(migrations_dir: Path) -> dict:
    migrations_dir = Path(migrations_dir)
    if not migrations_dir.is_dir():
        raise LineageError(f"migration directory does not exist: {migrations_dir}")

    parsed = []
    versions = set()
    for path in migrations_dir.iterdir():
        if path.suffix != ".sql":
            continue
        match = MIGRATION_FILENAME.fullmatch(path.name)
        if match is None:
            raise LineageError(f"malformed migration filename: {path.name}")

        version = int(match.group(1))
        if version < 1:
            raise LineageError("migration versions must start at 1")
        if version in versions:
            raise LineageError(f"duplicate migration version {version}")
        versions.add(version)
        parsed.append((version, match.group(2), path))

    if not parsed:
        raise LineageError(f"no migrations found in: {migrations_dir}")

    parsed.sort(key=lambda item: item[0])
    latest_version = parsed[-1][0]
    for expected in range(1, latest_version + 1):
        if expected not in versions:
            raise LineageError(f"missing migration version {expected}")

    entries = []
    for version, description_stem, path in parsed:
        raw_sql = path.read_bytes()
        entries.append(
            {
                "version": version,
                "description": description_stem.replace("_", " "),
                "filename": path.name,
                "checksum": hashlib.sha384(raw_sql).hexdigest(),
            }
        )

    compact_entries = json.dumps(entries, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    fingerprint = hashlib.sha256(compact_entries).hexdigest()
    return {
        "schemaVersion": SCHEMA_VERSION,
        "minimumSupportedVersion": MINIMUM_SUPPORTED_VERSION,
        "latestVersion": latest_version,
        "entryCount": len(entries),
        "fingerprint": fingerprint,
        "entries": entries,
    }


def serialize_lineage(document: dict) -> bytes:
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def write_atomic(path: Path, content: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--migrations", required=True, type=Path)
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output", type=Path)
    destination.add_argument("--check", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        expected = serialize_lineage(build_lineage(args.migrations))
        if args.output is not None:
            write_atomic(args.output, expected)
            return 0

        actual = args.check.read_bytes()
        if actual != expected:
            print(f"migration lineage is stale: {args.check}", file=sys.stderr)
            return 1
        return 0
    except (LineageError, OSError) as error:
        print(f"migration lineage error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
