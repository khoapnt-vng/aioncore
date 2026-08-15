#!/usr/bin/env python3
"""Add a pinned OfficeCLI binary to an AionCore managed-resources tree."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


OFFICECLI_VERSION = "v1.0.143"
OFFICECLI_RELEASE_BASE = f"https://github.com/iOfficeAI/OfficeCli/releases/download/{OFFICECLI_VERSION}"


class OfficeCliPreparationError(ValueError):
    """Raised when OfficeCLI cannot be added without violating the release contract."""


@dataclass(frozen=True)
class OfficeCliAsset:
    filename: str
    output_name: str
    sha256: str


ASSETS = {
    "aarch64-apple-darwin": OfficeCliAsset(
        filename="officecli-mac-arm64",
        output_name="officecli",
        sha256="2f158d46f9b6c5eb0dfe4eb02038114001e17acc47b67347417c56dcf9659096",
    ),
    "x86_64-pc-windows-msvc": OfficeCliAsset(
        filename="officecli-win-x64.exe",
        output_name="officecli.exe",
        sha256="d4d4c10fced307e209744cf98a56b003a6e613424fd651b08469274704afd2c6",
    ),
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def asset_for_target(target: str) -> OfficeCliAsset:
    try:
        return ASSETS[target]
    except KeyError as error:
        raise OfficeCliPreparationError(f"unsupported target: {target}") from error


def download_asset(url: str, destination: Path) -> None:
    command = [
        "curl",
        "--fail",
        "--location",
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--tlsv1.2",
        url,
        "--output",
        str(destination),
    ]
    try:
        subprocess.run(command, check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise OfficeCliPreparationError("OfficeCLI HTTPS download failed") from error


def install_asset(
    managed_resources: Path,
    asset: OfficeCliAsset,
    *,
    download: Callable[[str, Path], None] = download_asset,
) -> Path:
    managed_resources = Path(managed_resources)
    if managed_resources.is_symlink() or not managed_resources.is_dir():
        raise OfficeCliPreparationError("managed resources must be a regular directory")

    office_directory = managed_resources / "office"
    if office_directory.exists() or office_directory.is_symlink():
        raise OfficeCliPreparationError("managed-resources/office already exists; refusing to replace it")

    descriptor, staging_name = tempfile.mkstemp(prefix=".officecli-", dir=managed_resources)
    os.close(descriptor)
    staging = Path(staging_name)
    created_office_directory = False
    try:
        url = f"{OFFICECLI_RELEASE_BASE}/{asset.filename}"
        download(url, staging)
        actual_digest = sha256_file(staging)
        if actual_digest != asset.sha256:
            raise OfficeCliPreparationError(
                f"OfficeCLI digest mismatch for {asset.filename}: expected {asset.sha256}, got {actual_digest}"
            )

        staging.chmod(0o755)
        office_directory.mkdir()
        created_office_directory = True
        output = office_directory / asset.output_name
        os.replace(staging, output)
        return output
    except Exception:
        staging.unlink(missing_ok=True)
        if created_office_directory:
            office_directory.rmdir()
        raise


def prepare_officecli(managed_resources: Path, target: str) -> Path:
    asset = asset_for_target(target)
    output = install_asset(managed_resources, asset)
    print(
        f"Prepared OfficeCLI {OFFICECLI_VERSION} for {target} at {output} "
        f"(sha256={asset.sha256})"
    )
    return output


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--managed-resources", required=True, type=Path)
    parser.add_argument("--target", required=True)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        prepare_officecli(args.managed_resources, args.target)
        return 0
    except (OfficeCliPreparationError, OSError) as error:
        print(f"OfficeCLI preparation error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
