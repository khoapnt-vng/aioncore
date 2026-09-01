import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts.release import assemble_bundle, verify_bundle


REPOSITORY = "khoapnt-vng/aioncore"
VERSION = "0.1.55"
SOURCE_COMMIT = "a" * 40
BUILT_AT = "2026-08-15T14:00:00Z"


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.managed = self.root / "managed-input"
        (self.managed / "runtime").mkdir(parents=True)
        (self.managed / "runtime" / "tool.txt").write_bytes(b"managed-tool\n")
        (self.managed / "config.json").write_bytes(b'{"enabled":true}\n')
        (self.managed / "office").mkdir()
        (self.managed / "office" / "officecli").write_bytes(b"officecli-mac-arm64\n")
        self.lineage = self.root / "migration-lineage.json"
        entries = [
            {
                "version": 28,
                "description": "oauth token client id",
                "filename": "028_oauth_token_client_id.sql",
                "checksum": hashlib.sha384(b"ALTER TABLE oauth_tokens ADD COLUMN client_id TEXT;\n").hexdigest(),
            }
        ]
        fingerprint = hashlib.sha256(
            json.dumps(entries, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        self.lineage.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "minimumSupportedVersion": 19,
                    "latestVersion": 28,
                    "entryCount": 1,
                    "fingerprint": fingerprint,
                    "entries": entries,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def assemble(self, binary_name="aioncore", target="aarch64-apple-darwin", output_name="bundle"):
        office_directory = self.managed / "office"
        for name in ("officecli", "officecli.exe"):
            (office_directory / name).unlink(missing_ok=True)
        office_name = "officecli.exe" if "windows" in target else "officecli"
        (office_directory / office_name).write_bytes(f"{office_name}-{target}\n".encode())
        binary = self.root / binary_name
        binary.write_bytes(b"binary-bytes\n")
        output = self.root / output_name
        assemble_bundle.assemble_bundle(
            binary=binary,
            lineage=self.lineage,
            managed_resources=self.managed,
            output=output,
            repository=REPOSITORY,
            version=VERSION,
            source_commit=SOURCE_COMMIT,
            target=target,
            built_at=BUILT_AT,
        )
        return output

    def verify(self, bundle, **overrides):
        verify_bundle.verify_bundle(
            bundle=bundle,
            repository=overrides.get("repository", REPOSITORY),
            version=overrides.get("version", VERSION),
            source_commit=overrides.get("source_commit", SOURCE_COMMIT),
            target=overrides.get("target", "aarch64-apple-darwin"),
        )

    def mutate_manifest(self, bundle, mutate):
        path = bundle / "bundle-manifest.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        mutate(document)
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    def test_accepts_unix_and_windows_binary_names(self):
        cases = [
            ("aioncore", "aarch64-apple-darwin", "unix-bundle"),
            ("aioncore.exe", "x86_64-pc-windows-msvc", "windows-bundle"),
        ]
        for binary_name, target, output_name in cases:
            with self.subTest(binary_name=binary_name):
                bundle = self.assemble(binary_name, target, output_name)
                self.verify(bundle, target=target)

    def test_bundle_has_exact_top_level_set_and_sorted_manifest_contract(self):
        bundle = self.assemble()
        self.assertEqual(
            {path.name for path in bundle.iterdir()},
            {
                "aioncore",
                "migration-lineage.json",
                "managed-resources",
                "bundle-manifest.json",
                "SHA256SUMS",
            },
        )
        manifest = json.loads((bundle / "bundle-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["schemaVersion"], 1)
        self.assertEqual(manifest["repository"], REPOSITORY)
        self.assertEqual(manifest["version"], VERSION)
        self.assertEqual(manifest["sourceCommit"], SOURCE_COMMIT)
        self.assertEqual(manifest["target"], "aarch64-apple-darwin")
        self.assertEqual(manifest["builtAt"], BUILT_AT)
        self.assertEqual(manifest["migrationLineage"]["fingerprint"], json.loads(self.lineage.read_text())["fingerprint"])
        paths = [entry["path"] for entry in manifest["files"]]
        self.assertEqual(paths, sorted(paths))
        self.assertIn("managed-resources/office/officecli", paths)
        self.assertNotIn("bundle-manifest.json", paths)
        self.assertNotIn("SHA256SUMS", paths)

    def test_assembler_rejects_missing_or_wrong_target_officecli(self):
        for name in ("officecli", "officecli.exe"):
            (self.managed / "office" / name).unlink(missing_ok=True)
        binary = self.root / "aioncore"
        binary.write_bytes(b"binary-bytes\n")

        with self.assertRaisesRegex(assemble_bundle.BundleAssemblyError, "required OfficeCLI"):
            assemble_bundle.assemble_bundle(
                binary=binary,
                lineage=self.lineage,
                managed_resources=self.managed,
                output=self.root / "missing-officecli",
                repository=REPOSITORY,
                version=VERSION,
                source_commit=SOURCE_COMMIT,
                target="aarch64-apple-darwin",
                built_at=BUILT_AT,
            )

        (self.managed / "office" / "officecli").write_bytes(b"wrong target")
        windows_binary = self.root / "aioncore.exe"
        windows_binary.write_bytes(b"binary-bytes\n")
        with self.assertRaisesRegex(assemble_bundle.BundleAssemblyError, "required OfficeCLI"):
            assemble_bundle.assemble_bundle(
                binary=windows_binary,
                lineage=self.lineage,
                managed_resources=self.managed,
                output=self.root / "wrong-officecli",
                repository=REPOSITORY,
                version=VERSION,
                source_commit=SOURCE_COMMIT,
                target="x86_64-pc-windows-msvc",
                built_at=BUILT_AT,
            )

    def test_manifest_and_checksum_bytes_are_deterministic_for_fixed_inputs(self):
        first = self.assemble(output_name="bundle-one")
        second = self.assemble(output_name="bundle-two")
        self.assertEqual(
            (first / "bundle-manifest.json").read_bytes(),
            (second / "bundle-manifest.json").read_bytes(),
        )
        self.assertEqual((first / "SHA256SUMS").read_bytes(), (second / "SHA256SUMS").read_bytes())

    def test_verifier_rejects_missing_and_extra_payload_files(self):
        missing = self.assemble(output_name="missing")
        (missing / "managed-resources" / "config.json").unlink()
        with self.assertRaisesRegex(verify_bundle.BundleError, "payload inventory mismatch"):
            self.verify(missing)

        extra = self.assemble(output_name="extra")
        (extra / "managed-resources" / "unexpected.txt").write_bytes(b"unexpected")
        with self.assertRaisesRegex(verify_bundle.BundleError, "payload inventory mismatch"):
            self.verify(extra)

    def test_verifier_names_a_missing_required_officecli(self):
        bundle = self.assemble()
        (bundle / "managed-resources" / "office" / "officecli").unlink()
        with self.assertRaisesRegex(verify_bundle.BundleError, "required OfficeCLI"):
            self.verify(bundle)

    def test_verifier_rejects_wrong_payload_hash(self):
        bundle = self.assemble()
        (bundle / "aioncore").write_bytes(b"tampered")
        with self.assertRaisesRegex(verify_bundle.BundleError, "payload hash mismatch"):
            self.verify(bundle)

    def test_verifier_rejects_wrong_lineage_fingerprint(self):
        bundle = self.assemble()
        lineage = json.loads((bundle / "migration-lineage.json").read_text(encoding="utf-8"))
        lineage["fingerprint"] = "0" * 64
        (bundle / "migration-lineage.json").write_text(json.dumps(lineage), encoding="utf-8")
        with self.assertRaisesRegex(verify_bundle.BundleError, "lineage fingerprint mismatch"):
            self.verify(bundle)

    def test_verifier_rejects_wrong_expected_source_version_and_target(self):
        bundle = self.assemble()
        cases = [
            ({"source_commit": "b" * 40}, "source commit mismatch"),
            ({"version": "0.1.56"}, "version mismatch"),
            ({"target": "x86_64-pc-windows-msvc"}, "target mismatch"),
        ]
        for overrides, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(verify_bundle.BundleError, message):
                    self.verify(bundle, **overrides)

    def test_verifier_rejects_symlink_anywhere_in_bundle(self):
        bundle = self.assemble()
        link = bundle / "managed-resources" / "linked-tool"
        link.symlink_to(bundle / "managed-resources" / "runtime" / "tool.txt")
        with self.assertRaisesRegex(verify_bundle.BundleError, "symlink"):
            self.verify(bundle)

    @unittest.skipIf(os.name == "nt", "creating symlinks requires additional Windows privileges")
    def test_assembler_materializes_safe_managed_resource_symlinks(self):
        link = self.managed / "runtime" / "tool-link"
        link.symlink_to("tool.txt")

        bundle = self.assemble()
        materialized = bundle / "managed-resources" / "runtime" / "tool-link"

        self.assertFalse(materialized.is_symlink())
        self.assertEqual(materialized.read_bytes(), b"managed-tool\n")
        self.verify(bundle)

    @unittest.skipIf(os.name == "nt", "creating symlinks requires additional Windows privileges")
    def test_assembler_rejects_managed_resource_symlinks_that_escape_root(self):
        outside = self.root / "outside.txt"
        outside.write_bytes(b"outside")
        (self.managed / "escaping-link").symlink_to(outside)

        with self.assertRaisesRegex(assemble_bundle.BundleAssemblyError, "escapes its root"):
            self.assemble()

    def test_verifier_rejects_absolute_and_parent_escape_manifest_paths(self):
        cases = ["/tmp/aioncore", "managed-resources/../aioncore"]
        for index, unsafe_path in enumerate(cases):
            bundle = self.assemble(output_name=f"unsafe-{index}")
            self.mutate_manifest(bundle, lambda document: document["files"][0].update(path=unsafe_path))
            with self.subTest(path=unsafe_path):
                with self.assertRaisesRegex(verify_bundle.BundleError, "unsafe manifest path"):
                    self.verify(bundle)

    def test_verifier_rejects_duplicate_normalized_manifest_paths(self):
        bundle = self.assemble()

        def duplicate(document):
            entry = dict(document["files"][0])
            entry["path"] = entry["path"].replace("/", "//", 1)
            document["files"].append(entry)

        self.mutate_manifest(bundle, duplicate)
        with self.assertRaisesRegex(verify_bundle.BundleError, "duplicate normalized manifest path"):
            self.verify(bundle)

    def test_verifier_rejects_unsorted_manifest(self):
        bundle = self.assemble()
        self.mutate_manifest(bundle, lambda document: document["files"].reverse())
        with self.assertRaisesRegex(verify_bundle.BundleError, "manifest files must be sorted"):
            self.verify(bundle)

    def test_checksum_file_coverage_must_equal_payload_plus_manifest(self):
        bundle = self.assemble()
        checksum_path = bundle / "SHA256SUMS"
        lines = checksum_path.read_text(encoding="utf-8").splitlines()
        checksum_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(verify_bundle.BundleError, "checksum coverage mismatch"):
            self.verify(bundle)


if __name__ == "__main__":
    unittest.main()
