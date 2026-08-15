import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.release import prepare_officecli


class PrepareOfficeCliTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.managed = self.root / "managed-resources"
        self.managed.mkdir()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_maps_only_the_two_release_targets_to_pinned_assets(self):
        mac = prepare_officecli.asset_for_target("aarch64-apple-darwin")
        self.assertEqual(mac.filename, "officecli-mac-arm64")
        self.assertEqual(mac.output_name, "officecli")
        self.assertEqual(
            mac.sha256,
            "2f158d46f9b6c5eb0dfe4eb02038114001e17acc47b67347417c56dcf9659096",
        )

        windows = prepare_officecli.asset_for_target("x86_64-pc-windows-msvc")
        self.assertEqual(windows.filename, "officecli-win-x64.exe")
        self.assertEqual(windows.output_name, "officecli.exe")
        self.assertEqual(
            windows.sha256,
            "d4d4c10fced307e209744cf98a56b003a6e613424fd651b08469274704afd2c6",
        )

        with self.assertRaisesRegex(prepare_officecli.OfficeCliPreparationError, "unsupported target"):
            prepare_officecli.asset_for_target("x86_64-unknown-linux-gnu")

    def test_installs_only_after_the_download_matches_the_pinned_digest(self):
        payload = b"verified-officecli\n"
        asset = prepare_officecli.OfficeCliAsset(
            filename="officecli-test",
            output_name="officecli",
            sha256=hashlib.sha256(payload).hexdigest(),
        )

        def download(_url, destination):
            destination.write_bytes(payload)

        output = prepare_officecli.install_asset(self.managed, asset, download=download)

        self.assertEqual(output, self.managed / "office" / "officecli")
        self.assertEqual(output.read_bytes(), payload)
        self.assertTrue(output.stat().st_mode & 0o100)

    def test_digest_mismatch_leaves_no_officecli_or_staging_file(self):
        asset = prepare_officecli.OfficeCliAsset(
            filename="officecli-test",
            output_name="officecli.exe",
            sha256="0" * 64,
        )

        def download(_url, destination):
            destination.write_bytes(b"tampered")

        with self.assertRaisesRegex(prepare_officecli.OfficeCliPreparationError, "digest mismatch"):
            prepare_officecli.install_asset(self.managed, asset, download=download)

        self.assertFalse((self.managed / "office").exists())
        self.assertEqual(list(self.managed.glob(".officecli-*")), [])

    def test_refuses_to_replace_an_existing_office_directory(self):
        (self.managed / "office").mkdir()
        asset = prepare_officecli.OfficeCliAsset(
            filename="officecli-test",
            output_name="officecli",
            sha256="0" * 64,
        )

        with self.assertRaisesRegex(prepare_officecli.OfficeCliPreparationError, "already exists"):
            prepare_officecli.install_asset(self.managed, asset, download=lambda *_args: None)

    def test_default_downloader_uses_hardened_curl_transport(self):
        destination = self.root / "download"
        with patch("scripts.release.prepare_officecli.subprocess.run") as run:
            prepare_officecli.download_asset("https://example.test/officecli", destination)

        command = run.call_args.args[0]
        self.assertEqual(command[0], "curl")
        self.assertIn("--fail", command)
        self.assertIn("--location", command)
        self.assertIn("--proto", command)
        self.assertIn("=https", command)
        self.assertIn("--proto-redir", command)
        self.assertIn("--tlsv1.2", command)
        self.assertEqual(command[-2:], ["--output", str(destination)])
        run.assert_called_once_with(command, check=True)


if __name__ == "__main__":
    unittest.main()
