import re
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
RELEASE_PATH = ROOT / ".github" / "workflows" / "release.yml"
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"
APPROVED_TARGETS = {"aarch64-apple-darwin", "x86_64-pc-windows-msvc"}


class ReleaseWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.release_text = RELEASE_PATH.read_text(encoding="utf-8")
        cls.release = yaml.safe_load(cls.release_text)
        cls.ci_text = CI_PATH.read_text(encoding="utf-8")
        cls.ci = yaml.safe_load(cls.ci_text)

    def test_release_matrix_is_exactly_the_two_approved_native_targets(self):
        include = self.release["jobs"]["build"]["strategy"]["matrix"]["include"]
        self.assertEqual({entry["target"] for entry in include}, APPROVED_TARGETS)
        self.assertEqual(len(include), 2)
        self.assertEqual({entry["os"] for entry in include}, {"macos-latest", "windows-latest"})

    def test_prepare_release_binds_exact_tag_version_and_peeled_commit(self):
        prepare = self._job_script("prepare-release")
        self.assertIn('test "${RELEASE_TAG}" = "v0.1.55"', prepare)
        self.assertIn('test "${workspace_version}" = "0.1.55"', prepare)
        self.assertIn('git rev-parse "refs/tags/${RELEASE_TAG}^{}"', prepare)
        self.assertIn('test "${head_commit}" = "${tag_commit}"', prepare)

    def test_each_build_generates_and_verifies_lineage_and_complete_bundle(self):
        build = self._job_script("build")
        self.assertIn("generate-lineage.py", build)
        self.assertIn("--check migration-lineage.json", build)
        self.assertIn("prepare-managed-resources", build)
        self.assertIn("prepare_officecli.py", build)
        self.assertRegex(build, r"(?s)prepare_officecli\.py.*assemble_bundle\.py")
        self.assertIn("assemble_bundle.py", build)
        self.assertGreaterEqual(build.count("verify_bundle.py"), 2)
        self.assertRegex(build, r"(?s)(tar|Compress-Archive).*(tar|Expand-Archive).*verify_bundle\.py")

    def test_archive_names_are_exact_and_unsigned(self):
        self.assertIn("aioncore-v${VERSION}-${{ matrix.target }}.tar.gz", self.release_text)
        self.assertIn("aioncore-v${env:VERSION}-${{ matrix.target }}.zip", self.release_text)
        self.assertIn("unsigned", self.release_text.lower())
        self.assertNotRegex(self.release_text.lower(), r"\bcosign\b|\bsigning\b")

    def test_publish_is_create_only_and_stops_if_release_or_asset_exists(self):
        publish = self._job_script("github-release")
        self.assertNotIn("--clobber", self.release_text)
        self.assertNotIn("gh release upload", self.release_text)
        self.assertIn("gh release view", publish)
        self.assertIn("exit 1", publish)
        self.assertIn("gh release create", publish)
        self.assertIn("aioncore-checksums.txt", publish)

    def test_build_evidence_includes_manifest_and_logs(self):
        build = self.release["jobs"]["build"]
        upload_steps = [
            step
            for step in build["steps"]
            if step.get("uses", "").startswith("actions/upload-artifact@")
        ]
        serialized = str(upload_steps)
        self.assertIn("bundle-manifest.json", serialized)
        self.assertIn("work/extracted/bundle-manifest.json", serialized)
        self.assertIn("build.log", serialized)
        self.assertIn("prepare-officecli.log", serialized)
        self.assertIn("verify", serialized)

    def test_ci_runs_all_release_python_contract_tests(self):
        scripts = self._job_script("release-contract", workflow=self.ci)
        self.assertIn("unittest discover -s scripts/release", scripts)

    def test_workflow_has_no_force_or_overwrite_archive_path(self):
        forbidden = ["--force", "--clobber", "Compress-Archive -Force", "Remove-Item dist"]
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, self.release_text)

    def test_release_actions_are_pinned_to_full_commit_shas(self):
        action_refs = [
            step["uses"]
            for job in self.release["jobs"].values()
            for step in job.get("steps", [])
            if "uses" in step and not step["uses"].startswith("./")
        ]
        self.assertTrue(action_refs)
        for action_ref in action_refs:
            with self.subTest(action_ref=action_ref):
                self.assertRegex(action_ref, r"^[^@]+@[0-9a-f]{40}$")

    @staticmethod
    def _job_script(name, workflow=None):
        workflow = workflow or ReleaseWorkflowContractTests.release
        job = workflow["jobs"][name]
        return "\n".join(str(step.get("run", "")) for step in job.get("steps", []))


if __name__ == "__main__":
    unittest.main()
