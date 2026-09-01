import re
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
RELEASE_PATH = ROOT / ".github" / "workflows" / "release.yml"
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"
MANUAL_PATH = ROOT / ".github" / "workflows" / "build-manual.yml"
GITATTRIBUTES_PATH = ROOT / ".gitattributes"
APPROVED_TARGETS = {"aarch64-apple-darwin", "x86_64-pc-windows-msvc"}


class ReleaseWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.release_text = RELEASE_PATH.read_text(encoding="utf-8")
        cls.release = yaml.safe_load(cls.release_text)
        cls.ci_text = CI_PATH.read_text(encoding="utf-8")
        cls.ci = yaml.safe_load(cls.ci_text)
        cls.manual_text = MANUAL_PATH.read_text(encoding="utf-8")
        cls.manual = yaml.safe_load(cls.manual_text)
        cls.gitattributes_text = GITATTRIBUTES_PATH.read_text(encoding="utf-8")

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

    def test_prepare_release_requires_annotated_tag_merged_into_release_branch(self):
        prepare = self._job_script("prepare-release")
        self.assertEqual(
            self.release["env"]["RELEASE_BRANCH"],
            "security/pilot-hardening-d01-d06",
        )
        self.assertIn(
            'refs/heads/${RELEASE_BRANCH}:refs/remotes/origin/${RELEASE_BRANCH}',
            prepare,
        )
        tag_type = 'git cat-file -t "refs/tags/${RELEASE_TAG}"'
        annotated_guard = 'test "${tag_type}" = "tag" || {'
        tag_commit = 'git rev-parse "refs/tags/${RELEASE_TAG}^{}"'
        ancestor_guard = (
            'git merge-base --is-ancestor "${tag_commit}" '
            '"origin/${RELEASE_BRANCH}" || {'
        )
        self.assertIn(tag_type, prepare)
        self.assertIn(annotated_guard, prepare)
        self.assertIn(ancestor_guard, prepare)
        self.assertIn("set -euo pipefail", prepare)
        self.assertNotIn("set +e", prepare)
        self.assertNotIn("|| true", prepare)
        self.assertRegex(
            prepare,
            rf"(?s){re.escape(annotated_guard)}.*?exit 1.*?{re.escape(tag_commit)}",
        )
        self.assertRegex(
            prepare,
            rf'(?s){re.escape(ancestor_guard)}.*?exit 1.*?echo "version=',
        )
        self.assertLess(prepare.index(tag_type), prepare.index(annotated_guard))
        self.assertLess(prepare.index(annotated_guard), prepare.index(tag_commit))
        self.assertLess(prepare.index(tag_commit), prepare.index(ancestor_guard))

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

    def test_only_github_release_job_has_write_permission(self):
        self.assertEqual(self.release["permissions"], {"contents": "read"})
        self.assertEqual(
            self.release["jobs"]["github-release"].get("permissions"),
            {"contents": "write"},
        )
        for job_name in ("prepare-release", "build"):
            with self.subTest(job_name=job_name):
                self.assertNotEqual(
                    self.release["jobs"][job_name].get("permissions", {}).get("contents"),
                    "write",
                )

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

    def test_ci_runs_for_main_and_the_actual_release_branch(self):
        triggers = self.ci.get("on", self.ci.get(True))
        expected = {"main", "security/pilot-hardening-d01-d06"}
        self.assertEqual(set(triggers["push"]["branches"]), expected)
        self.assertEqual(set(triggers["pull_request"]["branches"]), expected)

    def test_manual_build_uploads_a_complete_bundle_for_internal_packaging(self):
        build = self._job_script("build", workflow=self.manual)
        self.assertIn("OPENSSL_SRC_PERL", build)
        self.assertIn("prepare-managed-resources", build)
        self.assertIn("prepare_officecli.py", build)
        self.assertIn("assemble_bundle.py", build)
        self.assertIn("verify_bundle.py", build)
        self.assertIn("work/bundle", build)

    def test_internal_tag_builds_only_the_two_internal_test_targets(self):
        self.assertIn('internal-sprint3-aioncore-*', self.manual_text)
        self.assertIn("inputs.platform || 'internal-two-target'", self.manual_text)
        self.assertIn('inputs.branch || github.sha', self.manual_text)
        self.assertIn('if [ "$PLATFORM" = "internal-two-target" ]', self.manual_text)

    def test_manual_build_exposes_only_targets_with_complete_officecli_bundles(self):
        self.assertIn("aarch64-apple-darwin", self.manual_text)
        self.assertIn("x86_64-pc-windows-msvc", self.manual_text)
        for unsupported in (
            "x86_64-apple-darwin",
            "aarch64-pc-windows-msvc",
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
        ):
            with self.subTest(unsupported=unsupported):
                self.assertNotIn(unsupported, self.manual_text)

    def test_windows_disables_crlf_conversion_before_checkout(self):
        for workflow_name, workflow in (("release", self.release), ("manual", self.manual)):
            with self.subTest(workflow=workflow_name):
                steps = workflow["jobs"]["build"]["steps"]
                configure_index = next(
                    index
                    for index, step in enumerate(steps)
                    if step.get("name") == "Configure LF checkout on Windows"
                )
                checkout_index = next(
                    index
                    for index, step in enumerate(steps)
                    if step.get("uses", "").startswith("actions/checkout@")
                )
                self.assertLess(configure_index, checkout_index)
                self.assertEqual(steps[configure_index].get("if"), "runner.os == 'Windows'")
                self.assertIn("core.autocrlf false", steps[configure_index]["run"])

    def test_migration_sql_is_pinned_to_lf(self):
        self.assertIn(
            "crates/aionui-db/migrations/*.sql text eol=lf",
            self.gitattributes_text.splitlines(),
        )

    def test_workflow_has_no_force_or_overwrite_archive_path(self):
        forbidden = ["--force", "--clobber", "Compress-Archive -Force", "Remove-Item dist"]
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, self.release_text)

    def test_manual_archives_refuse_existing_destinations(self):
        unix_package = self._step_script(
            "build", "Package binary (Unix)", self.manual
        )
        windows_package = self._step_script(
            "build", "Package binary (Windows)", self.manual
        )
        unix_guard = 'test ! -e "dist/${ARCHIVE}"'
        windows_guard = "Test-Path -LiteralPath $archivePath"
        self.assertIn(unix_guard, unix_package)
        self.assertIn(windows_guard, windows_package)
        self.assertIn(
            'throw "Refusing to overwrite existing archive ${archivePath}"',
            windows_package,
        )
        self.assertLess(
            unix_package.index(unix_guard), unix_package.index("tar -C work/bundle")
        )
        self.assertLess(
            windows_package.index(windows_guard),
            windows_package.index("Compress-Archive"),
        )
        self.assertNotIn("-Force", unix_package)
        self.assertNotIn("-Force", windows_package)
        self.assertNotRegex(unix_package, r"(?m)^\s*(rm|unlink)\b")
        self.assertNotIn("Remove-Item", windows_package)

    def test_release_actions_are_pinned_to_full_commit_shas(self):
        action_refs = self._external_action_refs(self.release)
        self.assertTrue(action_refs)
        for action_ref in action_refs:
            with self.subTest(action_ref=action_ref):
                self.assertRegex(action_ref, r"^[^@]+@[0-9a-f]{40}$")

    def test_manual_actions_are_pinned_to_the_reviewed_release_shas(self):
        release_refs = self._action_refs_by_name(self.release)
        manual_refs = self._action_refs_by_name(self.manual)
        self.assertTrue(manual_refs)
        for action_name, refs in manual_refs.items():
            with self.subTest(action_name=action_name):
                self.assertIn(action_name, release_refs)
                self.assertEqual(refs, release_refs[action_name])
                for action_ref in refs:
                    self.assertRegex(action_ref, r"^[^@]+@[0-9a-f]{40}$")

    @staticmethod
    def _job_script(name, workflow=None):
        workflow = workflow or ReleaseWorkflowContractTests.release
        job = workflow["jobs"][name]
        return "\n".join(str(step.get("run", "")) for step in job.get("steps", []))

    @staticmethod
    def _step_script(job_name, step_name, workflow):
        steps = workflow["jobs"][job_name]["steps"]
        return next(str(step.get("run", "")) for step in steps if step.get("name") == step_name)

    @staticmethod
    def _external_action_refs(workflow):
        return [
            step["uses"]
            for job in workflow["jobs"].values()
            for step in job.get("steps", [])
            if "uses" in step and not step["uses"].startswith("./")
        ]

    @classmethod
    def _action_refs_by_name(cls, workflow):
        refs = {}
        for action_ref in cls._external_action_refs(workflow):
            action_name = action_ref.split("@", 1)[0]
            refs.setdefault(action_name, set()).add(action_ref)
        return refs


if __name__ == "__main__":
    unittest.main()
