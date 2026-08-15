import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


GENERATOR_PATH = Path(__file__).with_name("generate-lineage.py")
SPEC = importlib.util.spec_from_file_location("generate_lineage", GENERATOR_PATH)
generate_lineage = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = generate_lineage
SPEC.loader.exec_module(generate_lineage)


class GenerateLineageTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.migrations = Path(self.tempdir.name)

    def tearDown(self):
        self.tempdir.cleanup()

    def write_migration(self, filename, content):
        (self.migrations / filename).write_bytes(content)

    def test_orders_entries_by_numeric_version_and_derives_descriptions(self):
        self.write_migration("002_second_step.sql", b"SELECT 2;\n")
        self.write_migration("001_first_step.sql", b"SELECT 1;\n")

        document = generate_lineage.build_lineage(self.migrations)

        self.assertEqual([entry["version"] for entry in document["entries"]], [1, 2])
        self.assertEqual(
            [entry["description"] for entry in document["entries"]],
            ["first step", "second step"],
        )
        self.assertEqual(
            [entry["filename"] for entry in document["entries"]],
            ["001_first_step.sql", "002_second_step.sql"],
        )

    def test_checksum_uses_exact_raw_sql_bytes(self):
        self.write_migration("001_first.sql", b"SELECT 1;\n")
        first = generate_lineage.build_lineage(self.migrations)["entries"][0]["checksum"]

        self.write_migration("001_first.sql", b"SELECT 1;\r\n")
        second = generate_lineage.build_lineage(self.migrations)["entries"][0]["checksum"]

        self.assertEqual(first, hashlib.sha384(b"SELECT 1;\n").hexdigest())
        self.assertEqual(second, hashlib.sha384(b"SELECT 1;\r\n").hexdigest())
        self.assertNotEqual(first, second)

    def test_fingerprint_is_sha256_of_compact_ordered_entries_json(self):
        self.write_migration("001_first.sql", b"SELECT 1;\n")
        self.write_migration("002_second.sql", b"SELECT 2;\n")
        document = generate_lineage.build_lineage(self.migrations)

        compact_entries = json.dumps(
            document["entries"],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

        self.assertEqual(document["fingerprint"], hashlib.sha256(compact_entries).hexdigest())

    def test_rejects_duplicate_numeric_versions(self):
        self.write_migration("001_first.sql", b"SELECT 1;\n")
        self.write_migration("001_duplicate.sql", b"SELECT 2;\n")

        with self.assertRaisesRegex(generate_lineage.LineageError, "duplicate migration version 1"):
            generate_lineage.build_lineage(self.migrations)

    def test_rejects_malformed_sql_filename(self):
        self.write_migration("1_not_zero_padded.sql", b"SELECT 1;\n")

        with self.assertRaisesRegex(generate_lineage.LineageError, "malformed migration filename"):
            generate_lineage.build_lineage(self.migrations)

    def test_rejects_missing_version_in_sequence(self):
        self.write_migration("001_first.sql", b"SELECT 1;\n")
        self.write_migration("003_third.sql", b"SELECT 3;\n")

        with self.assertRaisesRegex(generate_lineage.LineageError, "missing migration version 2"):
            generate_lineage.build_lineage(self.migrations)

    def test_rejects_version_zero_outside_001_to_latest_sequence(self):
        self.write_migration("000_before_sequence.sql", b"SELECT 0;\n")
        self.write_migration("001_first.sql", b"SELECT 1;\n")

        with self.assertRaisesRegex(generate_lineage.LineageError, "migration versions must start at 1"):
            generate_lineage.build_lineage(self.migrations)

    def test_repeated_builds_serialize_to_identical_bytes(self):
        self.write_migration("001_first.sql", b"SELECT 1;\n")
        self.write_migration("002_second.sql", b"SELECT 2;\n")

        first = generate_lineage.serialize_lineage(generate_lineage.build_lineage(self.migrations))
        second = generate_lineage.serialize_lineage(generate_lineage.build_lineage(self.migrations))

        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
