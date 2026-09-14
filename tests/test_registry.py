"""Registry tooling tests use synthetic IDs in temporary directories only."""

from pathlib import Path
import shutil
import tempfile
import unittest

from runner.cli import ROOT, RegistryError, check, scaffold, validate_metadata, read_toml


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "environments").mkdir()
        (self.root / "environments.toml").write_text("schema_version = 1\nenvironments = []\n")
        shutil.copytree(ROOT / "templates", self.root / "templates")

    def test_empty_registry_is_valid(self):
        self.assertEqual(check(self.root), [])

    def test_new_environment_is_registered_as_unverified_draft(self):
        target = scaffold(self.root, "synthetic-agent", "CVE-2099-99999")
        self.assertEqual(len(check(self.root)), 1)
        data = read_toml(target / "metadata.toml")
        self.assertEqual(data["lifecycle"], "draft")
        self.assertEqual(data["verification"]["mechanism"]["status"], "not_run")
        self.assertNotIn("{{CVE}}", (target / "reproduce.py").read_text())

    def test_duplicate_does_not_overwrite_environment(self):
        target = scaffold(self.root, "synthetic-agent", "CVE-2099-99999")
        (target / "reproduce.py").write_text("preserve this work\n")
        with self.assertRaises(RegistryError):
            scaffold(self.root, "synthetic-agent", "CVE-2099-99999")
        self.assertEqual((target / "reproduce.py").read_text(), "preserve this work\n")

    def test_path_traversal_and_invalid_cve_are_rejected(self):
        for product, identifier in [("../outside", "CVE-2099-99999"), ("agent", "not-a-cve")]:
            with self.subTest(product=product, identifier=identifier), self.assertRaises(RegistryError):
                scaffold(self.root, product, identifier)
        self.assertEqual(check(self.root), [])

    def test_ghsa_environment_is_supported(self):
        target = scaffold(self.root, "synthetic-agent", "GHSA-2099-aaaa-bbbb")
        self.assertEqual(len(check(self.root)), 1)
        data = read_toml(target / "metadata.toml")
        self.assertEqual(data["id"], "synthetic-agent/GHSA-2099-aaaa-bbbb")
        self.assertEqual(data["ghsa"], "GHSA-2099-aaaa-bbbb")

    def test_missing_required_file_is_rejected(self):
        target = scaffold(self.root, "synthetic-agent", "CVE-2099-99999")
        (target / "verify.py").rename(target / "verify.missing")
        with self.assertRaisesRegex(RegistryError, "verify.py"):
            check(self.root)

    def test_unregistered_environment_is_rejected(self):
        scaffold(self.root, "synthetic-agent", "CVE-2099-99999")
        (self.root / "environments.toml").write_text("schema_version = 1\nenvironments = []\n")
        with self.assertRaisesRegex(RegistryError, "Unregistered"):
            check(self.root)

    def test_passed_claim_needs_evidence(self):
        target = scaffold(self.root, "synthetic-agent", "CVE-2099-99999")
        data = read_toml(target / "metadata.toml")
        data["verification"]["mechanism"]["status"] = "passed"
        with self.assertRaisesRegex(RegistryError, "date and evidence"):
            validate_metadata(data, data["id"])

    def test_unfinished_template_cannot_be_ready(self):
        target = scaffold(self.root, "synthetic-agent", "CVE-2099-99999")
        data = read_toml(target / "metadata.toml")
        data["lifecycle"] = "ready"
        with self.assertRaisesRegex(RegistryError, "title and advisories"):
            validate_metadata(data, data["id"])


if __name__ == "__main__":
    unittest.main()
