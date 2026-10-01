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

    def test_passed_evidence_must_exist_and_match_the_tree(self):
        """A draft may claim `passed`; check must still reject stale or missing evidence."""
        target = scaffold(self.root, "synthetic-agent", "CVE-2099-99999")
        metadata_path = target / "metadata.toml"
        data = read_toml(metadata_path)
        relative = "results/synthetic-agent/CVE-2099-99999/20990101T000000Z-000000000000/report.json"
        report_path = self.root / relative
        report_path.parent.mkdir(parents=True)
        from runner.protocol import fingerprint, write_json
        write_json(report_path, {"environment_id": data["id"],
                                 "fingerprint": fingerprint(self.root, target, data)})
        metadata_path.write_text(metadata_path.read_text().replace(
            'evidence = []\nnotes = ""',
            f'evidence = ["{relative}"]\nnotes = ""', 1).replace(
            'verified_at = ""', 'verified_at = "2099-01-01T00:00:00+00:00"', 1).replace(
            '[verification.mechanism]\nstatus = "not_run"',
            '[verification.mechanism]\nstatus = "passed"', 1))
        check(self.root)

        write_json(report_path, {"environment_id": data["id"], "fingerprint": "0" * 64})
        with self.assertRaisesRegex(RegistryError, "stale for the current inputs"):
            check(self.root)

        report_path.unlink()
        with self.assertRaisesRegex(RegistryError, "missing evidence"):
            check(self.root)

    def test_unfinished_template_cannot_be_ready(self):
        target = scaffold(self.root, "synthetic-agent", "CVE-2099-99999")
        data = read_toml(target / "metadata.toml")
        data["lifecycle"] = "ready"
        with self.assertRaisesRegex(RegistryError, "title and advisories"):
            validate_metadata(data, data["id"])

    def test_verifier_change_does_not_invalidate_image_binding(self):
        """Host-side runner code must not participate in the build input binding.

        Otherwise every verifier edit would stale published image digests and force
        a rebuild and republish of every environment.
        """
        from runner.protocol import fingerprint, input_binding
        target = scaffold(self.root, "synthetic-agent", "CVE-2099-99999")
        data = read_toml(target / "metadata.toml")
        before_binding = input_binding(self.root, target, data)
        before_fingerprint = fingerprint(self.root, target, data)

        # Simulate editing a host-side runner file inside this synthetic root.
        runner = self.root / "runner"
        runner.mkdir(exist_ok=True)
        (runner / "probe.py").write_text("# verifier change\n")
        self.assertEqual(input_binding(self.root, target, data), before_binding)
        self.assertNotEqual(fingerprint(self.root, target, data), before_fingerprint)

        # A real build input must move both hashes.
        (target / "Dockerfile").write_text((target / "Dockerfile").read_text() + "\n")
        self.assertNotEqual(input_binding(self.root, target, data), before_binding)

    def test_severity_must_use_the_declared_vocabulary(self):
        target = scaffold(self.root, "synthetic-agent", "CVE-2099-99999")
        data = read_toml(target / "metadata.toml")
        self.assertEqual(data["severity"], "UNKNOWN")
        validate_metadata(data, data["id"])
        for accepted in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"):
            data["severity"] = accepted
            validate_metadata(data, data["id"])
        for rejected in ("high", "Severe", "", None, 9.8):
            data["severity"] = rejected
            with self.assertRaisesRegex(RegistryError, "severity must be one of"):
                validate_metadata(data, data["id"])

    def test_ready_accepts_an_unrated_advisory(self):
        """An advisory no source ever rated must not be permanently unpromotable."""
        target = scaffold(self.root, "synthetic-agent", "CVE-2099-99999")
        data = read_toml(target / "metadata.toml")
        data["lifecycle"] = "ready"
        data["title"] = "Synthetic boundary bypass"
        data["advisories"] = ["https://example.invalid/advisory"]
        data["agent_specificity"] = "agent_unique"
        for variant in ("vulnerable", "patched"):
            data[variant]["version"] = "1.0.0"
            data[variant]["source_url"] = f"https://example.invalid/{variant}"
            data[variant]["commit"] = "0" * 40
            data[variant]["image"] = "ghcr.io/example/synthetic@sha256:" + "0" * 64
        data["severity"] = "UNKNOWN"
        validate_metadata(data, data["id"])
        data["severity"] = "HIGH"
        validate_metadata(data, data["id"])

    def _ready_candidate(self):
        """A ready environment with pinned commits and no published images (ADR-0004)."""
        target = scaffold(self.root, "synthetic-agent", "CVE-2099-99999")
        data = read_toml(target / "metadata.toml")
        data["lifecycle"] = "ready"
        data["title"] = "Synthetic boundary bypass"
        data["advisories"] = ["https://example.invalid/advisory"]
        data["agent_specificity"] = "agent_unique"
        for variant in ("vulnerable", "patched"):
            data[variant]["version"] = "1.0.0"
            data[variant]["source_url"] = f"https://example.invalid/{variant}"
            data[variant]["commit"] = "0" * 40
            data[variant]["image"] = ""
        return data

    def test_ready_accepts_pinned_inputs_without_published_images(self):
        """Publishing is optional; pinned build inputs alone must not block ready."""
        data = self._ready_candidate()
        validate_metadata(data, data["id"])

    def test_ready_rejects_a_half_published_environment(self):
        """One variant with a digest and one without is reproducible by neither path."""
        data = self._ready_candidate()
        data["vulnerable"]["image"] = "ghcr.io/example/synthetic@sha256:" + "0" * 64
        with self.assertRaisesRegex(RegistryError, "the other variant does not"):
            validate_metadata(data, data["id"])

    def test_ready_rejects_a_floating_tag_as_an_image(self):
        data = self._ready_candidate()
        for variant in ("vulnerable", "patched"):
            data[variant]["image"] = "ghcr.io/example/synthetic:vulnerable-latest"
        with self.assertRaisesRegex(RegistryError, "immutable digest"):
            validate_metadata(data, data["id"])

    def test_ready_accepts_two_published_digests(self):
        data = self._ready_candidate()
        for variant in ("vulnerable", "patched"):
            data[variant]["image"] = "ghcr.io/example/synthetic@sha256:" + "0" * 64
        validate_metadata(data, data["id"])

    def test_execution_path_matches_the_real_reproduce_import_closure(self):
        """The hashed verifier set must equal what ``reproduce`` actually loads.

        A module added to the reproduce path but missing from EXECUTION_PATH would
        let a verifier change keep stale evidence valid, so derive the closure
        instead of trusting the constant.
        """
        import subprocess
        import sys

        from runner.protocol import EXECUTION_PATH
        code = ("import runner.runtime, runner.build, runner.lifecycle;"
                "import sys;print('\\n'.join(sorted(m for m in sys.modules"
                " if m.startswith('runner.') and not m.endswith('__init__'))))")
        loaded = subprocess.run([sys.executable, "-c", code], capture_output=True,
                                text=True, cwd=ROOT, check=True).stdout.split()
        expected = {f"runner.{name[:-3]}" for name in EXECUTION_PATH if name.endswith(".py")}
        # lab_support.py is copied into the image rather than imported on the host.
        self.assertEqual(expected - {"runner.lab_support"}, set(loaded))
        self.assertIn("lab_support.py", EXECUTION_PATH)

    def test_dispatch_only_modules_are_not_in_the_fingerprint(self):
        """Editing cli.py or prune.py must not stale every report in the registry."""
        from runner.protocol import fingerprint, input_binding

        target = scaffold(self.root, "synthetic-agent", "CVE-2099-99999")
        data = read_toml(target / "metadata.toml")
        runner = self.root / "runner"
        runner.mkdir(exist_ok=True)
        before = fingerprint(self.root, target, data)
        binding = input_binding(self.root, target, data)
        for name in ("cli.py", "prune.py"):
            (runner / name).write_text("# dispatch only\n")
        self.assertEqual(fingerprint(self.root, target, data), before)
        self.assertEqual(input_binding(self.root, target, data), binding)
        # A real verifier module must still move the fingerprint.
        (runner / "runtime.py").write_text("# verifier change\n")
        self.assertNotEqual(fingerprint(self.root, target, data), before)

    def test_prose_in_the_contract_doc_does_not_stale_evidence(self):
        """Editing documentation must not invalidate every report.

        `docs/environment-contract.md` is prose for recipe authors; it is not code
        that runs. Hashing it meant that fixing one sentence invalidated the whole
        registry and forced a re-stamp of every environment.
        """
        from runner.protocol import fingerprint

        target = scaffold(self.root, "synthetic-agent", "CVE-2099-99999")
        data = read_toml(target / "metadata.toml")
        docs = self.root / "docs"
        docs.mkdir(exist_ok=True)
        contract = docs / "environment-contract.md"
        contract.write_text("original prose\n")
        before = fingerprint(self.root, target, data)
        contract.write_text("corrected prose\n")
        self.assertEqual(fingerprint(self.root, target, data), before)


    def test_malformed_stage_result_is_rejected_not_ignored(self):
        """An unparsable result file must fail the check, not read as not_run.

        ``result_status`` extracts ``status`` with a regex, so a file that is not
        valid TOML silently degrades to "this stage never ran" and the batch driver
        never sees the problem. Three such files existed in the registry.
        """
        from runner.cli import _check_research_results

        target = scaffold(self.root, "synthetic-agent", "CVE-2099-99999")
        research = self.root / "research" / "synthetic-agent" / "CVE-2099-99999"
        research.mkdir(parents=True)
        # An unescaped \s is not a valid TOML escape; this exact shape hid a real
        # generate result from the tracker.
        (research / "generate-res.toml").write_text(
            'status = "continue"\nstage = "generate"\n'
            'environment_id = "synthetic-agent/CVE-2099-99999"\n'
            'reason = "regex /\\bimport\\s*\\(/ denylist"\n'
            'evidence = ["x"]\nupdated_at = "t"\n', encoding="utf-8")
        with self.assertRaisesRegex(RegistryError, "not valid TOML"):
            _check_research_results(self.root, "synthetic-agent/CVE-2099-99999")

        # A terse error record is legitimate: a stage can fail before it can say much.
        (research / "generate-res.toml").write_text(
            'status = "error"\nstage = "generate"\n'
            'environment_id = "synthetic-agent/CVE-2099-99999"\nreason = "not scaffolded"\n',
            encoding="utf-8")
        _check_research_results(self.root, "synthetic-agent/CVE-2099-99999")

        # status=continue must carry the fields the tracker later relies on.
        (research / "generate-res.toml").write_text(
            'status = "continue"\nstage = "generate"\n'
            'environment_id = "synthetic-agent/CVE-2099-99999"\nreason = "r"\n',
            encoding="utf-8")
        with self.assertRaisesRegex(RegistryError, "missing"):
            _check_research_results(self.root, "synthetic-agent/CVE-2099-99999")

        # The stage must match the file it is recorded in.
        (research / "generate-res.toml").write_text(
            'status = "continue"\nstage = "solve"\n'
            'environment_id = "synthetic-agent/CVE-2099-99999"\nreason = "r"\n'
            'evidence = ["x"]\nupdated_at = "t"\n', encoding="utf-8")
        with self.assertRaisesRegex(RegistryError, "declares stage"):
            _check_research_results(self.root, "synthetic-agent/CVE-2099-99999")

        # A scratch file that is not a stage result is out of scope.
        (research / "generate-res.toml").unlink()
        (research / "go-inputs.toml").write_text('  { name = "x" },\n', encoding="utf-8")
        _check_research_results(self.root, "synthetic-agent/CVE-2099-99999")


if __name__ == "__main__":
    unittest.main()
