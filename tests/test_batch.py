"""Batch driver: queueing, progress and gate selection. No network, no containers."""

from pathlib import Path
import shutil
import tempfile
import unittest

from runner import batch, factory
from runner.cli import ROOT, scaffold


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "environments").mkdir()
        (self.root / "environments.toml").write_text("schema_version = 1\nenvironments = []\n")
        shutil.copytree(ROOT / "templates", self.root / "templates")
        self.directory = scaffold(self.root, "demo", "CVE-2099-99999")
        self.environment = "demo/CVE-2099-99999"
        self.research = self.root / "research" / "demo" / "CVE-2099-99999"

    def write(self, relative: str, text: str = "synthetic\n") -> Path:
        path = self.directory / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def write_research(self, name: str, status: str = "continue") -> None:
        self.research.mkdir(parents=True, exist_ok=True)
        (self.research / name).write_text(
            f'status = "{status}"\nstage = "x"\nenvironment_id = "{self.environment}"\n'
            'reason = "synthetic"\nevidence = []\n', encoding="utf-8")

    def test_next_stage_starts_at_analyze_and_advances(self):
        self.assertEqual(batch.next_stage(self.root, self.environment), "analyze")
        state = factory.read_state(self.root, self.environment)
        state["stages"]["analyze"] = "passed"
        factory.write_state(self.root, self.environment, state)
        self.assertEqual(batch.next_stage(self.root, self.environment), "generate")

    def test_next_stage_is_none_once_every_stage_passed(self):
        state = factory.read_state(self.root, self.environment)
        for stage_id in batch.STAGE_IDS:
            state["stages"][stage_id] = "passed"
        factory.write_state(self.root, self.environment, state)
        self.assertIsNone(batch.next_stage(self.root, self.environment))
        self.assertTrue(batch.environment_status(self.root, self.environment)["complete"])

    def test_queue_writes_the_brief_for_the_next_stage(self):
        queued = batch.queue(self.root, [self.environment], batch_id="wave-001")
        entry = queued["entries"][0]
        self.assertEqual(entry["next_stage"], "analyze")
        brief = self.root / entry["brief"]
        self.assertTrue(brief.is_file())
        self.assertIn("Analyzer", brief.read_text(encoding="utf-8"))

    def test_queue_is_readable_from_disk(self):
        batch.queue(self.root, [self.environment], batch_id="wave-001")
        stored = batch.read_batch(self.root, "wave-001")
        self.assertEqual(stored["environment_ids"], [self.environment])

    def test_unknown_batch_is_rejected(self):
        with self.assertRaisesRegex(factory.FactoryError, "Unknown batch"):
            batch.read_batch(self.root, "nope")

    def test_agent_stage_without_artifacts_waits_instead_of_failing(self):
        """An agent stage must not be marked passed just because the batch ran."""
        batch.queue(self.root, [self.environment], batch_id="wave-001")
        report = batch.run_batch(self.root, "wave-001", execute=True)
        outcome = report["outcomes"][0]
        self.assertEqual(outcome["outcome"], "awaiting-agent")
        self.assertEqual(report["attempted"], 0)
        self.assertEqual(batch.next_stage(self.root, self.environment), "analyze")

    def test_analyze_runs_once_its_artifacts_exist(self):
        self.write_research("public.md", "# synthetic\n")
        self.write_research("analyze-res.toml")
        batch.queue(self.root, [self.environment], batch_id="wave-001")
        report = batch.run_batch(self.root, "wave-001", execute=True)
        self.assertEqual(report["outcomes"][0]["outcome"], "failed")
        self.assertEqual(report["attempted"], 1)

    def test_docker_stage_is_not_executed_without_the_flag(self):
        """A dry run must never start a container."""
        for stage_id in ("analyze", "generate", "build"):
            state = factory.read_state(self.root, self.environment)
            state["stages"][stage_id] = "passed"
            factory.write_state(self.root, self.environment, state)
        batch.queue(self.root, [self.environment], batch_id="wave-001")
        report = batch.run_batch(self.root, "wave-001", execute=False)
        self.assertEqual(report["outcomes"][0]["outcome"], "awaiting-execute")
        self.assertEqual(report["attempted"], 0)

    def test_stage_filter_skips_unselected_stages(self):
        batch.queue(self.root, [self.environment], batch_id="wave-001")
        report = batch.run_batch(self.root, "wave-001", stages=["check"], execute=True)
        self.assertEqual(report["outcomes"][0]["outcome"], "skipped")
        self.assertEqual(report["attempted"], 0)

    def test_limit_caps_how_many_environments_are_attempted(self):
        self.write_research("public.md", "# synthetic\n")
        self.write_research("analyze-res.toml")
        batch.queue(self.root, [self.environment], batch_id="wave-001")
        report = batch.run_batch(self.root, "wave-001", execute=True, limit=0)
        self.assertEqual(report["attempted"], 0)

    def test_progress_counts_completed_and_awaiting(self):
        batch.queue(self.root, [self.environment], batch_id="wave-001")
        report = batch.progress(self.root, "wave-001")
        self.assertEqual(report["environments"], 1)
        self.assertEqual(report["complete"], 0)
        self.assertEqual(report["awaiting_stage"], {"analyze": 1})

    def test_progress_reports_a_blocked_stage_with_its_problems(self):
        self.write_research("public.md", "# synthetic\n")
        self.write_research("analyze-res.toml")
        batch.queue(self.root, [self.environment], batch_id="wave-001")
        batch.run_batch(self.root, "wave-001", execute=True)
        report = batch.progress(self.root, "wave-001")
        self.assertEqual(len(report["blocked"]), 1)
        self.assertEqual(report["blocked"][0]["stage"], "analyze")

    def test_unknown_stage_is_rejected(self):
        batch.queue(self.root, [self.environment], batch_id="wave-001")
        with self.assertRaisesRegex(factory.FactoryError, "Unknown stage"):
            batch.run_batch(self.root, "wave-001", stages=["nope"])

    def test_agent_stage_classification_matches_the_stage_table(self):
        """Every stage is either agent-authored or mechanical; none may be unclassified."""
        self.assertEqual(set(batch.AGENT_STAGES) | set(batch.AUTOMATIC_STAGES),
                         set(batch.STAGE_IDS))
        self.assertEqual(set(batch.AGENT_STAGES) & set(batch.AUTOMATIC_STAGES), set())

    def test_unguarded_metadata_read_in_a_runtime_script_is_rejected(self):
        """metadata.toml never reaches the image, so reading it must fail the gate.

        The Dockerfile copies only inputs/, reproduce.py, verify.py, end_to_end.py,
        fixtures/ and lab_support.py into /lab. A run that reads metadata.toml dies
        with FileNotFoundError, which the static build gate cannot observe.
        """
        self.write("reproduce.py", 'from pathlib import Path\n'
                                   'ENVIRONMENT_DIR = Path(__file__).resolve().parent\n'
                                   'def f():\n'
                                   '    return _read_toml(ENVIRONMENT_DIR / "metadata.toml")\n')
        problems = factory._in_container_reference_problems(self.directory)
        self.assertEqual(len(problems), 1)
        self.assertIn("reproduce.py reads metadata.toml", problems[0])

    def test_guarded_metadata_read_and_prose_are_accepted(self):
        """A defensive read degrades to inlined constants; prose is not a defect."""
        self.write("reproduce.py",
                   '"""Pinned as declared in metadata.toml; values are inlined below."""\n'
                   'from pathlib import Path\n'
                   'PINNED = {"vulnerable": "1.0.0", "patched": "1.0.1"}\n'
                   'def declared():\n'
                   '    path = Path(__file__).with_name("metadata.toml")\n'
                   '    if not path.is_file():\n'
                   '        return {}\n'
                   '    return path.open("rb")\n')
        self.assertEqual(factory._in_container_reference_problems(self.directory), [])

    def test_variant_guarded_environment_variable_is_rejected(self):
        """A revision must not be handed its own environment.

        The defect this catches: the patched arm alone was given
        ``COWORK_REQUIRE_AUTH=true``, an explicitly-set value that selects a branch
        bypassing the validator under test, so the observed refusal came from the
        harness instead of from the pinned fix. The two revisions must run in the
        same environment so that only the fix explains a behavioural difference.
        """
        self.write("reproduce.py",
                   'def write_bootstrap_env(home, variant):\n'
                   '    lines = ["ANTON_ROUTER_MODEL=stub"]\n'
                   '    if variant == "patched":\n'
                   '        lines.append("COWORK_REQUIRE_AUTH=true")\n'
                   '    (home / ".env").write_text("\\n".join(lines))\n')
        problems = factory._variant_environment_problems(self.directory, {})
        self.assertEqual(len(problems), 1)
        self.assertIn("COWORK_REQUIRE_AUTH", problems[0])
        self.assertIn("variant guard", problems[0])

    def test_variant_guarded_environment_write_in_any_form_is_rejected(self):
        """Also catches os.environ and mapping writes, not just appended literals."""
        for body in (
            '    if variant == "patched":\n'
            '        os.environ["GUARD_ENABLED"] = "1"\n',
            '    if variant == "patched":\n'
            '        service_env["GUARD_ENABLED"] = "1"\n',
            '    os.putenv("GUARD_ENABLED", "1") if variant == "patched" else None\n',
        ):
            with self.subTest(body=body):
                self.write("reproduce.py", "import os\n\ndef run(variant, service_env):\n" + body)
                problems = factory._variant_environment_problems(self.directory, {})
                self.assertGreaterEqual(len(problems), 1)

    def test_artifact_selection_under_a_variant_guard_is_accepted(self):
        """Choosing the pinned artifact *is* the variant and must stay allowed."""
        self.write("reproduce.py",
                   'def resolve(variant, source_root, chain_kwargs):\n'
                   '    if variant == "patched":\n'
                   '        source = source_root / "patched"\n'
                   '        chain_kwargs["limit_to_domains"] = [LEGIT_BASE]\n'
                   '    else:\n'
                   '        source = source_root / "vulnerable"\n'
                   '    kwargs["llm" if variant == "vulnerable" else "model"] = completion\n'
                   '    return source\n')
        self.assertEqual(factory._variant_environment_problems(self.directory, {}), [])

    def test_documented_variant_environment_exception_is_honoured(self):
        """A revision that genuinely needs different config can declare it."""
        source = ('def write_bootstrap_env(home, variant):\n'
                  '    lines = []\n'
                  '    if variant == "patched":\n'
                  '        lines.append("COWORK_REQUIRE_AUTH=true")\n')
        self.write("reproduce.py", source)
        self.assertEqual(len(factory._variant_environment_problems(self.directory, {})), 1)
        for exceptions in (["COWORK_REQUIRE_AUTH"],
                           [{"name": "COWORK_REQUIRE_AUTH", "reason": "documented"}]):
            with self.subTest(exceptions=exceptions):
                metadata = {"runtime": {"variant_env_exceptions": exceptions}}
                self.assertEqual(factory._variant_environment_problems(self.directory, metadata), [])
        # A declaration for some other variable does not excuse this one.
        metadata = {"runtime": {"variant_env_exceptions": ["SOMETHING_ELSE"]}}
        self.assertEqual(len(factory._variant_environment_problems(self.directory, metadata)), 1)

    def test_generate_gate_reports_a_variant_guarded_environment(self):
        """The check is wired into the generate gate, not merely available."""
        self.write("reproduce.py",
                   'def write_bootstrap_env(home, variant):\n'
                   '    lines = []\n'
                   '    if variant == "patched":\n'
                   '        lines.append("COWORK_REQUIRE_AUTH=true")\n')
        self.write_research("generate-res.toml")
        metadata = factory.environment_directory(self.root, self.environment) / "metadata.toml"
        metadata.write_text('schema_version = 1\nenvironment_id = "%s"\n' % self.environment,
                            encoding="utf-8")
        problems = factory._gate_generate(self.root, self.environment, self.directory, self.research)
        self.assertTrue(any("COWORK_REQUIRE_AUTH" in problem for problem in problems), problems)


if __name__ == "__main__":
    unittest.main()
