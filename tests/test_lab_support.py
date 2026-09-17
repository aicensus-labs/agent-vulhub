"""Shared lab evidence helpers are tested without starting an environment."""

import json
from pathlib import Path
import tempfile
import unittest

from runner.lab_support import record, verify


class LabSupportTests(unittest.TestCase):
    def test_record_and_verify_use_versioned_facts_and_target_readiness(self):
        context = {
            "schema_version": 1,
            "run_id": "helper-test",
            "case_id": "01-vulnerable-attack",
            "variant": "vulnerable",
            "scenario": "attack",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context_path = root / "context.json"
            output = root / "evidence"
            context_path.write_text(json.dumps(context), encoding="utf-8")

            self.assertEqual(
                record(
                    context,
                    output,
                    {"execution_status": "completed", "target_ready": True},
                    {"effect.txt": "synthetic effect\n"},
                ),
                0,
            )
            facts = json.loads((output / "facts.json").read_text(encoding="utf-8"))
            self.assertEqual(facts["schema_version"], 1)

            def check_effect(_context, observation, paths):
                return (
                    "vulnerable_effect_observed",
                    observation["target_ready"] and paths["effect.txt"].read_text() == "synthetic effect\n",
                    "the synthetic effect is present",
                    "present",
                )

            self.assertEqual(verify(context_path, output, check_effect), 0)
            verdict = json.loads((output / "verdict.json").read_text(encoding="utf-8"))
            self.assertEqual(verdict["outcome"], "passed")

            self.assertEqual(
                record(
                    context,
                    output / "not-run",
                    {"execution_status": "not_run", "target_ready": False},
                ),
                2,
            )


if __name__ == "__main__":
    unittest.main()
