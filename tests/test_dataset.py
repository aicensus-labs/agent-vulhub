"""Agent-PoC dataset manifests include only validated accepted samples."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from runner.dataset import build_agent_manifest
from runner.protocol import write_json, write_metadata


class AgentDatasetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / "environments" / "sample" / "CVE-2099-99999"
        (self.directory / "evidence").mkdir(parents=True)
        (self.directory / "metadata.toml").write_text("\n")
        self.metadata = {
            "id": "sample/CVE-2099-99999",
            "verification": {
                "mechanism": {"status": "passed", "evidence": ["evidence/mechanism.json"]},
                "agent_poc": {
                    "adapter_status": "accepted",
                    "candidate_format": "command",
                    "task_sha256": "a" * 64,
                    "task_description_review": {"sha256": "b" * 64},
                    "verified_at": "2026-10-11T00:00:00Z",
                    "evidence": [
                        "evidence/adapter-review.md",
                        "evidence/positive.json",
                        "evidence/negative.json",
                    ],
                },
            },
        }
        write_metadata(self.directory / "metadata.toml", self.metadata)
        (self.directory / "evidence/adapter-review.md").write_text("Reviewed controls.\n")
        write_json(self.directory / "evidence/mechanism.json", {"layer": "mechanism"})
        write_json(self.directory / "evidence/positive.json", {"adapter_control_role": "positive"})
        write_json(self.directory / "evidence/negative.json", {"adapter_control_role": "negative"})
        self.entries = [{"id": self.metadata["id"], "path": "environments/sample/CVE-2099-99999"}]

    def test_manifest_binds_accepted_controls_and_current_fingerprints(self):
        with patch("runner.dataset.validate_adapter_admission"), \
                patch("runner.dataset.runner_fingerprint", return_value="c" * 64), \
                patch("runner.dataset.fingerprint", return_value="d" * 64):
            manifest = build_agent_manifest(self.root, self.entries)

        self.assertEqual(manifest["sample_count"], 1)
        sample = manifest["samples"][0]
        self.assertEqual(sample["task_sha256"], "a" * 64)
        self.assertEqual(sample["environment_fingerprint"], "d" * 64)
        self.assertEqual(sample["runner_fingerprint"], "c" * 64)
        self.assertEqual(set(sample["adapter_controls"]), {"positive", "negative"})

    def test_manifest_excludes_nonaccepted_samples(self):
        self.metadata["verification"]["agent_poc"]["adapter_status"] = "not_run"
        write_metadata(self.directory / "metadata.toml", self.metadata)
        with patch("runner.dataset.validate_adapter_admission") as validate, \
                patch("runner.dataset.runner_fingerprint", return_value="c" * 64):
            manifest = build_agent_manifest(self.root, self.entries)

        validate.assert_not_called()
        self.assertEqual(manifest["sample_count"], 0)
        self.assertEqual(manifest["samples"], [])


if __name__ == "__main__":
    unittest.main()
