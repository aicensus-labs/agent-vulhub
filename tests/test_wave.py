"""Rebuild-wave selection is static and never starts Docker."""

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from runner.cli import ROOT, read_toml, scaffold
from runner.protocol import fingerprint, runner_fingerprint, write_metadata
from scripts.rebuild_wave import WaveError, select_batch


class RebuildWaveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "environments").mkdir()
        (self.root / "environments.toml").write_text("schema_version = 1\nenvironments = []\n")
        shutil.copytree(ROOT / "templates", self.root / "templates")
        shutil.copytree(ROOT / "runner", self.root / "runner")
        self.directory = scaffold(self.root, "synthetic", "CVE-2099-99999")
        self.environment_id = "synthetic/CVE-2099-99999"
        self.metadata_path = self.directory / "metadata.toml"
        self.metadata = read_toml(self.metadata_path)
        for variant in ("vulnerable", "patched"):
            self.metadata[variant]["commit"] = "a" * 40
        write_metadata(self.metadata_path, self.metadata)
        self.metadata = read_toml(self.metadata_path)
        self.manifest_path = self.root / "wave.json"
        self.write_manifest()

    def write_manifest(self, entries=None):
        if entries is None:
            entries = [{
                "environment_id": self.environment_id,
                "fingerprint": fingerprint(self.root, self.directory, self.metadata),
            }]
        self.manifest_path.write_text(json.dumps({
            "schema_version": 1,
            "wave_id": "test-wave",
            "selection": {
                "provenance": "source",
                "historical_layer": "mechanism",
                "historical_outcome": "passed",
                "minimum_rounds": 3,
            },
            "environments": entries,
        }), encoding="utf-8")

    def test_selects_registered_source_environment_with_matching_fingerprint(self):
        selected = select_batch(self.root, self.manifest_path, offset=0, limit=1)
        self.assertEqual(selected, [{
            "environment_id": self.environment_id,
            "artifact_slug": "synthetic--CVE-2099-99999",
        }])

    def test_rejects_changed_experiment_inputs(self):
        (self.directory / "reproduce.py").write_text("# changed after wave generation\n")
        with self.assertRaisesRegex(WaveError, "fingerprint differs"):
            select_batch(self.root, self.manifest_path, offset=0, limit=1)

    def test_rejects_duplicate_manifest_entries(self):
        entry = json.loads(self.manifest_path.read_text())["environments"][0]
        self.write_manifest([entry, entry])
        with self.assertRaisesRegex(WaveError, "Duplicate environment"):
            select_batch(self.root, self.manifest_path, offset=0, limit=2)

    def test_rejects_unbounded_batch_size(self):
        with self.assertRaisesRegex(WaveError, "between 1 and 100"):
            select_batch(self.root, self.manifest_path, offset=0, limit=101)

    def test_selector_changes_do_not_change_execution_runner_fingerprint(self):
        before = runner_fingerprint(self.root)
        selector = self.root / "scripts" / "rebuild_wave.py"
        selector.parent.mkdir()
        selector.write_text("# dispatch-only selector\n", encoding="utf-8")
        self.assertEqual(runner_fingerprint(self.root), before)

    def test_passed_status_without_current_report_is_selected_for_rebuild(self):
        self.metadata["verification"]["mechanism"].update(status="passed", evidence=[])
        write_metadata(self.metadata_path, self.metadata)
        selected = select_batch(self.root, self.manifest_path, offset=0, limit=1)
        self.assertEqual(len(selected), 1)


if __name__ == "__main__":
    unittest.main()
