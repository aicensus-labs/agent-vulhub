"""Agent-PoC task and candidate validation tests do not start Docker."""

from pathlib import Path
import hashlib
import io
import json
import shutil
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import Mock

from runner.agent_poc import (AgentPocError, create_task, load_agent_metadata,
                              validate_candidate, validate_task)
from runner.cli import ROOT, read_toml, scaffold
from runner.runtime import _collect_candidate_facts


def archive_bytes(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, content in files.items():
            payload = content.encode()
            info = tarfile.TarInfo(f"upstream/{name}")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return stream.getvalue()


class AgentPocTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "environments").mkdir()
        (self.root / "environments.toml").write_text("schema_version = 1\nenvironments = []\n")
        shutil.copytree(ROOT / "templates", self.root / "templates")
        self.directory = scaffold(self.root, "synthetic", "CVE-2099-99999")
        self.metadata = read_toml(self.directory / "metadata.toml")
        self.metadata["description"] = "A synthetic description with a fixed source path."
        self.metadata["build"]["base_image"] = "python@sha256:" + "a" * 64
        vulnerable = archive_bytes({"README.md": "vulnerable source\n", "src/target.py": "return 'vulnerable'\n"})
        patched = archive_bytes({"README.md": "patched source\n", "src/target.py": "return 'patched'\n"})
        self.cache = self.root / ".cache/sha256"
        self.cache.mkdir(parents=True)
        inputs = []
        for name, payload in (("vulnerable.tar.gz", vulnerable), ("patched.tar.gz", patched)):
            checksum = hashlib.sha256(payload).hexdigest()
            (self.cache / checksum).write_bytes(payload)
            inputs.append({"name": name, "url": f"https://example.invalid/{name}", "sha256": checksum})
        self.metadata["build"]["inputs"] = inputs
        self.metadata["vulnerable"].update(commit="a" * 40, archive="vulnerable.tar.gz")
        self.metadata["patched"].update(commit="b" * 40, archive="patched.tar.gz")

    def test_level_one_task_contains_source_and_description_but_no_hidden_material(self):
        task_dir = create_task(self.root, self.directory, self.metadata, 1, self.root / "task", offline=True)
        task = validate_task(self.root, self.directory, task_dir, self.metadata["id"], self.metadata)
        self.assertEqual(task["difficulty"], 1)
        self.assertIn("vulnerable source", (task_dir / "source/README.md").read_text())
        self.assertIn("synthetic description", (task_dir / "description.md").read_text())
        self.assertFalse((task_dir / "patched").exists())
        self.assertFalse((task_dir / "verify.py").exists())
        task_text = (task_dir / "task.json").read_text()
        self.assertNotIn("patched.tar.gz", task_text)
        self.assertNotIn("b" * 40, task_text)

    def test_task_source_or_binding_tampering_is_rejected(self):
        task_dir = create_task(self.root, self.directory, self.metadata, 1, self.root / "task", offline=True)
        (task_dir / "source/src/target.py").write_text("tampered\n")
        with self.assertRaisesRegex(AgentPocError, "source hash"):
            validate_task(self.root, self.directory, task_dir, self.metadata["id"], self.metadata)

    def test_task_visible_material_tampering_is_rejected(self):
        task_dir = create_task(self.root, self.directory, self.metadata, 1, self.root / "task", offline=True)
        (task_dir / "description.md").write_text("tampered\n")
        with self.assertRaisesRegex(AgentPocError, "visible file inventory"):
            validate_task(self.root, self.directory, task_dir, self.metadata["id"], self.metadata)

    def test_task_source_must_match_the_trusted_vulnerable_archive(self):
        task_dir = create_task(self.root, self.directory, self.metadata, 1, self.root / "task", offline=True)
        source = task_dir / "source/src/target.py"
        source.write_text("replacement source\n")
        task = json.loads((task_dir / "task.json").read_text())
        entries = []
        for path in sorted(task_dir.rglob("*")):
            if path.is_file() and path.relative_to(task_dir).as_posix() != "task.json":
                entries.append({"path": path.relative_to(task_dir).as_posix(),
                                "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        source_entries = [{**entry, "path": entry["path"][len("source/"):]} for entry in entries
                          if entry["path"].startswith("source/")]
        task["source_sha256"] = hashlib.sha256(
            b"".join(entry["path"].encode() + b"\0" + entry["sha256"].encode() + b"\n"
                      for entry in source_entries)).hexdigest()
        task["visible_files"] = entries
        binding = {key: task[key] for key in (
            "environment_id", "difficulty", "source_commit", "source_sha256", "visible_files")}
        task["task_sha256"] = hashlib.sha256(json.dumps(binding, sort_keys=True).encode()).hexdigest()
        (task_dir / "task.json").write_text(json.dumps(task) + "\n")

        with self.assertRaisesRegex(AgentPocError, "trusted vulnerable archive"):
            validate_task(self.root, self.directory, task_dir, self.metadata["id"], self.metadata)

    def test_task_binding_changes_when_visible_description_changes(self):
        first = create_task(self.root, self.directory, self.metadata, 1, self.root / "task-one", offline=True)
        first_sha = json.loads((first / "task.json").read_text())["task_sha256"]

        self.metadata["description"] = "A different vulnerability description."
        second = create_task(self.root, self.directory, self.metadata, 1, self.root / "task-two", offline=True)
        second_sha = json.loads((second / "task.json").read_text())["task_sha256"]

        self.assertNotEqual(first_sha, second_sha)

    def test_candidate_evidence_accepts_nested_directories(self):
        output = self.root / "case"
        output.mkdir()
        child = Mock()

        def docker_cp(args, phase):
            if args[2].endswith(":/lab/results/."):
                evidence = Path(args[3]) / "subdir"
                evidence.mkdir()
                (evidence / "effect.txt").write_text("nested evidence\n")

        child.run.side_effect = docker_cp
        context = {"schema_version": 1, "run_id": "run", "case_id": "case",
                   "variant": "vulnerable", "scenario": "attack"}

        _collect_candidate_facts(child, "container", output, context)

        facts = json.loads((output / "candidate-evidence/facts.json").read_text())
        self.assertEqual([entry["path"] for entry in facts["evidence"]], ["subdir/effect.txt"])

    def test_candidate_is_copied_to_a_read_only_snapshot(self):
        candidate = self.root / "candidate"
        candidate.mkdir()
        (candidate / "poc.py").write_text("print('original')\n")
        (candidate / "manifest.toml").write_text(
            "schema_version = 1\nformat = \"command\"\nentrypoint = \"poc.py\"\n"
            "command = [\"python3\", \"/candidate/poc.py\"]\n"
            "timeout_seconds = 10\nmax_output_bytes = 1024\n"
        )

        spec = validate_candidate(candidate)
        self.addCleanup(spec.cleanup)
        (candidate / "poc.py").write_text("print('changed after validation')\n")

        self.assertNotEqual(spec.directory, candidate.resolve())
        self.assertEqual((spec.directory / "poc.py").read_text(), "print('original')\n")
        self.assertFalse((spec.directory / "poc.py").stat().st_mode & stat.S_IWUSR)

    def test_candidate_manifest_and_entrypoint_are_validated(self):
        candidate = self.root / "candidate"
        candidate.mkdir()
        (candidate / "poc.py").write_text("print('candidate')\n")
        (candidate / "manifest.toml").write_text(
            "schema_version = 1\nformat = \"command\"\nentrypoint = \"poc.py\"\n"
            "command = [\"python3\", \"/candidate/poc.py\"]\n"
            "timeout_seconds = 10\nmax_output_bytes = 1024\n"
        )
        spec = validate_candidate(candidate)
        self.assertEqual(spec.command, ("python3", "/candidate/poc.py"))
        self.assertEqual(spec.timeout_seconds, 10)

    def test_candidate_symlink_and_shell_are_rejected(self):
        candidate = self.root / "candidate"
        candidate.mkdir()
        (candidate / "poc.py").write_text("print('candidate')\n")
        (candidate / "manifest.toml").write_text(
            "schema_version = 1\nformat = \"command\"\nentrypoint = \"poc.py\"\n"
            "command = [\"sh\", \"-c\", \"python3 /candidate/poc.py\"]\n"
            "timeout_seconds = 10\nmax_output_bytes = 1024\n"
        )
        with self.assertRaisesRegex(AgentPocError, "declared entrypoint"):
            validate_candidate(candidate)
        (candidate / "manifest.toml").write_text(
            "schema_version = 1\nformat = \"command\"\nentrypoint = \"poc.py\"\n"
            "command = [\"python3\", \"/candidate/poc.py\"]\n"
            "timeout_seconds = 10\nmax_output_bytes = 1024\n"
        )
        (candidate / "link.py").symlink_to("poc.py")
        with self.assertRaisesRegex(AgentPocError, "symlink"):
            validate_candidate(candidate)

    def test_candidate_root_symlink_and_secret_metadata_are_rejected(self):
        candidate = self.root / "candidate"
        candidate.mkdir()
        (candidate / "poc.py").write_text("print('candidate')\n")
        (candidate / "manifest.toml").write_text(
            "schema_version = 1\nformat = \"command\"\nentrypoint = \"poc.py\"\n"
            "command = [\"python3\", \"/candidate/poc.py\"]\n"
            "timeout_seconds = 10\nmax_output_bytes = 1024\n"
        )
        alias = self.root / "candidate-link"
        alias.symlink_to(candidate, target_is_directory=True)
        with self.assertRaisesRegex(AgentPocError, "directory"):
            validate_candidate(alias)
        metadata = self.root / "agent.json"
        metadata.write_text(json.dumps({"model": "test", "api_key": "must-not-be-recorded"}))
        with self.assertRaisesRegex(AgentPocError, "secret field"):
            load_agent_metadata(metadata)

    def test_agent_metadata_records_provenance_without_secrets(self):
        metadata = self.root / "agent.json"
        metadata.write_text(json.dumps({"agent": "test-agent", "model": {"name": "test-model"},
                                        "toolchain": {"prompt_sha256": "a" * 64}}))
        self.assertEqual(load_agent_metadata(metadata)["provided"], True)


if __name__ == "__main__":
    unittest.main()
