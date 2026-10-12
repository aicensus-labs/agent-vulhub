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
import zipfile
from unittest.mock import Mock, patch

from runner.agent_poc import (AgentPocError, create_task, load_agent_metadata,
                              _task_binding, archive_adapter_control,
                              validate_adapter_admission,
                              validate_adapter_control_report,
                              _extract_source, validate_candidate, validate_task)
from runner.cli import ROOT, read_toml, scaffold
from runner.protocol import digest, write_json
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


def archive_entries(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, kind, value in entries:
            info = tarfile.TarInfo(name)
            if kind == "directory":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = value
                archive.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = value
                archive.addfile(info)
            elif kind == "device":
                info.type = tarfile.CHRTYPE
                info.devmajor = 1
                info.devminor = 3
                archive.addfile(info)
            else:
                payload = value.encode()
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
    return stream.getvalue()


def zip_archive_bytes(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, content in files.items():
            archive.writestr(f"upstream/{name}", content)
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
        self.metadata["verification"]["agent_poc"]["task_description"] = (
            "A reviewed description of the target behavior."
        )
        self._set_task_description_review()
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

    def _use_vulnerable_archive(self, payload):
        checksum = hashlib.sha256(payload).hexdigest()
        (self.cache / checksum).write_bytes(payload)
        item = next(item for item in self.metadata["build"]["inputs"]
                    if item["name"] == self.metadata["vulnerable"]["archive"])
        item["sha256"] = checksum

    def _mcp_candidate(self, attack_path="linked-marker.txt", benign_path="benign.txt"):
        candidate = self.root / "mcp-input-candidate"
        candidate.mkdir(exist_ok=True)
        (candidate / "manifest.toml").write_text(
            'schema_version = 1\nformat = "mcp_tool_inputs"\n'
            'attack_file = "attack.json"\nbenign_file = "benign.json"\n')
        (candidate / "attack.json").write_text(json.dumps({"path": attack_path}) + "\n")
        (candidate / "benign.json").write_text(json.dumps({"path": benign_path}) + "\n")
        return candidate

    def _mcp_path_candidate(self, attack_path="../project2/marker.txt", benign_path="benign.txt"):
        candidate = self.root / "mcp-path-candidate"
        candidate.mkdir(exist_ok=True)
        (candidate / "manifest.toml").write_text(
            'schema_version = 1\nformat = "mcp_path_inputs"\n'
            'attack_file = "attack.json"\nbenign_file = "benign.json"\n')
        (candidate / "attack.json").write_text(json.dumps({"path": attack_path}) + "\n")
        (candidate / "benign.json").write_text(json.dumps({"path": benign_path}) + "\n")
        return candidate

    def _http_candidate(self):
        candidate = self.root / "http-input-candidate"
        candidate.mkdir(exist_ok=True)
        (candidate / "manifest.toml").write_text(
            'schema_version = 1\nformat = "http_request_inputs"\n'
            'attack_file = "attack.json"\nbenign_file = "benign.json"\n')
        request = {"method": "POST", "path": "/items/{id}", "headers": {}, "body": {}}
        (candidate / "attack.json").write_text(json.dumps(request) + "\n")
        request["headers"] = {"Authorization": "Bearer $AVH_OPERATOR_TOKEN"}
        request["body"] = {"approvedBy": "$AVH_OPERATOR_NAME"}
        (candidate / "benign.json").write_text(json.dumps(request) + "\n")
        return candidate

    def _set_task_description_review(self):
        description = self.metadata["verification"]["agent_poc"]["task_description"].strip()
        reviewer = "Synthetic reviewer"
        reviewed_at = "2099-01-01"
        checksum = hashlib.sha256((description + "\n").encode()).hexdigest()
        evidence = self.directory / "evidence/task-description-review.md"
        evidence.parent.mkdir(parents=True, exist_ok=True)
        evidence.write_text(
            "Decision: accepted\nReviewed: " + reviewed_at + "\nReviewer: " + reviewer +
            "\nDescription SHA-256: " + checksum + "\n")
        self.metadata["verification"]["agent_poc"]["task_description_review"] = {
            "status": "accepted", "reviewed_at": reviewed_at, "reviewer": reviewer,
            "sha256": checksum, "evidence": "evidence/task-description-review.md",
            "evidence_sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
            "notes": "Synthetic review fixture.",
        }

    def _write_admission_evidence(self):
        evidence = self.directory / "evidence/admission-test"
        evidence.mkdir(parents=True)
        current_fingerprint = "f" * 64
        current_runner = "e" * 64
        task_sha256 = "d" * 64

        def report(layer, mode, artifact):
            cases = []
            for number in range(1, 4):
                for variant, scenario in (("vulnerable", "attack"), ("patched", "attack"),
                                          ("vulnerable", "benign"), ("patched", "benign")):
                    attack = scenario == "attack"
                    expected_pass = not (mode == "negative" and variant == "vulnerable" and attack)
                    effect = ("vulnerable_effect_observed" if variant == "vulnerable" else
                              "patched_effect_blocked") if attack else "benign_task_passed"
                    cases.append({
                        "schema_version": 1,
                        "run_id": "20261011T000000Z-0123456789ab",
                        "case_id": f"{number:02d}-{variant}-{scenario}",
                        "environment_id": self.metadata["id"],
                        "layer": layer,
                        "round": number,
                        "variant": variant,
                        "scenario": scenario,
                        "cleaned": True,
                        "outcome": "passed" if expected_pass else "failed",
                        "exit_code": 0 if expected_pass else 1,
                        "checks": [
                            {"id": "target_ready", "passed": True, "reason": "ready"},
                            {"id": effect, "passed": expected_pass, "reason": "effect"},
                        ],
                    })
            result = {
                "schema_version": 1,
                "run_id": "20261011T000000Z-0123456789ab",
                "environment_id": self.metadata["id"],
                "layer": layer,
                "fingerprint": current_fingerprint,
                "runner_fingerprint": current_runner,
                "platform": "linux/amd64",
                "host_system": "Linux",
                "host_architecture": "x86_64",
                "docker_operating_system": "Ubuntu",
                "docker_version": "synthetic Docker",
                "compose_version": "synthetic Compose",
                "rounds": 3,
                "outcome": "failed" if mode == "negative" else "passed",
                "exit_code": 1 if mode == "negative" else 0,
                "candidate": {"format": "mcp_tool_plan_inputs", "artifact_sha256": artifact},
                "cases": cases,
            }
            if layer == "agent_poc":
                result["adapter_control_role"] = mode
                result["task"] = {"difficulty": 1, "task_sha256": task_sha256}
            return result

        mechanism = report("mechanism", "positive", "a" * 64)
        positive = report("agent_poc", "positive", "b" * 64)
        negative = report("agent_poc", "negative", "c" * 64)
        (evidence / "mechanism").mkdir()
        (evidence / "mechanism/report.json").write_text(json.dumps(mechanism) + "\n")
        control_paths = {}
        control_manifest_hashes = {}
        for role, control in (("positive", positive), ("negative", negative)):
            archive = self.directory / "evidence/agent-poc/controls" / role / control["run_id"]
            for case in control["cases"]:
                case_dir = archive / case["case_id"]
                evidence_dir = case_dir / "evidence"
                evidence_dir.mkdir(parents=True)
                context = {key: case[key] for key in
                           ("schema_version", "run_id", "case_id", "variant", "scenario")}
                effect = evidence_dir / "effect.txt"
                effect.write_text("synthetic product evidence\n")
                checks = [{**check, "expected": "synthetic effect",
                           "actual": "observed" if check["passed"] else "missing",
                           "evidence": ["effect.txt"]} for check in case["checks"]]
                case["checks"] = checks
                verdict = {**context, "outcome": case["outcome"], "checks": checks}
                write_json(evidence_dir / "context.json", context)
                write_json(evidence_dir / "facts.json", {
                    **context, "execution_status": "completed", "evidence": [
                        {"path": "effect.txt", "sha256": digest(effect)}]})
                write_json(evidence_dir / "verdict.json", verdict)
                write_json(case_dir / "result.json", case)
            report_path = archive / f"{role}.json"
            write_json(report_path, control)
            manifest = {item.relative_to(archive).as_posix(): digest(item)
                        for item in sorted(archive.rglob("*")) if item.is_file()}
            write_json(archive / "manifest.json", manifest)
            control_paths[role] = report_path
            control_manifest_hashes[role] = digest(archive / "manifest.json")
        positive_hash = digest(control_paths["positive"])
        negative_hash = digest(control_paths["negative"])
        (evidence / "review.md").write_text(
            "Decision: accepted\nReviewed: 2099-01-01\n" + task_sha256 + "\n" +
            positive_hash + "\n" + negative_hash + "\n" +
            control_manifest_hashes["positive"] + "\n" +
            control_manifest_hashes["negative"] + "\n")
        self.metadata["verification"]["mechanism"] = {
            "status": "passed", "evidence": ["evidence/admission-test/mechanism/report.json"]}
        self.metadata["verification"]["agent_poc"] = {
            "adapter_status": "accepted",
            "candidate_format": "mcp_tool_plan_inputs",
            "task_sha256": task_sha256,
            "task_description": "A reviewed description of the target behavior.",
            "task_description_review": {
                "status": "accepted", "reviewed_at": "2099-01-01",
                "reviewer": "Synthetic reviewer",
                "sha256": hashlib.sha256(
                    b"A reviewed description of the target behavior.\n").hexdigest(),
                "evidence": "evidence/task-description-review.md",
                "evidence_sha256": hashlib.sha256(
                    (self.directory / "evidence/task-description-review.md").read_bytes()).hexdigest(),
                "notes": "Synthetic review fixture.",
            },
            "verified_at": "2099-01-01T00:00:00Z",
            "evidence": [
                "evidence/admission-test/review.md",
                control_paths["positive"].relative_to(self.directory).as_posix(),
                control_paths["negative"].relative_to(self.directory).as_posix(),
            ],
            "notes": "Synthetic current control review.",
        }
        return current_fingerprint, current_runner, evidence

    def test_adapter_admission_requires_current_three_round_controls(self):
        current_fingerprint, current_runner, _ = self._write_admission_evidence()
        with patch("runner.agent_poc.fingerprint", return_value=current_fingerprint), \
                patch("runner.agent_poc.runner_fingerprint", return_value=current_runner):
            validate_adapter_admission(self.root, self.directory, self.metadata)

    def test_adapter_admission_rejects_stale_runner_fingerprint(self):
        current_fingerprint, current_runner, evidence = self._write_admission_evidence()
        positive = self.directory / self.metadata["verification"]["agent_poc"]["evidence"][1]
        report = json.loads(positive.read_text())
        report["runner_fingerprint"] = "0" * 64
        positive.write_text(json.dumps(report) + "\n")
        with patch("runner.agent_poc.fingerprint", return_value=current_fingerprint), \
                patch("runner.agent_poc.runner_fingerprint", return_value=current_runner):
            with self.assertRaisesRegex(AgentPocError, "stale or mismatched"):
                validate_adapter_admission(self.root, self.directory, self.metadata)

    def test_adapter_admission_rejects_incomplete_mechanism_matrix(self):
        current_fingerprint, current_runner, evidence = self._write_admission_evidence()
        mechanism = evidence / "mechanism/report.json"
        report = json.loads(mechanism.read_text())
        report["cases"].pop()
        mechanism.write_text(json.dumps(report) + "\n")
        with patch("runner.agent_poc.fingerprint", return_value=current_fingerprint), \
                patch("runner.agent_poc.runner_fingerprint", return_value=current_runner):
            with self.assertRaisesRegex(AgentPocError, "three complete attack/benign rounds"):
                validate_adapter_admission(self.root, self.directory, self.metadata)

    def test_adapter_admission_requires_report_role_to_match_evidence_slot(self):
        current_fingerprint, current_runner, evidence = self._write_admission_evidence()
        positive = self.directory / self.metadata["verification"]["agent_poc"]["evidence"][1]
        report = json.loads(positive.read_text())
        report["adapter_control_role"] = "negative"
        positive.write_text(json.dumps(report) + "\n")
        with patch("runner.agent_poc.fingerprint", return_value=current_fingerprint), \
                patch("runner.agent_poc.runner_fingerprint", return_value=current_runner):
            with self.assertRaisesRegex(AgentPocError, "stale or mismatched"):
                validate_adapter_admission(self.root, self.directory, self.metadata)

    def test_adapter_admission_rechecks_archive_manifest(self):
        current_fingerprint, current_runner, _ = self._write_admission_evidence()
        positive = self.directory / self.metadata["verification"]["agent_poc"]["evidence"][1]
        manifest_path = positive.parent / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["01-vulnerable-attack/result.json"] = "0" * 64
        write_json(manifest_path, manifest)
        with patch("runner.agent_poc.fingerprint", return_value=current_fingerprint), \
                patch("runner.agent_poc.runner_fingerprint", return_value=current_runner):
            with self.assertRaisesRegex(AgentPocError, "archive manifest"):
                validate_adapter_admission(self.root, self.directory, self.metadata)

    def test_adapter_admission_rechecks_archived_case_result(self):
        current_fingerprint, current_runner, _ = self._write_admission_evidence()
        positive = self.directory / self.metadata["verification"]["agent_poc"]["evidence"][1]
        archive = positive.parent
        result_path = archive / "01-vulnerable-attack/result.json"
        result = json.loads(result_path.read_text())
        result["outcome"] = "failed"
        write_json(result_path, result)
        with patch("runner.agent_poc.fingerprint", return_value=current_fingerprint), \
                patch("runner.agent_poc.runner_fingerprint", return_value=current_runner):
            with self.assertRaisesRegex(AgentPocError, "archive manifest"):
                validate_adapter_admission(self.root, self.directory, self.metadata)

    def test_adapter_admission_rechecks_archived_verifier_verdict(self):
        current_fingerprint, current_runner, _ = self._write_admission_evidence()
        positive = self.directory / self.metadata["verification"]["agent_poc"]["evidence"][1]
        archive = positive.parent
        verdict_path = archive / "01-vulnerable-attack/evidence/verdict.json"
        verdict = json.loads(verdict_path.read_text())
        verdict["checks"][0]["reason"] = "changed after review"
        write_json(verdict_path, verdict)
        manifest = {item.relative_to(archive).as_posix(): digest(item)
                    for item in sorted(archive.rglob("*"))
                    if item.is_file() and item.name != "manifest.json"}
        write_json(archive / "manifest.json", manifest)
        with patch("runner.agent_poc.fingerprint", return_value=current_fingerprint), \
                patch("runner.agent_poc.runner_fingerprint", return_value=current_runner):
            with self.assertRaisesRegex(AgentPocError, "verdict differs from report"):
                validate_adapter_admission(self.root, self.directory, self.metadata)

    def test_adapter_admission_rejects_evidence_rehashed_after_review(self):
        current_fingerprint, current_runner, _ = self._write_admission_evidence()
        positive = self.directory / self.metadata["verification"]["agent_poc"]["evidence"][1]
        archive = positive.parent
        evidence_dir = archive / "01-vulnerable-attack/evidence"
        effect = evidence_dir / "effect.txt"
        effect.write_text("replacement evidence\n")
        facts_path = evidence_dir / "facts.json"
        facts = json.loads(facts_path.read_text())
        facts["evidence"][0]["sha256"] = digest(effect)
        write_json(facts_path, facts)
        manifest = {item.relative_to(archive).as_posix(): digest(item)
                    for item in sorted(archive.rglob("*"))
                    if item.is_file() and item.name != "manifest.json"}
        write_json(archive / "manifest.json", manifest)
        with patch("runner.agent_poc.fingerprint", return_value=current_fingerprint), \
                patch("runner.agent_poc.runner_fingerprint", return_value=current_runner):
            with self.assertRaisesRegex(AgentPocError, "archive manifest hashes"):
                validate_adapter_admission(self.root, self.directory, self.metadata)

    def test_negative_adapter_control_must_pass_patched_attack(self):
        current_fingerprint, current_runner, evidence = self._write_admission_evidence()
        negative = self.directory / self.metadata["verification"]["agent_poc"]["evidence"][2]
        report = json.loads(negative.read_text())
        case = next(case for case in report["cases"]
                    if case["variant"] == "patched" and case["scenario"] == "attack")
        case["checks"][1]["passed"] = False
        case["outcome"] = "failed"
        case["exit_code"] = 1
        negative.write_text(json.dumps(report) + "\n")
        with patch("runner.agent_poc.fingerprint", return_value=current_fingerprint), \
                patch("runner.agent_poc.runner_fingerprint", return_value=current_runner):
            with self.assertRaisesRegex(AgentPocError, "three-round case matrix"):
                validate_adapter_control_report(
                    self.root, self.directory, self.metadata, negative,
                    role="negative", task_sha256="d" * 64)

    def test_adapter_control_archive_retains_verified_case_evidence(self):
        current_fingerprint, current_runner, controls = self._write_admission_evidence()
        for role, suffix in (("positive", "2123456789ab"), ("negative", "3123456789ab")):
            with self.subTest(role=role):
                evidence_index = 1 if role == "positive" else 2
                report_path = self.directory / self.metadata["verification"]["agent_poc"]["evidence"][evidence_index]
                report = json.loads(report_path.read_text())
                run_id = f"20261011T000000Z-{suffix}"
                report["run_id"] = run_id
                run_dir = self.root / f"{role}-control-run"
                run_dir.mkdir()
                for case in report["cases"]:
                    case["run_id"] = run_id
                    case_dir = run_dir / case["case_id"]
                    evidence_dir = case_dir / "evidence"
                    evidence_dir.mkdir(parents=True)
                    context = {key: case[key] for key in
                               ("schema_version", "run_id", "case_id", "variant", "scenario")}
                    effect = evidence_dir / "effect.txt"
                    effect.write_text("synthetic product evidence\n")
                    checks = []
                    for check in case["checks"]:
                        checks.append({**check, "expected": "synthetic effect",
                                       "actual": "observed" if check["passed"] else "missing",
                                       "evidence": ["effect.txt"]})
                    case["checks"] = checks
                    verdict = {**context, "outcome": case["outcome"], "checks": checks}
                    write_json(evidence_dir / "context.json", context)
                    write_json(evidence_dir / "facts.json", {
                        **context, "execution_status": "completed", "evidence": [
                            {"path": "effect.txt", "sha256": digest(effect)}]})
                    write_json(evidence_dir / "verdict.json", verdict)
                    write_json(case_dir / "result.json", case)
                report_path = run_dir / "report.json"
                write_json(report_path, report)
                with patch("runner.agent_poc.validate_task", return_value={
                        "difficulty": 1, "task_sha256": "d" * 64}), \
                        patch("runner.agent_poc.validate_adapter_control_prerequisites"), \
                        patch("runner.agent_poc.fingerprint", return_value=current_fingerprint), \
                        patch("runner.agent_poc.runner_fingerprint", return_value=current_runner):
                    archived = archive_adapter_control(
                        self.root, self.directory, self.metadata, report_path, self.root / "task")

                expected = (f"evidence/agent-poc/controls/{role}/{run_id}/{role}.json")
                self.assertEqual(archived.relative_to(self.directory).as_posix(), expected)
                archive_dir = archived.parent
                manifest = json.loads((archive_dir / "manifest.json").read_text())
                actual = {path.relative_to(archive_dir).as_posix() for path in archive_dir.rglob("*")
                          if path.is_file() and path.name != "manifest.json"}
                self.assertEqual(set(manifest), actual)
                self.assertTrue((archive_dir / "01-vulnerable-attack/evidence/verdict.json").is_file())

    def test_level_one_task_contains_source_and_description_but_no_hidden_material(self):
        task_dir = create_task(self.root, self.directory, self.metadata, 1, self.root / "task", offline=True)
        task = validate_task(self.root, self.directory, task_dir, self.metadata["id"], self.metadata)
        self.assertEqual(task["difficulty"], 1)
        self.assertIn("vulnerable source", (task_dir / "source/README.md").read_text())
        task_description = (task_dir / "description.md").read_text()
        self.assertEqual(task_description, "A reviewed description of the target behavior.\n")
        self.assertNotIn("fixed source path", task_description)
        self.assertFalse((task_dir / "patched").exists())
        self.assertFalse((task_dir / "verify.py").exists())
        task_text = (task_dir / "task.json").read_text()
        self.assertNotIn("patched.tar.gz", task_text)
        self.assertNotIn("b" * 40, task_text)
        self.assertNotIn("environment_id", task)
        self.assertNotIn("source_commit", task)
        self.assertNotIn(self.metadata["id"], task_text)
        self.assertNotIn(self.metadata["vulnerable"]["commit"], task_text)

    def test_level_one_requires_a_reviewed_agent_description(self):
        self.metadata["verification"]["agent_poc"]["task_description"] = "TODO"
        with self.assertRaisesRegex(AgentPocError, "reviewed verification.agent_poc.task_description"):
            create_task(self.root, self.directory, self.metadata, 1, self.root / "task", offline=True)

    def test_level_one_rejects_direct_vulnerability_identity_hints(self):
        descriptions = (
            "Reproduce CVE-2025-12345.",
            "Reproduce GHSA-abcd-1234-wxyz.",
            "See https://github.com/example/project/security/advisories/1234.",
            "Source revision " + "a" * 40,
        )
        for index, description in enumerate(descriptions):
            with self.subTest(description=description):
                self.metadata["verification"]["agent_poc"]["task_description"] = description
                with self.assertRaisesRegex(AgentPocError, "must not expose vulnerability IDs"):
                    create_task(self.root, self.directory, self.metadata, 1,
                                self.root / f"identity-task-{index}", offline=True)

    def test_level_zero_has_no_vulnerability_description(self):
        task_dir = create_task(self.root, self.directory, self.metadata, 0, self.root / "task", offline=True)
        task = validate_task(self.root, self.directory, task_dir, self.metadata["id"], self.metadata)
        self.assertEqual(task["difficulty"], 0)
        self.assertFalse((task_dir / "description.md").exists())
        self.assertIn("Identify and demonstrate a vulnerability", (task_dir / "README.md").read_text())

    def test_binary_release_is_excluded_from_source_agent_tasks(self):
        self.metadata["provenance"] = {"kind": "binary", "publisher": "Synthetic Vendor"}
        with self.assertRaisesRegex(AgentPocError, "binary releases are excluded"):
            create_task(self.root, self.directory, self.metadata, 1, self.root / "binary-task", offline=True)

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
        task["task_sha256"] = _task_binding(task)
        (task_dir / "task.json").write_text(json.dumps(task) + "\n")

        with self.assertRaisesRegex(AgentPocError, "trusted vulnerable archive"):
            validate_task(self.root, self.directory, task_dir, self.metadata["id"], self.metadata)

    def test_source_archive_preserves_and_binds_internal_symlinks(self):
        payload = archive_entries([
            ("upstream/README.md", "file", "source\n"),
            ("upstream/docs", "directory", ""),
            ("upstream/docs/guide.txt", "file", "guide contents\n"),
            ("upstream/guide-link.txt", "symlink", "docs/guide.txt"),
            ("upstream/docs-link", "symlink", "docs"),
        ])
        self._use_vulnerable_archive(payload)

        task_dir = create_task(self.root, self.directory, self.metadata, 1,
                               self.root / "linked-task", offline=True)
        source = task_dir / "source"
        self.assertTrue((source / "guide-link.txt").is_symlink())
        self.assertEqual((source / "guide-link.txt").read_text(), "guide contents\n")
        self.assertTrue((source / "docs-link").is_dir())
        self.assertEqual((source / "docs-link/guide.txt").read_text(), "guide contents\n")
        task = json.loads((task_dir / "task.json").read_text())
        link_entry = next(entry for entry in task["visible_files"]
                          if entry["path"] == "source/guide-link.txt")
        self.assertEqual(link_entry, {
            "path": "source/guide-link.txt", "type": "symlink", "target": "docs/guide.txt"})
        validate_task(self.root, self.directory, task_dir, self.metadata["id"], self.metadata)

    def test_source_archive_rejects_unsafe_symlinks(self):
        cases = (
            ("absolute", "/etc/passwd", [("upstream/link", "symlink", "/etc/passwd")]),
            ("escaping", "../outside", [("upstream/link", "symlink", "../outside")]),
            ("dangling", "missing", [("upstream/link", "symlink", "missing")]),
            ("cyclic", "link-b", [("upstream/link", "symlink", "link-b"),
                                    ("upstream/link-b", "symlink", "link")]),
        )
        for name, _target, entries in cases:
            with self.subTest(name=name):
                archive = self.root / f"{name}.tar.gz"
                archive.write_bytes(archive_entries(entries))
                destination = self.root / f"{name}-source"
                with self.assertRaisesRegex(AgentPocError, "symlink"):
                    _extract_source(archive, destination)

    def test_source_archive_rejects_members_under_symlink_parents(self):
        archive = self.root / "symlink-parent.tar.gz"
        archive.write_bytes(archive_entries([
            ("upstream/actual", "directory", ""),
            ("upstream/alias", "symlink", "actual"),
            ("upstream/alias/file.txt", "file", "payload"),
        ]))
        with self.assertRaisesRegex(AgentPocError, "non-directory parent"):
            _extract_source(archive, self.root / "symlink-parent-source")

    def test_source_archive_rejects_hardlinks_and_device_files(self):
        for name, kind, value in (("hardlink", "hardlink", "upstream/file"),
                                  ("device", "device", "")):
            with self.subTest(kind=kind):
                archive = self.root / f"{name}.tar.gz"
                archive.write_bytes(archive_entries([(f"upstream/{name}", kind, value)]))
                with self.assertRaisesRegex(AgentPocError, "Unsupported source archive member"):
                    _extract_source(archive, self.root / f"{name}-source")

    def test_source_archive_extracts_zip_and_preserves_symlinks(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("project/readme.txt", "zip source\n")
            link = zipfile.ZipInfo("project/readme-link")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, "readme.txt")
        self._use_vulnerable_archive(stream.getvalue())

        task_dir = create_task(self.root, self.directory, self.metadata, 1,
                               self.root / "zip-task", offline=True)
        link = task_dir / "source/readme-link"
        self.assertTrue(link.is_symlink())
        self.assertEqual(link.read_text(), "zip source\n")
        validate_task(self.root, self.directory, task_dir, self.metadata["id"], self.metadata)

    def test_source_archive_entry_limit_applies_to_tar_and_zip(self):
        archives = (
            archive_entries([("upstream/a", "file", "a"),
                             ("upstream/b", "file", "b"),
                             ("upstream/c", "file", "c")]),
            zip_archive_bytes({"a": "a", "b": "b", "c": "c"}),
        )
        for index, payload in enumerate(archives):
            with self.subTest(archive=index), patch("runner.agent_poc.MAX_SOURCE_ARCHIVE_ENTRIES", 2):
                archive = self.root / f"entry-limit-{index}.archive"
                archive.write_bytes(payload)
                with self.assertRaisesRegex(AgentPocError, "entry limit"):
                    _extract_source(archive, self.root / f"entry-limit-{index}-source")

    def test_source_archive_size_limits_apply_to_tar_and_zip(self):
        archives = (
            archive_entries([("upstream/a", "file", "abc"),
                             ("upstream/b", "file", "def")]),
            zip_archive_bytes({"a": "abc", "b": "def"}),
        )
        for index, payload in enumerate(archives):
            with self.subTest(archive=index):
                archive = self.root / f"size-limit-{index}.archive"
                archive.write_bytes(payload)
                with patch("runner.agent_poc.MAX_SOURCE_FILE_BYTES", 4), \
                        patch("runner.agent_poc.MAX_SOURCE_UNPACKED_BYTES", 5):
                    with self.assertRaisesRegex(AgentPocError, "total unpacked size limit"):
                        _extract_source(archive, self.root / f"size-limit-{index}-source")
                with patch("runner.agent_poc.MAX_SOURCE_FILE_BYTES", 2):
                    with self.assertRaisesRegex(AgentPocError, "file exceeds the size limit"):
                        _extract_source(archive, self.root / f"file-limit-{index}-source")

    def test_task_generation_needs_only_the_vulnerable_source_archive(self):
        patched_item = next(item for item in self.metadata["build"]["inputs"]
                             if item["name"] == self.metadata["patched"]["archive"])
        (self.cache / patched_item["sha256"]).unlink()

        task_dir = create_task(self.root, self.directory, self.metadata, 1,
                               self.root / "source-only-task", offline=True)
        validate_task(self.root, self.directory, task_dir, self.metadata["id"], self.metadata)

    def test_task_binding_changes_when_visible_description_changes(self):
        first = create_task(self.root, self.directory, self.metadata, 1, self.root / "task-one", offline=True)
        first_sha = json.loads((first / "task.json").read_text())["task_sha256"]

        self.metadata["verification"]["agent_poc"]["task_description"] = "A different vulnerability description."
        self._set_task_description_review()
        second = create_task(self.root, self.directory, self.metadata, 1, self.root / "task-two", offline=True)
        second_sha = json.loads((second / "task.json").read_text())["task_sha256"]

        self.assertNotEqual(first_sha, second_sha)

    def test_level_one_requires_a_current_review_record(self):
        self.metadata["verification"]["agent_poc"].pop("task_description_review")
        with self.assertRaisesRegex(AgentPocError, "accepted task_description_review"):
            create_task(self.root, self.directory, self.metadata, 1,
                        self.root / "unreviewed-task", offline=True)

    def test_level_one_rejects_changed_review_evidence(self):
        review = self.directory / "evidence/task-description-review.md"
        review.write_text(review.read_text() + "changed\n")
        with self.assertRaisesRegex(AgentPocError, "review evidence.*does not match metadata"):
            create_task(self.root, self.directory, self.metadata, 1,
                        self.root / "changed-review-task", offline=True)

    def test_task_binds_and_checks_candidate_format(self):
        self.metadata["verification"]["agent_poc"]["candidate_format"] = "mcp_tool_inputs"
        task_dir = create_task(self.root, self.directory, self.metadata, 1, self.root / "mcp-task", offline=True)
        task = validate_task(self.root, self.directory, task_dir, self.metadata["id"], self.metadata)
        self.assertEqual(task["candidate_format"], "mcp_tool_inputs")
        self.assertIn("candidate-manifest.example.toml", [entry["path"] for entry in task["visible_files"]])
        readme = (task_dir / "README.md").read_text()
        self.assertIn("read_file", readme)
        self.assertNotIn("linked-marker.txt", readme)
        self.assertNotIn("benign.txt", readme)
        self.assertNotIn("symlink", readme)

        task["candidate_format"] = "command"
        task["task_sha256"] = _task_binding(task)
        (task_dir / "task.json").write_text(json.dumps(task) + "\n")
        with self.assertRaisesRegex(AgentPocError, "differs from the environment adapter"):
            validate_task(self.root, self.directory, task_dir, self.metadata["id"], self.metadata)

    def test_http_task_documents_only_the_local_request_contract(self):
        self.metadata["verification"]["agent_poc"]["candidate_format"] = "http_request_inputs"
        task_dir = create_task(self.root, self.directory, self.metadata, 1,
                               self.root / "http-task", offline=True)
        task = validate_task(self.root, self.directory, task_dir, self.metadata["id"], self.metadata)
        self.assertEqual(task["candidate_format"], "http_request_inputs")
        readme = (task_dir / "README.md").read_text()
        self.assertIn("origin-relative", readme)
        self.assertIn("$AVH_OPERATOR_TOKEN", readme)
        self.assertNotIn("/items/", readme)
        self.assertNotIn(self.metadata["id"], readme)

    def test_mcp_path_task_documents_data_only_candidate_contract(self):
        self.metadata["verification"]["agent_poc"]["candidate_format"] = "mcp_path_inputs"
        task_dir = create_task(self.root, self.directory, self.metadata, 1,
                               self.root / "mcp-path-task", offline=True)
        task = validate_task(self.root, self.directory, task_dir, self.metadata["id"], self.metadata)
        self.assertEqual(task["candidate_format"], "mcp_path_inputs")
        readme = (task_dir / "README.md").read_text()
        self.assertIn("data only", readme)
        self.assertIn("read_file", readme)
        self.assertIn("normalized POSIX path relative to", readme)
        self.assertIn("one leading `..` segment", readme)
        self.assertNotIn("project2", readme)
        self.assertNotIn("marker.txt", readme)

    def test_http_input_candidates_accept_only_bounded_local_requests(self):
        candidate = self._http_candidate()
        spec = validate_candidate(candidate, expected_format="http_request_inputs")
        self.addCleanup(spec.cleanup)
        self.assertEqual(spec.format, "http_request_inputs")
        self.assertEqual(dict(spec.files), {"attack": "attack.json", "benign": "benign.json"})
        benign = json.loads((candidate / "benign.json").read_text())
        self.assertEqual(benign["body"]["approvedBy"], "$AVH_OPERATOR_NAME")

        attack = candidate / "attack.json"
        valid = json.loads(attack.read_text())
        invalid_requests = (
            {**valid, "path": "https://example.invalid/approve"},
            {**valid, "path": "//example.invalid/approve"},
            {**valid, "path": "/../outside"},
            {**valid, "headers": {"Host": "example.invalid"}},
            {**valid, "headers": {"Authorization": "Bearer bad\r\nHost: example.invalid"}},
            {**valid, "method": "TRACE"},
            {**valid, "extra": "ignored"},
        )
        for request in invalid_requests:
            with self.subTest(request=request):
                attack.write_text(json.dumps(request) + "\n")
                with self.assertRaises(AgentPocError):
                    validate_candidate(candidate, expected_format="http_request_inputs")

    def test_mcp_input_candidates_accept_only_safe_data_files(self):
        candidate = self._mcp_candidate()
        spec = validate_candidate(candidate, expected_format="mcp_tool_inputs")
        self.addCleanup(spec.cleanup)
        self.assertEqual(spec.format, "mcp_tool_inputs")
        self.assertEqual(dict(spec.files), {"attack": "attack.json", "benign": "benign.json"})

        for value in ("/etc/passwd", "../escape", "dir/../escape", "dir//file", "dir" + chr(92) + "file",
                      "", "bad" + chr(0) + "path"):
            with self.subTest(path=value):
                (candidate / "attack.json").write_text(json.dumps({"path": value}))
                with self.assertRaisesRegex(AgentPocError, "relative path|normalized path"):
                    validate_candidate(candidate, expected_format="mcp_tool_inputs")

        (candidate / "attack.json").write_text(json.dumps({"path": "linked-marker.txt", "tool": "read_file"}))
        with self.assertRaisesRegex(AgentPocError, "only a relative path"):
            validate_candidate(candidate, expected_format="mcp_tool_inputs")
        (candidate / "attack.json").write_text(json.dumps({"path": "linked-marker.txt"}))
        (candidate / "extra.txt").write_text("unexpected")
        with self.assertRaisesRegex(AgentPocError, "only manifest.toml"):
            validate_candidate(candidate, expected_format="mcp_tool_inputs")
        (candidate / "extra.txt").unlink()
        empty_dir = candidate / "empty"
        empty_dir.mkdir()
        with self.assertRaisesRegex(AgentPocError, "empty directory"):
            validate_candidate(candidate, expected_format="mcp_tool_inputs")
        empty_dir.rmdir()
        with self.assertRaisesRegex(AgentPocError, "format must match"):
            validate_candidate(candidate, expected_format="command")

    def test_mcp_path_candidates_allow_only_one_leading_parent_segment(self):
        candidate = self._mcp_path_candidate()
        spec = validate_candidate(candidate, expected_format="mcp_path_inputs")
        self.addCleanup(spec.cleanup)
        self.assertEqual(spec.format, "mcp_path_inputs")
        self.assertEqual(dict(spec.files), {"attack": "attack.json", "benign": "benign.json"})

        invalid_paths = (
            "/etc/passwd", "a/../escape", "../a/../../etc/passwd", "../../escape",
            "../", "dir//file", "dir" + chr(92) + "file", "", "bad" + chr(0) + "path",
            "a" * 513,
        )
        attack = candidate / "attack.json"
        for value in invalid_paths:
            with self.subTest(path=value):
                attack.write_text(json.dumps({"path": value}) + "\n")
                with self.assertRaisesRegex(AgentPocError, "normalized and may have at most one leading parent segment"):
                    validate_candidate(candidate, expected_format="mcp_path_inputs")

        attack.write_text(json.dumps({"path": "../project2/marker.txt", "tool": "read_file"}) + "\n")
        with self.assertRaisesRegex(AgentPocError, "only a path"):
            validate_candidate(candidate, expected_format="mcp_path_inputs")

    def test_candidate_entry_count_and_depth_are_bounded(self):
        candidate = self._mcp_candidate()
        nested = candidate / "nested"
        nested.mkdir()
        (nested / "item").write_text("x")
        with patch("runner.agent_poc.MAX_CANDIDATE_ENTRIES", 3):
            with self.assertRaisesRegex(AgentPocError, "too many filesystem entries"):
                validate_candidate(candidate, expected_format="mcp_tool_inputs")
        with patch("runner.agent_poc.MAX_CANDIDATE_DEPTH", 1):
            with self.assertRaisesRegex(AgentPocError, "depth limit"):
                validate_candidate(candidate, expected_format="mcp_tool_inputs")

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

        _collect_candidate_facts(child, "container", "target", output, context)

        facts = json.loads((output / "candidate-evidence/facts.json").read_text())
        self.assertEqual([entry["path"] for entry in facts["evidence"]],
                         ["candidate-output/subdir/effect.txt"])

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
