"""Protocol and lifecycle tests never execute environment code or Docker."""

from argparse import Namespace
import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import Mock, patch
import ipaddress
import subprocess

from runner.cli import ROOT, check, main, read_toml, scaffold
from runner.agent_poc import CandidateSpec
from runner.build import build_images, fetch_inputs, validate_sources
from runner.compose import validate_compose
from runner.lifecycle import promote, ready_check, refresh
from runner.protocol import (CASES, check_fixtures, digest, fingerprint, revision_identity,
                             validate_report, validate_verdict, write_json, write_metadata)
from runner.runtime import (RunError, _candidate_container_command, _collect_candidate_facts,
                             _verifier_container_command, allocate_subnet,
                             apply_network_subnet, fallback_pool, reproduce, run_case)


def facts_and_verdict(folder, context, passed=True):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "effect.txt").write_text("synthetic evidence for tooling test\n")
    write_json(folder / "context.json", context)
    write_json(folder / "facts.json", {**context, "execution_status": "completed", "evidence": [
        {"path": "effect.txt", "sha256": digest(folder / "effect.txt")}]})
    required = "benign_task_passed" if context["scenario"] == "benign" else (
        "vulnerable_effect_observed" if context["variant"] == "vulnerable" else "patched_effect_blocked")
    checks = [{"id": key, "passed": passed, "reason": "synthetic test observation",
               "expected": "marker", "actual": "marker" if passed else "missing", "evidence": ["effect.txt"]}
              for key in ("target_ready", required)]
    verdict = {**context, "outcome": "passed" if passed else "failed", "checks": checks}
    write_json(folder / "verdict.json", verdict)
    return verdict


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "environments").mkdir()
        (self.root / "environments.toml").write_text("schema_version = 1\nenvironments = []\n")
        shutil.copytree(ROOT / "templates", self.root / "templates")
        shutil.copytree(ROOT / "runner", self.root / "runner")
        self.directory = scaffold(self.root, "synthetic", "CVE-2099-99999")
        self.metadata = read_toml(self.directory / "metadata.toml")
        for variant in ("vulnerable", "patched"):
            self.metadata[variant]["commit"] = "a" * 40
        self.context = {"schema_version": 1, "run_id": "test-run", "case_id": "01-vulnerable-attack",
                        "environment_id": self.metadata["id"], "variant": "vulnerable", "scenario": "attack"}

    def report(self):
        output = self.root / "results" / "test-run"
        output.mkdir(parents=True, exist_ok=True)
        report = {"schema_version": 1, "environment_id": self.metadata["id"], "run_id": "test-run",
                  "layer": "mechanism",
                  "fingerprint": fingerprint(self.root, self.directory, self.metadata), "rounds": 3,
                  "platform": "linux/amd64", "host_system": "Linux", "docker_operating_system": "Linux",
                  "host_architecture": "x86_64",
                  "docker_version": "test", "compose_version": "test", "runner_fingerprint": "test",
                  "outcome": "passed", "exit_code": 0, "finished_at": "2026-09-09T00:00:00Z", "cases": []}
        for number in range(1, 4):
            for variant, scenario in CASES:
                context = {**self.context, "case_id": f"{number:02d}-{variant}-{scenario}",
                           "variant": variant, "scenario": scenario}
                folder = output / context["case_id"]
                verdict = facts_and_verdict(folder / "evidence", context)
                revision_kind, revision = revision_identity(self.metadata, variant)
                case = {**context, "round": number, "project": context["case_id"], "outcome": "passed",
                        "exit_code": 0, "revision_kind": revision_kind, "target_revision": revision,
                        "cleaned": True, "image": "test@sha256:" + "a" * 64, "checks": verdict["checks"]}
                if revision_kind == "source_commit":
                    case["source_commit"] = revision
                else:
                    case["artifact_sha256"] = revision.removeprefix("sha256:")
                report["cases"].append(case)
                write_json(folder / "result.json", case)
        write_json(output / "report.json", report)
        return output, report

    def test_missing_evidence_is_not_a_success(self):
        folder = self.root / "evidence"
        facts_and_verdict(folder, self.context)
        (folder / "effect.txt").rename(folder / "effect.missing")
        with self.assertRaises(OSError):
            validate_verdict(folder, self.context)

    def test_tampering_and_stale_context_are_rejected(self):
        folder = self.root / "evidence"
        facts_and_verdict(folder, self.context)
        (folder / "effect.txt").write_text("tampered")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            validate_verdict(folder, self.context)
        facts_and_verdict(folder, self.context)
        with self.assertRaisesRegex(ValueError, "context mismatch"):
            validate_verdict(folder, {**self.context, "run_id": "another"})

    def test_boolean_claim_without_checks_is_rejected(self):
        folder = self.root / "evidence"
        verdict = facts_and_verdict(folder, self.context)
        verdict["checks"] = []
        write_json(folder / "verdict.json", verdict)
        with self.assertRaisesRegex(ValueError, "no checks"):
            validate_verdict(folder, self.context)

    def test_verifier_false_check_cannot_claim_passed(self):
        folder = self.root / "evidence"
        verdict = facts_and_verdict(folder, self.context, passed=False)
        self.assertEqual(validate_verdict(folder, self.context)["outcome"], "failed")
        verdict["outcome"] = "passed"
        write_json(folder / "verdict.json", verdict)
        with self.assertRaisesRegex(ValueError, "disagrees"):
            validate_verdict(folder, self.context)

    def test_evidence_path_traversal_and_symlink_rejected(self):
        folder = self.root / "evidence"
        facts_and_verdict(folder, self.context)
        facts = json.loads((folder / "facts.json").read_text())
        facts["evidence"][0]["path"] = "../outside"
        write_json(folder / "facts.json", facts)
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            validate_verdict(folder, self.context)

    def test_fixture_inventory_and_hashes(self):
        (self.directory / "fixtures/attack.txt").write_text("attack")
        with self.assertRaisesRegex(ValueError, "cover exactly"):
            check_fixtures(self.directory)
        sha = digest(self.directory / "fixtures/attack.txt")
        (self.directory / "fixtures/manifest.toml").write_text(f'[files]\n"attack.txt" = "{sha}"\n')
        (self.directory / "fixtures/__pycache__").mkdir()
        (self.directory / "fixtures/__pycache__/attack.cpython-312.pyc").write_bytes(b"generated")
        check_fixtures(self.directory)

    def test_offline_source_cache_requires_matching_hash(self):
        sha = hashlib.sha256(b"test source").hexdigest()
        self.metadata["build"].update(base_image="base@sha256:" + "a" * 64,
            inputs=[{"name": "source.tar", "url": "https://example.invalid/source.tar", "sha256": sha}])
        for variant in ("vulnerable", "patched"):
            self.metadata[variant].update(commit="a" * 40, archive="source.tar")
        with self.assertRaisesRegex(RunError, "cache miss"):
            fetch_inputs(self.root, self.directory, self.metadata, offline=True)
        cache = self.root / ".cache/sha256" / sha
        cache.write_bytes(b"corrupted")
        with self.assertRaisesRegex(ValueError, "Cache hash mismatch"):
            fetch_inputs(self.root, self.directory, self.metadata, offline=True)
        cache.write_bytes(b"test source")
        self.assertEqual(fetch_inputs(self.root, self.directory, self.metadata, offline=True), {"source.tar": cache})

    def test_binary_build_requires_artifact_inputs_without_source_commits(self):
        self.metadata["provenance"] = {"kind": "binary", "publisher": "Synthetic Vendor"}
        self.metadata["build"].update(base_image="base@sha256:" + "a" * 64,
            inputs=[{"name": "vulnerable.pkg", "url": "https://example.invalid/vulnerable.pkg",
                     "sha256": "1" * 64},
                    {"name": "patched.pkg", "url": "https://example.invalid/patched.pkg",
                     "sha256": "2" * 64}])
        for variant in ("vulnerable", "patched"):
            self.metadata[variant].pop("commit")
            self.metadata[variant].pop("archive")
            self.metadata[variant]["artifact"] = variant + ".pkg"
        self.assertEqual(validate_sources(self.directory, self.metadata), self.metadata["build"]["inputs"])

        self.metadata["patched"]["artifact"] = "missing.pkg"
        with self.assertRaisesRegex(ValueError, "artifact must name a build input"):
            validate_sources(self.directory, self.metadata)

    def test_binary_build_passes_artifact_identity_to_dockerfile(self):
        self.metadata["provenance"] = {"kind": "binary", "publisher": "Synthetic Vendor"}
        self.metadata["build"].update(base_image="base@sha256:" + "a" * 64,
            inputs=[{"name": "vulnerable.pkg", "url": "https://example.invalid/vulnerable.pkg",
                     "sha256": hashlib.sha256(b"vulnerable").hexdigest()},
                    {"name": "patched.pkg", "url": "https://example.invalid/patched.pkg",
                     "sha256": hashlib.sha256(b"patched").hexdigest()}])
        for variant, payload in (("vulnerable", b"vulnerable"), ("patched", b"patched")):
            self.metadata[variant].pop("commit")
            self.metadata[variant].pop("archive")
            self.metadata[variant]["artifact"] = variant + ".pkg"
            cache_file = self.root / ".cache/sha256" / hashlib.sha256(payload).hexdigest()
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_bytes(payload)

        output = self.root / "build-output"
        output.mkdir()
        commands = Mock()
        commands.output = output
        commands.timeout = 60
        builds = []

        def run(args, phase, **kwargs):
            if args[:2] == ["docker", "build"]:
                builds.append(args)
                Path(args[args.index("--iidfile") + 1]).write_text("sha256:" + "b" * 64)
            return "", ""

        commands.run.side_effect = run
        with patch("runner.build.image_check"):
            build_images(self.root, self.directory, self.metadata, commands, offline=True)

        self.assertEqual(len(builds), 2)
        for args, sha in zip(builds, (hashlib.sha256(b"vulnerable").hexdigest(),
                                      hashlib.sha256(b"patched").hexdigest())):
            build_args = {args[index + 1].split("=", 1)[0]: args[index + 1].split("=", 1)[1]
                          for index, value in enumerate(args[:-1]) if value == "--build-arg"}
            self.assertEqual(build_args["ARTIFACT_SHA256"], sha)
            self.assertEqual(build_args["TARGET_REVISION"], "sha256:" + sha)
            self.assertIn(f"org.agent-vulhub.target-revision=sha256:{sha}", args)

    def test_unknown_environment_never_calls_docker(self):
        with patch("runner.cli.ROOT", self.root), patch("runner.runtime.preflight") as docker:
            self.assertEqual(main(["reproduce", "unknown/CVE-2099-99999"]), 2)
            docker.assert_not_called()

    def test_partial_round_and_reused_project_prevent_promotion(self):
        _, report = self.report()
        validate_report(report, report["fingerprint"])
        partial = copy.deepcopy(report)
        partial["cases"].pop()
        with self.assertRaisesRegex(ValueError, "complete rounds"):
            validate_report(partial, report["fingerprint"])
        report["cases"][1]["project"] = report["cases"][0]["project"]
        with self.assertRaisesRegex(ValueError, "independent"):
            validate_report(report, report["fingerprint"])

    def test_cases_from_another_run_prevent_promotion(self):
        _, report = self.report()
        report["cases"][0]["run_id"] = "another-run"
        with self.assertRaisesRegex(ValueError, "run_id"):
            validate_report(report, report["fingerprint"])

    def test_promotion_preserves_evidence_and_invalidates_changed_code(self):
        output, report = self.report()
        promote(self.root, self.directory, self.metadata, output / "report.json", ["maintainer"])
        ready_check(self.root, self.directory, self.metadata)
        (self.directory / "README.zh-cn.md").write_text("documentation only")
        ready_check(self.root, self.directory, self.metadata)
        (self.directory / "reproduce.py").write_text("changed execution")
        self.assertTrue(refresh(self.root, self.directory, self.metadata))
        self.assertEqual(self.metadata["lifecycle"], "draft")
        self.assertEqual(self.metadata["verification"]["mechanism"]["status"], "not_run")
        self.assertTrue((self.directory / "evidence/test-run/report.json").exists())
        self.assertTrue(list((self.directory / "evidence/history").glob("*.json")))

    def test_refresh_invalidates_stale_draft_evidence_and_preserves_history(self):
        output, report = self.report()
        report["fingerprint"] = "0" * 64
        write_json(output / "report.json", report)
        self.metadata["verification"]["mechanism"].update(
            status="passed", evidence=["results/test-run/report.json"])
        write_metadata(self.directory / "metadata.toml", self.metadata)

        self.assertTrue(refresh(self.root, self.directory, self.metadata))
        self.assertEqual(self.metadata["lifecycle"], "draft")
        self.assertEqual(self.metadata["verification"]["mechanism"]["status"], "not_run")
        self.assertEqual(self.metadata["verification"]["mechanism"]["evidence"], [])
        self.assertTrue((output / "report.json").is_file())
        self.assertTrue(list((self.directory / "evidence/history").glob("*.json")))

    def test_refresh_invalidates_stale_adapter_without_dropping_current_mechanism(self):
        output, _ = self.report()
        self.metadata["verification"]["mechanism"].update(
            status="passed", evidence=["results/test-run/report.json"])
        adapter = self.metadata["verification"]["agent_poc"]
        adapter.update(adapter_status="accepted", verified_at="2099-01-01",
                       evidence=["evidence/adapter-review.json"], notes="Synthetic acceptance")
        original_description = adapter["task_description"]
        original_review = copy.deepcopy(adapter.get("task_description_review"))

        with patch("runner.agent_poc.validate_adapter_admission", side_effect=ValueError("stale controls")):
            self.assertTrue(refresh(self.root, self.directory, self.metadata))

        self.assertEqual(self.metadata["verification"]["mechanism"]["status"], "passed")
        self.assertEqual(adapter["adapter_status"], "not_run")
        self.assertEqual(adapter["evidence"], [])
        self.assertEqual(adapter["task_description"], original_description)
        self.assertEqual(adapter.get("task_description_review"), original_review)

    def test_archive_command_records_passed_evidence_without_ready_promotion(self):
        self.metadata["provenance"] = {"kind": "binary", "publisher": "Synthetic Vendor"}
        self.metadata["build"].update(
            base_image="python:3.12-slim@sha256:" + "a" * 64,
            inputs=[
                {"name": "vulnerable.pkg", "url": "https://example.invalid/vulnerable.pkg",
                 "sha256": "1" * 64},
                {"name": "patched.pkg", "url": "https://example.invalid/patched.pkg",
                 "sha256": "2" * 64},
            ],
        )
        for variant in ("vulnerable", "patched"):
            self.metadata[variant].pop("commit")
            self.metadata[variant].pop("archive")
            self.metadata[variant].update(
                version="1.0.0",
                source_url="https://example.invalid/" + variant,
                artifact=variant + ".pkg",
            )
        write_metadata(self.directory / "metadata.toml", self.metadata)
        output, _ = self.report()

        with patch("runner.cli.ROOT", self.root):
            result = main([
                "archive", self.metadata["id"], "--report", str(output / "report.json")])

        self.assertEqual(result, 0)
        retained = read_toml(self.directory / "metadata.toml")
        self.assertEqual(retained["lifecycle"], "draft")
        self.assertEqual(retained["verification"]["mechanism"]["status"], "passed")
        self.assertEqual(
            retained["verification"]["mechanism"]["evidence"],
            ["evidence/test-run/report.json"],
        )
        self.assertTrue((self.directory / "evidence/test-run/manifest.json").is_file())
        self.assertNotIn("review", retained)
        self.assertEqual(len(check(self.root)), 1)

    def test_binary_report_and_promotion_bind_to_release_hashes(self):
        self.metadata["provenance"] = {"kind": "binary", "publisher": "Synthetic Vendor"}
        self.metadata["build"]["inputs"] = []
        for index, variant in enumerate(("vulnerable", "patched"), start=1):
            name = variant + ".pkg"
            self.metadata[variant].update(version="1.0.0", source_url=f"https://example.invalid/{variant}",
                                          artifact=name)
            self.metadata[variant].pop("commit")
            self.metadata[variant].pop("archive")
            self.metadata["build"]["inputs"].append({
                "name": name, "url": f"https://example.invalid/{name}", "sha256": str(index) * 64})

        output, report = self.report()
        self.assertEqual(report["cases"][0]["revision_kind"], "artifact_sha256")
        self.assertEqual(report["cases"][0]["target_revision"], "sha256:" + "1" * 64)
        validate_report(report, report["fingerprint"])
        promote(self.root, self.directory, self.metadata, output / "report.json", ["maintainer"])
        ready_check(self.root, self.directory, self.metadata)

    def test_agent_poc_report_cannot_promote_as_mechanism(self):
        output, report = self.report()
        report["layer"] = "agent_poc"
        write_json(output / "report.json", report)
        with self.assertRaisesRegex(ValueError, "Only mechanism reports"):
            promote(self.root, self.directory, self.metadata, output / "report.json", ["maintainer"])

    def test_exception_requires_second_distinct_reviewer(self):
        self.metadata["runtime"]["exceptions"] = [{"rule": "network.lab.internal", "reason": "reviewed"}]
        output, _ = self.report()
        with self.assertRaisesRegex(ValueError, "2 distinct"):
            promote(self.root, self.directory, self.metadata, output / "report.json", ["one", "one"])

    def test_published_manifest_must_bind_current_inputs_before_any_push(self):
        from runner.publish import publish
        from runner.runtime import Commands
        manifest = self.root / "build.json"
        write_json(manifest, {"environment_id": self.metadata["id"], "input_binding": "stale"})
        commands = Commands(self.root / "logs")
        with patch.object(commands, "run") as call, self.assertRaisesRegex(ValueError, "stale"):
            publish(self.root, self.directory, self.metadata, manifest, "ghcr.io/test/synthetic", commands)
        call.assert_not_called()

    def test_archived_evidence_cannot_silently_disappear_from_manifest(self):
        output, _ = self.report()
        archive = promote(self.root, self.directory, self.metadata, output / "report.json", ["maintainer"])
        write_json(archive / "manifest.json", {})
        with self.assertRaisesRegex(ValueError, "cover retained"):
            ready_check(self.root, self.directory, self.metadata)

    def test_preflight_failure_leaves_diagnostic_report(self):
        args = Namespace(rounds=3, timeout=10, build=False, images=None, offline=True,
                         allow_exceptions=False, scenario="all", keep_on_failure=False)
        with patch("runner.runtime.preflight", side_effect=RunError("preflight", "Docker missing", 2, "not_run")):
            code = reproduce(self.root, self.directory, self.metadata, args)
        self.assertEqual(code, 2)
        report = json.loads(next((self.root / "results").rglob("report.json")).read_text())
        self.assertEqual(report["failure"]["actual"], "Docker missing")
        self.assertEqual(report["cases"], [])

    def test_agent_evaluation_requires_an_accepted_adapter_before_docker(self):
        args = Namespace(rounds=1, timeout=10, build=False, images=None, offline=True,
                         allow_exceptions=False, scenario="all", keep_on_failure=False)
        candidate = CandidateSpec(self.root, ("python3", "/candidate/poc.py"), 10, 1024, "a" * 64, "b" * 64)
        task = {"task_sha256": "c" * 64, "difficulty": 1}
        with patch("runner.runtime.preflight") as docker:
            code = reproduce(self.root, self.directory, self.metadata, args, candidate=candidate,
                             layer="agent_poc", task=task)
        self.assertEqual(code, 2)
        docker.assert_not_called()
        report_path = next((self.root / "results" / self.metadata["id"] / "agent-poc").rglob("report.json"))
        report = json.loads(report_path.read_text())
        self.assertEqual(report["failure"]["phase"], "agent_adapter")

    def test_adapter_control_requires_mechanism_evidence_before_docker(self):
        args = Namespace(rounds=3, timeout=10, build=False, images=None, offline=True,
                         allow_exceptions=False, keep_on_failure=False)
        candidate = CandidateSpec(self.root, ("python3", "/candidate/poc.py"), 10, 1024,
                                  "a" * 64, "b" * 64)
        task = {"task_sha256": "c" * 64, "difficulty": 1}
        with patch("runner.runtime.preflight") as docker:
            code = reproduce(self.root, self.directory, self.metadata, args, candidate=candidate,
                             layer="agent_poc", task=task, control_role="positive")
        self.assertEqual(code, 2)
        docker.assert_not_called()
        report_path = next((self.root / "results" / self.metadata["id"] / "agent-poc").rglob("report.json"))
        report = json.loads(report_path.read_text())
        self.assertEqual(report["adapter_control_role"], "positive")
        self.assertIn("current passed mechanism evidence", report["failure"]["actual"])

    def test_agent_evaluation_rejects_accepted_adapter_without_current_evidence(self):
        args = Namespace(rounds=1, timeout=10, build=False, images=None, offline=True,
                         allow_exceptions=False, scenario="all", keep_on_failure=False)
        candidate = CandidateSpec(self.root, ("python3", "/candidate/poc.py"), 10, 1024, "a" * 64, "b" * 64)
        task = {"task_sha256": "c" * 64, "difficulty": 1}
        metadata = copy.deepcopy(self.metadata)
        metadata["verification"]["agent_poc"].update(
            adapter_status="accepted", verified_at="2099-01-01T00:00:00Z",
            task_sha256=task["task_sha256"],
            evidence=["evidence/missing-review.md"], notes="Synthetic stale acceptance.")
        with patch("runner.runtime.preflight") as docker:
            code = reproduce(self.root, self.directory, metadata, args, candidate=candidate,
                             layer="agent_poc", task=task)
        self.assertEqual(code, 2)
        docker.assert_not_called()
        report_path = next((self.root / "results" / metadata["id"] / "agent-poc").rglob("report.json"))
        report = json.loads(report_path.read_text())
        self.assertEqual(report["failure"]["phase"], "agent_adapter")
        self.assertIn("current passed mechanism evidence", report["failure"]["actual"])

    def test_agent_evaluation_rejects_task_not_bound_to_accepted_adapter(self):
        args = Namespace(rounds=1, timeout=10, build=False, images=None, offline=True,
                         allow_exceptions=False, scenario="all", keep_on_failure=False)
        candidate = CandidateSpec(self.root, ("python3", "/candidate/poc.py"), 10, 1024,
                                  "a" * 64, "b" * 64)
        metadata = copy.deepcopy(self.metadata)
        metadata["verification"]["agent_poc"].update(
            adapter_status="accepted", task_sha256="d" * 64)
        task = {"task_sha256": "c" * 64, "difficulty": 1}
        with patch("runner.agent_poc.validate_adapter_admission") as admission, \
                patch("runner.runtime.preflight") as docker:
            code = reproduce(self.root, self.directory, metadata, args, candidate=candidate,
                             layer="agent_poc", task=task)
        self.assertEqual(code, 2)
        admission.assert_not_called()
        docker.assert_not_called()
        report_path = next((self.root / "results" / metadata["id"] / "agent-poc").rglob("report.json"))
        report = json.loads(report_path.read_text())
        self.assertEqual(report["failure"]["phase"], "agent_adapter")
        self.assertIn("exact task_sha256", report["failure"]["actual"])

    def test_agent_evaluation_rejects_level_zero_task_even_if_hash_matches(self):
        args = Namespace(rounds=1, timeout=10, build=False, images=None, offline=True,
                         allow_exceptions=False, scenario="all", keep_on_failure=False)
        candidate = CandidateSpec(self.root, ("python3", "/candidate/poc.py"), 10, 1024,
                                  "a" * 64, "b" * 64)
        metadata = copy.deepcopy(self.metadata)
        metadata["verification"]["agent_poc"].update(
            adapter_status="accepted", task_sha256="d" * 64)
        task = {"task_sha256": "d" * 64, "difficulty": 0}
        with patch("runner.agent_poc.validate_adapter_admission") as admission, \
                patch("runner.runtime.preflight") as docker:
            code = reproduce(self.root, self.directory, metadata, args, candidate=candidate,
                             layer="agent_poc", task=task)
        self.assertEqual(code, 2)
        admission.assert_not_called()
        docker.assert_not_called()
        report_path = next((self.root / "results" / metadata["id"] / "agent-poc").rglob("report.json"))
        report = json.loads(report_path.read_text())
        self.assertEqual(report["failure"]["phase"], "agent_adapter")
        self.assertIn("Level 1 task package", report["failure"]["actual"])

    def test_mcp_input_candidate_runs_through_trusted_harness(self):
        output = self.root / "mcp-case"
        output.mkdir()
        candidate_dir = self.root / "mcp-candidate"
        candidate_dir.mkdir()
        (candidate_dir / "attack.json").write_text('{"path":"linked-marker.txt"}\n')
        (candidate_dir / "benign.json").write_text('{"path":"benign.txt"}\n')
        candidate = CandidateSpec(candidate_dir, (), 30, 1024, "a" * 64, "b" * 64,
                                  format="mcp_tool_inputs",
                                  files=(("attack", "attack.json"), ("benign", "benign.json")))
        config = {"services": {"vulnerable": {"volumes": [
            {"source": "results", "target": "/lab/results"}]}},
            "volumes": {"results": {}}}
        child = Mock()
        calls = []

        def run(command, phase, **kwargs):
            calls.append((command, phase))
            if command[:2] == ["docker", "inspect"]:
                project = command[-1].removesuffix("-target")
                return 0, json.dumps([{"Config": {"Labels": {
                    "com.docker.compose.project": project}}}])
            return 0, ""

        child.run.side_effect = run
        parent = Mock()
        parent.output = output
        parent.timeout = 30
        metadata = copy.deepcopy(self.metadata)
        metadata["runtime"].update(mode="oneshot", harness="node")
        report = {"run_id": "test-run", "platform": "linux/amd64",
                  "runner_fingerprint": "runner", "docker_version": "docker",
                  "compose_version": "compose"}
        images = {variant: "test@sha256:" + "a" * 64 for variant in ("vulnerable", "patched")}
        args = Namespace(timeout=30, allow_exceptions=False, keep_on_failure=False)
        passed = {"outcome": "passed", "checks": []}

        with patch("runner.runtime.Commands", return_value=child):
            with patch("runner.runtime.inspect_config", return_value=config):
                with patch("runner.runtime.validate_verdict", return_value=passed):
                    result = run_case(parent, self.directory, metadata, images, report, 1,
                                      "vulnerable", "attack", args, candidate=candidate, layer="agent_poc")

        self.assertEqual(result["outcome"], "passed")
        harness_calls = [command for command, phase in calls if phase == "reproduce"]
        self.assertEqual(len(harness_calls), 1)
        self.assertRegex(harness_calls[0][2], r"avh-[a-f0-9]+-target")
        self.assertIn("/lab/reproduce.py", harness_calls[0])
        self.assertNotIn("--user", harness_calls[0])
        self.assertNotIn("AVH_AGENT_CONTEXT", harness_calls[0])
        self.assertTrue(any(command[-1].endswith(":/lab/results/candidate-input.json")
                            for command, _ in calls if command[:2] == ["docker", "cp"]))
        self.assertFalse(any(command[:2] == ["docker", "run"] and "-d" in command
                             for command, _ in calls))

    def test_mcp_path_candidate_runs_through_trusted_harness(self):
        output = self.root / "mcp-path-case"
        output.mkdir()
        candidate_dir = self.root / "mcp-path-candidate"
        candidate_dir.mkdir()
        (candidate_dir / "attack.json").write_text('{"path":"../project2/marker.txt"}\n')
        (candidate_dir / "benign.json").write_text('{"path":"benign.txt"}\n')
        candidate = CandidateSpec(candidate_dir, (), 30, 1024, "a" * 64, "b" * 64,
                                  format="mcp_path_inputs",
                                  files=(("attack", "attack.json"), ("benign", "benign.json")))
        config = {"services": {"vulnerable": {"volumes": [
            {"source": "results", "target": "/lab/results"}]}},
            "volumes": {"results": {}}}
        child = Mock()
        calls = []

        def run(command, phase, **kwargs):
            calls.append((command, phase))
            if command[:2] == ["docker", "inspect"]:
                project = command[-1].removesuffix("-target")
                return 0, json.dumps([{"Config": {"Labels": {
                    "com.docker.compose.project": project}}}])
            return 0, ""

        child.run.side_effect = run
        parent = Mock()
        parent.output = output
        parent.timeout = 30
        metadata = copy.deepcopy(self.metadata)
        metadata["runtime"].update(mode="oneshot", harness="node")
        report = {"run_id": "test-run", "platform": "linux/amd64",
                  "runner_fingerprint": "runner", "docker_version": "docker",
                  "compose_version": "compose"}
        images = {variant: "test@sha256:" + "a" * 64 for variant in ("vulnerable", "patched")}
        args = Namespace(timeout=30, allow_exceptions=False, keep_on_failure=False)
        passed = {"outcome": "passed", "checks": []}

        with patch("runner.runtime.Commands", return_value=child):
            with patch("runner.runtime.inspect_config", return_value=config):
                with patch("runner.runtime.validate_verdict", return_value=passed):
                    result = run_case(parent, self.directory, metadata, images, report, 1,
                                      "vulnerable", "attack", args, candidate=candidate, layer="agent_poc")

        self.assertEqual(result["outcome"], "passed")
        harness_calls = [command for command, phase in calls if phase == "reproduce"]
        self.assertEqual(len(harness_calls), 1)
        self.assertIn("/lab/reproduce.py", harness_calls[0])
        self.assertTrue(any(command[-1].endswith(":/lab/results/candidate-input.json")
                            for command, _ in calls if command[:2] == ["docker", "cp"]))

    def test_agent_candidate_and_verifier_use_separate_containers(self):
        config = {"services": {"vulnerable": {"volumes": [
            {"source": "results", "target": "/lab/results"}]}},
                  "volumes": {"results": {}}}
        candidate_name, candidate = _candidate_container_command(
            "image@sha256:" + "a" * 64, "target-container", "project")
        self.assertEqual(candidate_name, "project-candidate")
        self.assertIn("container:target-container", candidate)
        self.assertTrue(any(arg.startswith("type=tmpfs,destination=/lab/results,tmpfs-size=16777216")
                            for arg in candidate))
        self.assertIn("--memory", candidate)
        self.assertIn("--cpus", candidate)
        self.assertNotIn("/lab/verify.py", candidate)

        verifier_name, verifier = _verifier_container_command(
            "image@sha256:" + "a" * 64, "project", config, "vulnerable", "python3")
        self.assertEqual(verifier_name, "project-verifier")
        self.assertIn("--rm", verifier)
        self.assertIn("--network", verifier)
        self.assertIn("none", verifier)
        self.assertIn("/lab/verify.py", verifier)
        self.assertNotIn("container:target-container", verifier)

    def test_candidate_facts_are_rebuilt_and_output_is_copied_to_verifier_namespace(self):
        output = self.root / "candidate-case"
        output.mkdir()
        context = {"schema_version": 1, "run_id": "run", "case_id": "01-vulnerable-attack",
                   "variant": "vulnerable", "scenario": "attack", "layer": "agent_poc"}
        child = Mock()

        def run(command, phase, **kwargs):
            if phase == "candidate_collect":
                collected = Path(command[-1])
                (collected / "facts.json").write_text('{"execution_status":"completed","evidence":[]}\n')
                (collected / "verdict.json").write_text('{"outcome":"passed"}\n')
                (collected / "context.json").write_text('{"variant":"patched"}\n')
                (collected / "observation.json").write_text('{"candidate_claim":"success"}\n')
            return 0, ""

        child.run.side_effect = run
        _collect_candidate_facts(child, "candidate", "target", output, context)

        facts = json.loads((output / "candidate-evidence/facts.json").read_text())
        self.assertEqual(facts, {**context, "execution_status": "completed", "evidence": [
            {"path": "candidate-output/observation.json",
             "sha256": digest(output / "candidate-artifacts/observation.json")} ]})
        self.assertEqual((output / "candidate-artifacts/observation.json").read_text(),
                         '{"candidate_claim":"success"}\n')
        commands = [call.args[0] for call in child.run.call_args_list]
        self.assertTrue(any(command[-1] == "/lab/results/candidate-output" and "mkdir" in command
                            for command in commands))
        self.assertTrue(any(command[-1].endswith(":/lab/results/facts.json") for command in commands))

    def test_candidate_output_rejects_symlinks_and_oversize_files(self):
        context = {"schema_version": 1, "run_id": "run", "case_id": "01-vulnerable-attack",
                   "variant": "vulnerable", "scenario": "attack", "layer": "agent_poc"}

        for filename, prepare in (
                ("symlink", lambda path: path.symlink_to(self.root / "outside")),
                ("oversize", lambda path: path.write_bytes(b"x" * (8 * 1024 * 1024 + 1)))):
            with self.subTest(filename=filename):
                output = self.root / ("candidate-" + filename)
                output.mkdir()
                child = Mock()

                def run(command, phase, **kwargs):
                    if phase == "candidate_collect":
                        Path(command[-1]).mkdir(exist_ok=True)
                        prepare(Path(command[-1]) / filename)
                    return 0, ""

                child.run.side_effect = run
                expected = "invalid evidence path" if filename == "symlink" else "exceeds 8 MiB"
                with self.assertRaisesRegex(ValueError, expected):
                    _collect_candidate_facts(child, "candidate", "target", output, context)
                self.assertFalse(any(call.args[1] == "candidate_setup" for call in child.run.call_args_list))


class ComposePolicyTests(unittest.TestCase):
    def config(self):
        images = {v: "image@sha256:" + "a" * 64 for v in ("vulnerable", "patched")}
        services = {v: {"image": image, "profiles": [v], "mem_limit": 1024,
                       "cpus": 1, "pids_limit": 32, "cap_drop": ["ALL"],
                       "security_opt": ["no-new-privileges:true"], "networks": {"lab": {}},
                       "volumes": [{"type": "volume", "source": "results",
                                    "target": "/lab/results"}]}
                    for v, image in images.items()}
        return {"name": "avh-test", "services": services, "networks": {"lab": {"internal": True}},
                "volumes": {"results": {}}}, images

    def test_bind_mount_and_shared_name_rejected(self):
        config, images = self.config()
        validate_compose(config, images)
        config["services"]["vulnerable"]["volumes"].append(
            {"type": "bind", "source": "/tmp", "target": "/host"})
        with self.assertRaisesRegex(ValueError, "bind_mounts"):
            validate_compose(config, images)

    def test_target_results_volume_is_required(self):
        config, images = self.config()
        config["services"]["vulnerable"]["volumes"] = []
        with self.assertRaisesRegex(ValueError, "managed /lab/results"):
            validate_compose(config, images)

    def test_local_immutable_image_ids_are_valid_targets(self):
        config, images = self.config()
        for name in images:
            images[name] = "sha256:" + "1" * 64
            config["services"][name]["image"] = images[name]
        validate_compose(config, images)

    def test_project_resource_names_cannot_be_shared(self):
        config, images = self.config()
        config["networks"]["lab"]["name"] = "shared-network"
        with self.assertRaisesRegex(ValueError, "project-scoped"):
            validate_compose(config, images)

    def test_targets_cannot_depend_on_other_variant(self):
        config, images = self.config()
        config["services"]["vulnerable"]["depends_on"] = {"patched": {"condition": "service_started"}}
        with self.assertRaisesRegex(ValueError, "activate a target"):
            validate_compose(config, images)

    def test_unknown_escape_hatches_fail_closed(self):
        for key in ("pid", "ipc", "env_file", "build", "container_name"):
            config, images = self.config()
            config["services"]["vulnerable"][key] = "host"
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "Unsupported"):
                validate_compose(config, images)

    def test_exception_needs_documentation_and_explicit_opt_in(self):
        config, images = self.config()
        config["networks"]["lab"]["internal"] = False
        exceptions = [{"rule": "network.lab.internal", "reason": "controlled endpoint"}]
        with self.assertRaises(ValueError):
            validate_compose(config, images, exceptions)
        validate_compose(config, images, exceptions, True)

    def test_declared_subnet_needs_the_subnet_exception(self):
        config, images = self.config()
        config["networks"]["lab"]["ipam"] = {"config": [{"subnet": "10.200.0.0/24"}]}
        exceptions = [{"rule": "network.lab.subnet", "reason": "host pools exhausted"}]
        with self.assertRaisesRegex(ValueError, "network.lab.subnet"):
            validate_compose(config, images)
        with self.assertRaisesRegex(ValueError, "network.lab.subnet"):
            validate_compose(config, images, exceptions)
        validate_compose(config, images, exceptions, True)

    def test_empty_ipam_from_compose_config_stays_accepted(self):
        # `docker compose config` always emits an empty ipam mapping; it must not require
        # the exception.
        config, images = self.config()
        config["networks"]["lab"]["ipam"] = {}
        validate_compose(config, images)

    def test_subnet_allocation_skips_host_networks(self):
        used = [ipaddress.ip_network("10.200.0.0/24"), ipaddress.ip_network("10.200.1.0/24")]
        with patch("runner.runtime.host_subnets", return_value=used):
            chosen = allocate_subnet("10.200.0.0/16", "avh-0000")
        self.assertNotIn(chosen, used)
        self.assertEqual(chosen.prefixlen, 24)
        self.assertTrue(chosen.subnet_of(ipaddress.ip_network("10.200.0.0/16")))

    def test_subnet_pool_must_hold_a_slash_24(self):
        with self.assertRaisesRegex(ValueError, "IPv4 network of /16 or larger"):
            allocate_subnet("10.200.0.0/20", "avh-0000")
        with self.assertRaisesRegex(ValueError, "IPv4 network of /16 or larger"):
            allocate_subnet("2001:db8::/32", "avh-0000")

    def test_network_pool_is_injected_for_the_run(self):
        config = {"name": "avh-test", "networks": {"lab": {"name": "avh-test_lab",
                  "ipam": {}, "internal": True}}}
        metadata = {"runtime": {"network_pool": "10.200.0.0/16"}}
        with patch("runner.runtime.host_subnets", return_value=[]):
            apply_network_subnet(config, metadata, "avh-test")
        subnet = ipaddress.ip_network(
            config["networks"]["lab"]["ipam"]["config"][0]["subnet"], strict=True)
        self.assertEqual(subnet.prefixlen, 24)
        self.assertTrue(subnet.subnet_of(ipaddress.ip_network("10.200.0.0/16")))

    def test_slash_16_pool_still_spreads_across_projects(self):
        """A /16 holds exactly 256 /24s; the spread must not be skipped at that size."""
        projects = ["avh-" + f"{index:04d}" for index in range(24)]
        with patch("runner.runtime.host_subnets", return_value=[]):
            chosen = {project: allocate_subnet("10.200.0.0/16", project) for project in projects}
        self.assertEqual(len(set(chosen.values())), len(projects))

    def test_host_pool_exhaustion_needs_no_recipe_declaration(self):
        """Regression: every environment had to declare a pool to survive a busy host.

        Docker's own default pools are finite and a shared host exhausts them, so
        compose could not create the lab network and every case died in compose_up.
        Requiring `runtime.network_pool` made that host detail part of every recipe.
        The tool layer now allocates on its own.
        """
        config = {"name": "avh-test", "networks": {"lab": {"name": "avh-test_lab",
                  "ipam": {}, "internal": True}}}
        # The two default ranges Docker would otherwise try are both taken.
        exhausted = [ipaddress.ip_network(f"172.{n}.0.0/16") for n in range(17, 32)]
        exhausted += [ipaddress.ip_network(f"192.168.{n}.0/20") for n in range(0, 256, 16)]
        with patch("runner.runtime.host_subnets", return_value=exhausted):
            apply_network_subnet(config, {"runtime": {}}, "avh-test")
        subnet = ipaddress.ip_network(
            config["networks"]["lab"]["ipam"]["config"][0]["subnet"], strict=True)
        self.assertEqual(subnet.prefixlen, 24)
        self.assertTrue(subnet.subnet_of(ipaddress.ip_network("10.0.0.0/8")))
        self.assertFalse(any(subnet.overlaps(other) for other in exhausted))

    def test_tool_allocated_subnet_needs_no_exception(self):
        """The exception guards recipe-declared subnets, not the tool's own allocation."""
        config, images = self.config()
        config["networks"]["lab"]["ipam"] = {"config": [{"subnet": "10.50.50.0/24"}]}
        with self.assertRaisesRegex(ValueError, "network.lab.subnet"):
            validate_compose(config, images)
        # Same populated ipam, but it came from apply_network_subnet.
        validate_compose(config, images, (), False, tool_allocated=True)

    def test_fallback_allocation_terminates_when_blocks_are_taken(self):
        """The scan is bounded and still finds a free /16 behind occupied ones."""
        used = [ipaddress.ip_network(f"10.{n}.0.0/16") for n in range(0, 40)]
        with patch("runner.runtime.host_subnets", return_value=used):
            block = fallback_pool("avh-0000", used)
        self.assertTrue(block.subnet_of(ipaddress.ip_network("10.0.0.0/8")))
        self.assertFalse(any(block.overlaps(other) for other in used))

    def test_host_scan_survives_a_network_vanishing_mid_scan(self):
        """Concurrent cases remove networks while we scan them.

        `docker network ls` lists a name, another case tears its project down, and
        `docker network inspect` then exits non-zero. That race is host plumbing, not
        the mechanism, so the scan must retry instead of failing the whole case with
        `invalid_evidence`.
        """
        from runner import runtime

        real_run = subprocess.run
        calls = {"n": 0}

        def flaky(command, *args, **kwargs):
            if command[:3] == ["docker", "network", "inspect"]:
                calls["n"] += 1
                if calls["n"] == 1:
                    return subprocess.CompletedProcess(command, 1, "", "no such network")
                return subprocess.CompletedProcess(command, 0, "10.9.9.0/24 ", "")
            if command[:3] == ["docker", "network", "ls"]:
                return subprocess.CompletedProcess(command, 0, "net-a\nnet-b\n", "")
            return real_run(command, *args, **kwargs)

        with patch.object(runtime, "_HOST_SUBNETS_CACHE", None), \
                patch("runner.runtime.subprocess.run", side_effect=flaky):
            subnets = runtime.host_subnets()
        self.assertEqual(subnets, [ipaddress.ip_network("10.9.9.0/24")])
        self.assertGreaterEqual(calls["n"], 2)

    def test_host_scan_cache_is_dropped_between_cases(self):
        """Each case tears its network down, so a cached scan goes stale."""
        from runner import runtime

        with patch.object(runtime, "_HOST_SUBNETS_CACHE", [ipaddress.ip_network("10.1.0.0/24")]):
            runtime.invalidate_host_subnets()
            self.assertIsNone(runtime._HOST_SUBNETS_CACHE)


if __name__ == "__main__":
    unittest.main()
