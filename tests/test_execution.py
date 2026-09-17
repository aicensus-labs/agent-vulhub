"""Protocol and lifecycle tests never execute environment code or Docker."""

from argparse import Namespace
import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from runner.cli import ROOT, main, read_toml, scaffold
from runner.build import fetch_inputs
from runner.compose import validate_compose
from runner.lifecycle import promote, ready_check, refresh
from runner.protocol import (CASES, check_fixtures, digest, fingerprint, validate_report,
                             validate_verdict, write_json)
from runner.runtime import RunError, reproduce


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
                case = {**context, "round": number, "project": context["case_id"], "outcome": "passed",
                        "exit_code": 0, "source_commit": "a" * 40,
                        "cleaned": True, "image": "test@sha256:" + "a" * 64, "checks": verdict["checks"]}
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


if __name__ == "__main__":
    unittest.main()
