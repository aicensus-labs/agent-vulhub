import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

from runner import lab_support


ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT = ROOT / "environments/network-ai/CVE-2026-58482"
sys.modules.setdefault("lab_support", lab_support)


def load_environment_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


reproduce = load_environment_module("network_ai_reproduce", ENVIRONMENT / "reproduce.py")
verify = load_environment_module("network_ai_verify", ENVIRONMENT / "verify.py")


class NetworkAiAgentPocTests(unittest.TestCase):
    def test_operator_name_placeholder_renders_recursively(self):
        request = {
            "approvedBy": "$AVH_OPERATOR_NAME",
            "details": ["reviewed by $AVH_OPERATOR_NAME", {"owner": "$AVH_OPERATOR_NAME"}],
        }
        expected = {
            "approvedBy": "release-operator",
            "details": ["reviewed by release-operator", {"owner": "release-operator"}],
        }
        self.assertEqual(reproduce._render_operator_name(request), expected)
        self.assertEqual(verify._render_operator_name(request), expected)

    def test_verifier_binds_rendered_candidate_body_and_dynamic_id(self):
        candidate = {
            "method": "POST",
            "path": "/approvals/{id}/approve",
            "headers": {"Authorization": "Bearer $AVH_OPERATOR_TOKEN"},
            "body": {"approvedBy": "$AVH_OPERATOR_NAME", "reason": "planned change"},
        }
        exchange = {
            "enumerate": {"body": json.dumps([{"id": "pending-123"}])},
            "approve": {
                "method": "POST",
                "path": "/approvals/pending-123/approve",
                "request_body": json.dumps({
                    "approvedBy": "release-operator",
                    "reason": "planned change",
                }),
                "request_headers": {"Authorization": "Bearer synthetic-secret"},
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            candidate_path = Path(temporary) / "candidate-input.json"
            candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
            problems = verify._candidate_request_problems(
                exchange, {"candidate-input.json": candidate_path}
            )
        self.assertEqual(problems, [])

        exchange["approve"]["request_body"] = json.dumps({"approvedBy": "attacker"})
        with tempfile.TemporaryDirectory() as temporary:
            candidate_path = Path(temporary) / "candidate-input.json"
            candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
            problems = verify._candidate_request_problems(
                exchange, {"candidate-input.json": candidate_path}
            )
        self.assertIn("the recorded HTTP body differs from candidate-input.json", problems)

    def test_mechanism_requires_the_id_returned_by_http_enumeration(self):
        observation = {
            "target_ready": True,
            "node_exit_code": 0,
            "driver_errors": [],
            "id_source": "http_enumeration",
        }
        exchange = {
            "enumerate": {
                "status": 200,
                "path": "/approvals/?status=pending",
                "body": json.dumps([{"id": "pending-123"}]),
            },
            "approve": {
                "method": "POST",
                "path": "/approvals/pending-123/approve",
            },
        }
        action = {"name": "synthetic pending action"}
        self.assertEqual(verify._shared_problems(observation, exchange, action), [])

        observation["id_source"] = "in_process"
        problems = verify._shared_problems(observation, exchange, action)
        self.assertIn(
            "the approval ID was not obtained from the HTTP enumeration response",
            problems,
        )

    def test_mechanism_rejects_empty_enumeration_and_unrelated_approve_id(self):
        observation = {
            "target_ready": True,
            "node_exit_code": 0,
            "driver_errors": [],
            "id_source": "http_enumeration",
        }
        exchange = {
            "enumerate": {
                "status": 200,
                "path": "/approvals/?status=pending",
                "body": "[]",
            },
            "approve": {"method": "POST", "path": "/approvals/guessed/approve"},
        }
        problems = verify._shared_problems(observation, exchange, {"name": "pending"})
        self.assertIn("HTTP enumeration returned no pending approval ID", problems)

        exchange["enumerate"]["body"] = json.dumps([{"id": "pending-123"}])
        problems = verify._shared_problems(observation, exchange, {"name": "pending"})
        self.assertIn("approve path does not use the ID returned by HTTP enumeration", problems)


if __name__ == "__main__":
    unittest.main()
