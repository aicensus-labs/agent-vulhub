import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "environments/mcp-filesystem/CVE-2025-53110/verify.py"
NODE = shutil.which("node")


@unittest.skipUnless(NODE, "Node.js is required to exercise the MCP verifier")
class McpPathVerifierTests(unittest.TestCase):
    def run_verifier(self, read_relative_path=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "output"
        project = output / "project"
        project2 = output / "project2"
        project.mkdir(parents=True)
        project2.mkdir()
        (project / "benign.txt").write_text("benign filesystem read\n", encoding="utf-8")
        marker = "MCP_FILESYSTEM_CVE_2025_53110_MARKER\n"
        (project2 / "marker.txt").write_text(marker, encoding="utf-8")

        context = {
            "schema_version": 1,
            "run_id": "test-run",
            "case_id": "01-vulnerable-attack",
            "variant": "vulnerable",
            "scenario": "attack",
            "layer": "agent_poc",
        }
        candidate = {"calls": [
            {"tool": "list_directory", "scope": "sibling"},
            {"tool": "read_file", "from_list": 0, "entries": "all"},
        ]}
        candidate_bytes = (json.dumps(candidate) + "\n").encode("utf-8")
        candidate_file = output / "candidate-input.json"
        candidate_file.write_bytes(candidate_bytes)
        allowed = project.resolve()
        sibling = project2.resolve()
        listing_response = {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"content": [{"type": "text", "text": "[FILE] marker.txt"}]},
        }
        read_response = {
            "jsonrpc": "2.0",
            "id": 3,
            "result": {"content": [{"type": "text", "text": marker}]},
        }
        tool_calls = [
            {
                "tool": "list_directory",
                "arguments": {"path": str(sibling)},
                "response": listing_response,
            },
            {
                "tool": "read_file",
                "arguments": {"path": str((output / read_relative_path).resolve())
                    if read_relative_path else str(sibling / "marker.txt")},
                "response": read_response,
            },
        ]
        observation = {
            "schema_version": 1,
            "context": {key: context[key] for key in (
                "schema_version", "run_id", "case_id", "variant", "scenario"
            )},
            "target_ready": True,
            "candidate_plan": candidate,
            "candidate_input_sha256": hashlib.sha256(candidate_bytes).hexdigest(),
            "allowed_directory": str(allowed),
            "sibling_directory": str(sibling),
            "tool_calls": tool_calls,
            "marker_observed": True,
        }
        observation_file = output / "observation.json"
        observation_bytes = (json.dumps(observation) + "\n").encode("utf-8")
        observation_file.write_bytes(observation_bytes)
        evidence = [
            {
                "path": "observation.json",
                "sha256": hashlib.sha256(observation_bytes).hexdigest(),
            },
            {
                "path": "project2/marker.txt",
                "sha256": hashlib.sha256((project2 / "marker.txt").read_bytes()).hexdigest(),
            },
            {
                "path": "candidate-input.json",
                "sha256": hashlib.sha256(candidate_bytes).hexdigest(),
            },
        ]
        facts = {
            "schema_version": 1,
            **{key: context[key] for key in (
                "schema_version", "run_id", "case_id", "variant", "scenario"
            )},
            "execution_status": "completed",
            "evidence": evidence,
        }
        (output / "facts.json").write_text(json.dumps(facts), encoding="utf-8")
        context_file = Path(temporary.name) / "context.json"
        context_file.write_text(json.dumps(context), encoding="utf-8")
        return subprocess.run(
            [NODE, str(VERIFY), "--context", str(context_file), "--output", str(output)],
            capture_output=True,
            text=True,
            check=False,
        ), output

    def test_attack_candidate_must_resolve_to_the_sibling_marker(self):
        completed, output = self.run_verifier()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        verdict = json.loads((output / "verdict.json").read_text(encoding="utf-8"))
        self.assertEqual(verdict["outcome"], "passed")

    def test_attack_candidate_cannot_reuse_a_different_resolved_path(self):
        completed, _ = self.run_verifier("project/benign.txt")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("read_file arguments were not derived from the listing response", completed.stderr)


if __name__ == "__main__":
    unittest.main()
