"""Independent verifier for Agent Device credential redirection."""

import argparse
import hashlib
import json
from pathlib import Path
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    context = json.loads(Path(args.context).read_text())
    output = Path(args.output)
    facts = json.loads((output / "facts.json").read_text())
    observation = json.loads((output / "observation.json").read_text())
    for key in ("schema_version", "run_id", "case_id", "variant", "scenario"):
        if facts[key] != context[key] or observation["context"][key] != context[key]:
            raise ValueError(f"context mismatch: {key}")
    evidence_entry = next((item for item in facts["evidence"] if item["path"] == "observation.json"), None)
    if evidence_entry is None or evidence_entry["sha256"] != digest(output / "observation.json"):
        raise ValueError("observation evidence hash mismatch")

    requests = observation["observations"]
    token_requests = [item for item in requests if item["authorization"] == "Bearer poc-secret-token" and item["x_agent_device_token"] == "poc-secret-token"]
    evidence = ["observation.json"]
    checks = [{
        "id": "target_ready", "passed": bool(observation["target_ready"] and observation["return_code"] is not None),
        "expected": "The upstream CLI executes to a terminal state", "actual": f"return_code={observation['return_code']}",
        "reason": "The complete upstream build is present and the CLI invocation completed or reported its rejection.", "evidence": evidence,
    }]
    if context["scenario"] == "benign":
        checks.append({
            "id": "benign_task_passed", "passed": not token_requests and observation["configured_project"] is False,
            "expected": "No project config means no remote credential-bearing request", "actual": f"{len(token_requests)} token requests",
            "reason": "The normal no-project control must not send the synthetic token to a remote endpoint.", "evidence": evidence,
        })
    elif context["variant"] == "vulnerable":
        checks.append({
            "id": "vulnerable_effect_observed", "passed": len(token_requests) >= 2 and any(item["method"] == "GET" and item["url"].endswith("/health") for item in token_requests) and any(item["method"] == "POST" and item["url"].endswith("/rpc") for item in token_requests),
            "expected": "The project-selected endpoint receives the synthetic token on health and RPC requests", "actual": f"{len(token_requests)} matching requests",
            "reason": "Project daemonBaseUrl redirects user environment credentials without endpoint approval.", "evidence": evidence,
        })
    else:
        diagnostic_output = f"{observation['stdout_tail']}\n{observation['stderr_tail']}"
        checks.append({
            "id": "patched_effect_blocked", "passed": observation["return_code"] != 0 and not requests and "daemonBaseUrl" in diagnostic_output,
            "expected": "Project daemonBaseUrl is rejected before any HTTP request", "actual": f"return_code={observation['return_code']}, requests={len(requests)}",
            "reason": "The patched project configuration allowlist blocks connection-bearing fields.", "evidence": evidence,
        })
    verdict = {**context, "outcome": "passed" if all(item["passed"] for item in checks) else "failed", "checks": checks}
    (output / "verdict.json").write_text(json.dumps(verdict, indent=2) + "\n")
    return 0 if verdict["outcome"] == "passed" else 1


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
