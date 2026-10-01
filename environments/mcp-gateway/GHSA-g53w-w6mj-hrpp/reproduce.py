"""Mechanism reproduction for GHSA-g53w-w6mj-hrpp.

The build stage compiles the upstream `internal/mcp-router` test binary with the
mechanism harness linked in. This script runs that binary so the upstream
`ExtProcServer.HandleNoneToolCall` method is invoked for real, then records what
it did.

No HTTP server, Envoy proxy, or Kubernetes control plane participates: the
hair-pin authorization decision is a pure function of the request headers and
the router configuration, so calling the upstream method in-process exercises
the real vulnerable code path.

This script does not judge the result. It writes facts.json and an observation,
and verify.py decides whether the observed behaviour is the expected one.
"""

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys

TEST_BINARY = "/lab/router-mechanism.test"
FIXTURES_DIR = "/lab/fixtures"


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--output", required=True)
    options = parser.parse_args()

    context = json.loads(pathlib.Path(options.context).read_text())
    output = pathlib.Path(options.output)
    output.mkdir(parents=True, exist_ok=True)

    environment = dict(os.environ)
    environment.update(
        {
            "LAB_CONTEXT": str(pathlib.Path(options.context).resolve()),
            "LAB_OUTPUT": str(output.resolve()),
            "LAB_FIXTURES": FIXTURES_DIR,
        }
    )

    execution_status = "completed"
    error = None
    try:
        completed = subprocess.run(
            [TEST_BINARY, "-test.run", "TestMechanismHairpinInitialize", "-test.v"],
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if completed.returncode != 0:
            execution_status = "failed"
            error = (completed.stdout or "") + (completed.stderr or "")
    except Exception as caught:  # noqa: BLE001 - recorded as evidence, not raised
        execution_status = "failed"
        error = str(caught)

    observation_path = output / "observation.json"
    if not observation_path.exists():
        # The harness could not run or crashed before writing: record that
        # explicitly so verify.py reports a failed case rather than a crash.
        observation_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "context": {
                        "schema_version": context.get("schema_version"),
                        "run_id": context.get("run_id"),
                        "case_id": context.get("case_id"),
                        "variant": context.get("variant"),
                        "scenario": context.get("scenario"),
                    },
                    "target_ready": False,
                    "request": {},
                    "response": {},
                    "header_rewrite": {},
                    "error": error or "harness produced no observation",
                },
                indent=2,
            )
            + "\n"
        )

    evidence = [{"path": "observation.json", "sha256": sha256(observation_path)}]
    facts = {
        "schema_version": 1,
        "run_id": context["run_id"],
        "case_id": context["case_id"],
        "variant": context["variant"],
        "scenario": context["scenario"],
        "execution_status": execution_status,
        "evidence": evidence,
    }
    (output / "facts.json").write_text(json.dumps(facts, indent=2) + "\n")

    if execution_status != "completed":
        print(error or "mechanism harness failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
