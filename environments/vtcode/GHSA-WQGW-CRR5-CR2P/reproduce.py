"""Mechanism reproduction for GHSA-wqgw-crr5-cr2p (VT Code unapproved lifecycle hooks).

The harness is an in-crate test module added to the pinned revision's
`vtcode-core`, mounted the same way upstream mounts its own
`workspace_hook_approval.rs`. It drives the real `LifecycleHookEngine`: a
workspace-controlled `session_start` hook is configured, `run_session_start()` is
called, and the effect is a marker file the hook writes.

Why a test module rather than a binary: the config types the engine takes live in
`vtcode-config` and the engine's constructor is crate-internal, so an external
crate cannot assemble the same call without widening upstream visibility. Running
inside the crate uses the real API at its real access level.

Scope: the advisory's trigger surface is the interactive TUI `session_start`
path. The approval gate itself is engine-level and non-interactive, which is why
it is reproducible here; the TUI overlay that collects the user's answer is not
exercised. See metadata notes.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

APP_DIR = "/lab/app"
CANARY = "canary_proof.txt"
APPROVED_CANARY = "canary_approved.txt"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    context = json.loads(Path(args.context).read_text())
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    for name in (CANARY, APPROVED_CANARY):
        (output / name).unlink(missing_ok=True)

    observation_path = output / "observation.json"
    execution_status = "completed"
    error = None
    try:
        completed = subprocess.run(
            [
                "/opt/rust/bin/cargo", "test",
                "--locked", "--offline", "-p", "vtcode-core",
                "lab_workspace_hook_approval", "--", "--nocapture",
            ],
            cwd=APP_DIR,
            capture_output=True,
            text=True,
            timeout=900,
            env={
                "PATH": "/opt/rust/bin:/usr/local/bin:/usr/bin:/bin",
                "CARGO_HOME": "/lab/cargo-home",
                "HOME": "/root",
                "LAB_CONTEXT": args.context,
                "LAB_OUTPUT": str(output),
                "LAB_FIXTURES": "/lab/fixtures",
                "LAB_WORKSPACE": "/lab/workspace",
            },
        )
        if completed.returncode != 0:
            execution_status = "failed"
            error = (completed.stdout + completed.stderr).strip()[-3000:]
    except subprocess.TimeoutExpired:
        execution_status = "failed"
        error = "harness timed out"

    if not observation_path.exists():
        observation_path.write_text(json.dumps({
            "schema_version": 1,
            "context": {key: context[key] for key in ("schema_version", "run_id", "case_id", "variant", "scenario")},
            "target_ready": False,
            "workspace_gated": False,
            "needed_approval_before": False,
            "canary_created": False,
            "skip_reason_surfaced": False,
            "needed_approval_after": False,
            "approved_canary_created": False,
            "error": error or "harness produced no observation",
        }, indent=2) + "\n")

    evidence = [{"path": "observation.json", "sha256": digest(observation_path)}]
    for name in (CANARY, APPROVED_CANARY):
        if (output / name).exists():
            evidence.append({"path": name, "sha256": digest(output / name)})

    (output / "facts.json").write_text(json.dumps({
        "schema_version": 1,
        "run_id": context["run_id"],
        "case_id": context["case_id"],
        "variant": context["variant"],
        "scenario": context["scenario"],
        "execution_status": execution_status,
        "evidence": evidence,
    }, indent=2) + "\n")

    if execution_status != "completed":
        print(error or "harness failed", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
