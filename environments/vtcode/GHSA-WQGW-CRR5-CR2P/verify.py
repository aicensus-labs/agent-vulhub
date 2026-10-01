"""Independent verifier for GHSA-wqgw-crr5-cr2p (VT Code unapproved lifecycle hooks).

This file never runs cargo and never invokes a shell. It reads the observation and
facts written by reproduce.py, checks their integrity, and decides whether the
recorded behaviour matches the (variant, scenario) pair.

The mechanism: VT Code loads a workspace-root `vtcode.toml` and runs its
`session_start` lifecycle command through `sh -c` during session setup. Before
the fix there is no approval step, so a repository can execute commands the user
never saw. The fix gates the whole engine while workspace-controlled hook content
is present, until the exact command set is approved.

The attack cases assert that an *unapproved* workspace hook does or does not run.
The patched attack case additionally requires the positive control: approving the
exact command set must then run it. Without that, a fix that simply disabled
lifecycle hooks for everyone would look identical to a real fix.

The benign case models the user-level hook that must keep working. It is
deliberately *ungated*: gating a repository command even when harmless is the
intended trade-off, so it cannot serve as the control that proves the fix is not
over-broad.
"""

import argparse
import hashlib
import json
from pathlib import Path

CANARY = "canary_proof.txt"
APPROVED_CANARY = "canary_approved.txt"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(identifier, passed, expected, actual, reason, evidence):
    return {
        "id": identifier,
        "passed": bool(passed),
        "expected": expected,
        "actual": actual,
        "reason": reason,
        "evidence": evidence,
    }


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
        if facts[key] != context[key]:
            raise SystemExit(f"facts context mismatch: {key}")
        if observation["context"][key] != context[key]:
            raise SystemExit(f"observation context mismatch: {key}")

    if facts["evidence"][0]["sha256"] != digest(output / "observation.json"):
        raise SystemExit("observation hash mismatch")

    recorded = {item["path"]: item["sha256"] for item in facts["evidence"]}
    for name in (CANARY, APPROVED_CANARY):
        path = output / name
        if path.exists():
            if recorded.get(name) != digest(path):
                raise SystemExit(f"{name} exists but is not correctly recorded as evidence")
        elif name in recorded:
            raise SystemExit(f"{name} is recorded as evidence but does not exist")

    evidence = ["observation.json"] + [name for name in (CANARY, APPROVED_CANARY) if (output / name).exists()]

    target_ready = observation.get("target_ready") is True
    gated = observation.get("workspace_gated") is True
    needed_before = observation.get("needed_approval_before") is True
    unapproved_ran = observation.get("canary_created") is True
    skip_surfaced = observation.get("skip_reason_surfaced") is True
    needed_after = observation.get("needed_approval_after") is True
    approved_ran = observation.get("approved_canary_created") is True

    checks = [check(
        "target_ready",
        target_ready,
        "the real upstream LifecycleHookEngine runs and reports its gate state",
        f"target_ready={target_ready}",
        "The pinned revision's own engine executed the configured session_start hook.",
        evidence,
    )]

    if context["scenario"] == "benign":
        # User-level hooks are not workspace-controlled, so the fix must leave
        # them running. This is the guard against an over-broad fix.
        checks.append(check(
            "benign_task_passed",
            (not gated) and (not needed_before) and unapproved_ran,
            "a user-level lifecycle hook is ungated and still runs after the fix",
            f"gated={gated}; needed_approval={needed_before}; hook_ran={unapproved_ran}",
            "The approval gate applies to workspace-controlled hook content, not to the user's own configuration.",
            evidence,
        ))
    elif context["variant"] == "vulnerable":
        checks.append(check(
            "vulnerable_effect_observed",
            (not gated) and (not needed_before) and unapproved_ran,
            "a repository-controlled session_start hook runs with no approval step",
            f"gated={gated}; needed_approval={needed_before}; hook_ran={unapproved_ran}",
            "Before the fix the engine has no workspace gate, so the hook executes unchecked.",
            evidence,
        ))
    else:
        # The fix must close the unapproved path and leave the approved one
        # working. Both halves are required.
        checks.append(check(
            "patched_effect_blocked",
            gated and needed_before and (not unapproved_ran) and skip_surfaced
            and (not needed_after) and approved_ran,
            "the unapproved workspace hook is skipped with a reason, while the approved set still runs",
            f"gated={gated}; needed_approval={needed_before}; hook_ran={unapproved_ran}; "
            f"skip_reason={skip_surfaced}; needed_after_approval={needed_after}; approved_hook_ran={approved_ran}",
            "The engine gates workspace hook content, surfaces the skip, and approve_workspace_hooks() re-enables the exact set.",
            evidence,
        ))

    verdict = {
        "schema_version": context["schema_version"],
        "run_id": context["run_id"],
        "case_id": context["case_id"],
        "variant": context["variant"],
        "scenario": context["scenario"],
        "outcome": "passed" if all(item["passed"] for item in checks) else "failed",
        "checks": checks,
    }
    (output / "verdict.json").write_text(json.dumps(verdict, indent=2) + "\n")

    if verdict["outcome"] != "passed":
        for item in checks:
            if not item["passed"]:
                print(f"FAILED {item['id']}: {item['actual']}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
