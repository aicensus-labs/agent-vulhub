#!/usr/bin/env python3
"""Unattended driver for the AgentSec reproduction pipeline.

The pipeline has two kinds of stage:

* Deterministic stages (``validate``, ``check``) and the static parts of the others
  are run by ``runner factory gate``. Those are what this script drives.
* Stages that need research judgement (``analyze``, ``generate``, ``solve``) are
  performed by agents from their briefs. This script cannot start an agent by
  itself -- the harness has no non-interactive one-shot CLI -- so instead of
  pretending otherwise it *prepares* each environment, runs every gate whose
  prerequisites are already satisfied, and writes the exact brief paths that still
  need an agent into a worklist.

Everything is resumable: state lives in ``<root>/batch/`` and in each
environment's ``research/<env>/state.json``, so re-running never redoes a stage that
already passed.

Usage:
  python3 driver.py --root staging --limit 200
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

CHECKOUT = Path(__file__).resolve().parent
STAGE_ORDER = ["analyze", "generate", "build", "validate", "solve", "check"]
AGENT_STAGES = {"analyze", "generate", "solve"}


def log(message: str) -> None:
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    print(f"[{stamp}] {message}", flush=True)


def run(command: list[str], root: Path, timeout: int) -> tuple[int, str]:
    env = dict(os.environ, AVH_ROOT=str(root), DOCKER_CONFIG=os.environ.get("DOCKER_CONFIG", "/tmp/docker-config"))
    try:
        done = subprocess.run(command, cwd=CHECKOUT, env=env, timeout=timeout,
                              capture_output=True, text=True)
        return done.returncode, (done.stdout or "") + (done.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s"


def stage_state(root: Path, environment_id: str) -> dict:
    path = root / "research" / environment_id / "state.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("stages", {})
    except (OSError, ValueError):
        return {}


def stage_status(root: Path, environment_id: str, stage_id: str) -> str:
    """Read the agent's own result status for a stage.

    ``error`` is a terminal, correct outcome (closed source, no fix commit, no
    upstream source): it must NOT be retried on the next pass, or every wave
    would burn agents re-deriving the same impossibility.
    """
    path = root / "research" / environment_id / f"{stage_id}-res.toml"
    if not path.is_file():
        return ""
    try:
        import tomllib
        return str(tomllib.loads(path.read_text(encoding="utf-8")).get("status", ""))
    except (OSError, ValueError):
        return ""


def next_missing(stages: dict) -> str | None:
    for stage_id in STAGE_ORDER:
        if stages.get(stage_id) != "passed":
            return stage_id
    return None


def load_candidates(root: Path, limit: int) -> list[dict]:
    """Harvest uncovered candidates, newest worklist wins."""
    database = os.environ.get("AGENTSEC_DB", "")
    cache = root / "batch" / "candidates.json"
    if cache.is_file():
        payload = json.loads(cache.read_text(encoding="utf-8"))
        log(f"reusing {len(payload)} harvested candidates from {cache}")
        return payload[:limit]
    if not database:
        log("AGENTSEC_DB is not set and no cached candidate list exists; nothing to do")
        return []
    command = [sys.executable, "-m", "runner", "harvest", "--db", database,
               "--out", str(root), "--json"]
    code, output = run(command, root, 3600)
    if code != 0:
        log(f"harvest failed ({code}): {output[-400:]}")
        return []
    payload = json.loads(output)
    candidates = payload.get("candidates", [])
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(candidates, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    log(f"harvested {len(candidates)} uncovered candidates")
    return candidates[:limit]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="staging")
    parser.add_argument("--limit", type=int, default=0, help="process at most N environments (0 = all)")
    parser.add_argument("--gate-timeout", type=int, default=2400)
    parser.add_argument("--skip-docker", action="store_true",
                        help="only run static stages; never start a container")
    args = parser.parse_args()
    root = (CHECKOUT / args.root).resolve() if not Path(args.root).is_absolute() else Path(args.root)

    candidates = load_candidates(root, args.limit or 10 ** 9)
    if not candidates:
        return 1
    log(f"driving {len(candidates)} environment(s) against root {root}")

    worklist: list[dict] = []
    rejected: list[dict] = []
    counters = {"complete": 0, "awaiting-agent": 0, "rejected": 0, "failed": 0, "error": 0}

    for index, candidate in enumerate(candidates, start=1):
        environment_id = candidate["environment_id"]
        stages = stage_state(root, environment_id)
        missing = next_missing(stages)

        if missing is None:
            counters["complete"] += 1
            log(f"[{index}/{len(candidates)}] {environment_id}: complete (6/6)")
            continue

        # Scaffold the draft if this environment has never been worked on.
        if not stages:
            code, output = run([sys.executable, "-m", "runner", "harvest", "--db",
                                os.environ.get("AGENTSEC_DB", ""), "--out", str(root),
                                "--identifier", candidate.get("identifier", environment_id.split("/")[-1]),
                                "--scaffold", "--json"], root, 900)
            if code != 0:
                log(f"[{index}/{len(candidates)}] {environment_id}: scaffold failed: {output[-200:]}")
                counters["error"] += 1
                worklist.append({"environment_id": environment_id, "needs": "scaffold",
                                 "detail": output[-300:]})
                continue

        if missing in AGENT_STAGES:
            # Static gate first: it may already pass from a previous agent wave.
            code, output = run([sys.executable, "-m", "runner", "factory", "gate",
                                environment_id, "--stage", missing, "--timeout", str(args.gate_timeout)],
                               root, args.gate_timeout)
            # Materialise the self-contained brief so the worklist is actionable.
            run([sys.executable, "-m", "runner", "factory", "brief",
                 environment_id, "--stage", missing], root, 300)
            brief = root / "research" / environment_id / f"brief-{missing}.md"
            if code == 0:
                log(f"[{index}/{len(candidates)}] {environment_id}: {missing} passed")
                continue
            if stage_status(root, environment_id, missing) == "error":
                counters["rejected"] += 1
                rejected.append({"environment_id": environment_id, "stage": missing})
                log(f"[{index}/{len(candidates)}] {environment_id}: rejected at {missing} (agent reported error)")
                continue
            counters["awaiting-agent"] += 1
            worklist.append({"environment_id": environment_id, "needs": missing,
                             "brief": str(brief.relative_to(CHECKOUT)) if brief.is_file() else None})
            log(f"[{index}/{len(candidates)}] {environment_id}: awaiting agent for {missing}")
            continue

        if args.skip_docker and missing in {"validate", "solve"}:
            counters["awaiting-agent"] += 1
            worklist.append({"environment_id": environment_id, "needs": missing,
                             "detail": "docker stage skipped by --skip-docker"})
            continue

        if stage_status(root, environment_id, missing) == "error":
            counters["rejected"] += 1
            rejected.append({"environment_id": environment_id, "stage": missing})
            log(f"[{index}/{len(candidates)}] {environment_id}: rejected at {missing} (agent reported error)")
            continue

        # A Docker stage whose own result file does not exist yet has not been
        # attempted: the earlier stage merely passed and the work has not started.
        # Recording that as "failed" would be a lie -- "failed" is reserved for a
        # stage that actually ran and did not pass.
        if not (root / "research" / environment_id / f"{missing}-res.toml").is_file():
            brief = root / "research" / environment_id / f"brief-{missing}.md"
            run([sys.executable, "-m", "runner", "factory", "brief",
                 environment_id, "--stage", missing], root, 300)
            counters["awaiting-agent"] += 1
            worklist.append({"environment_id": environment_id, "needs": missing,
                             "brief": str(brief.relative_to(CHECKOUT)) if brief.is_file() else None,
                             "detail": "stage not started"})
            log(f"[{index}/{len(candidates)}] {environment_id}: awaiting agent for {missing} (not started)")
            continue

        # validate / check: deterministic, run the objective gate.
        code, output = run([sys.executable, "-m", "runner", "factory", "gate",
                            environment_id, "--stage", missing, "--execute",
                            "--timeout", str(args.gate_timeout)], root, args.gate_timeout + 300)
        if code == 0:
            log(f"[{index}/{len(candidates)}] {environment_id}: {missing} passed")
        else:
            counters["failed"] += 1
            tail = output.strip().splitlines()[-1] if output.strip() else "no output"
            worklist.append({"environment_id": environment_id, "needs": missing, "detail": tail[:300]})
            log(f"[{index}/{len(candidates)}] {environment_id}: {missing} failed -- {tail[:160]}")

    batch = root / "batch"
    batch.mkdir(parents=True, exist_ok=True)
    (batch / "worklist.json").write_text(
        json.dumps({"counters": counters, "worklist": worklist, "rejected": rejected},
                   ensure_ascii=False, indent=1) + "\n",
        encoding="utf-8")
    log(f"done: {counters}")
    log(f"worklist written to {batch / 'worklist.json'} ({len(worklist)} item(s) needing attention)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
