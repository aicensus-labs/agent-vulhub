"""Drive the six-stage factory over many harvested candidates.

``harvest`` selects candidates and scaffolds drafts; ``factory`` advances one
environment one stage at a time. This module connects them: it queues a batch of
scaffolded drafts, reports where each one stands, and runs the objective gates.

Only the gates are automated here. ``analyze``, ``generate``, ``build`` and
``solve`` need an agent to read the advisory, write the diagram, PoC and verifier;
this module prepares the briefs for that work and refuses to mark a stage passed
without the artifact the gate demands. Nothing in here claims a reproduction:
``validate``/``solve`` only pass when Docker actually ran the four scenarios.
"""

import json
from pathlib import Path

from .factory import (FactoryError, STAGES, STAGE_BY_ID, environment_directory,
                      gate, now, read_state, research_directory, write_brief,
                      write_state)

SCHEMA = 1
# Stages that produce code or research and therefore need an agent turn.
AGENT_STAGES = ("analyze", "generate", "build", "solve")
# Stages whose gate is purely mechanical and can be executed unattended.
AUTOMATIC_STAGES = ("validate", "check")
STAGE_IDS = tuple(stage.id for stage in STAGES)


def batch_directory(root: Path) -> Path:
    directory = Path(root) / "batch"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def batch_path(root: Path, batch_id: str) -> Path:
    return batch_directory(root) / f"{batch_id}.json"


def read_batch(root: Path, batch_id: str) -> dict:
    path = batch_path(root, batch_id)
    if not path.is_file():
        raise FactoryError(f"Unknown batch: {batch_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def write_batch(root: Path, batch: dict) -> Path:
    batch["updated_at"] = now()
    path = batch_path(root, batch["batch_id"])
    path.write_text(json.dumps(batch, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    return path


def next_stage(root: Path, environment_id: str) -> str | None:
    """Return the first stage that has not passed yet, or ``None`` when done."""
    state = read_state(Path(root), environment_id)
    for stage_id in STAGE_IDS:
        if state.get("stages", {}).get(stage_id) != "passed":
            return stage_id
    return None


def environment_status(root: Path, environment_id: str) -> dict:
    state = read_state(Path(root), environment_id)
    stages = {stage_id: state.get("stages", {}).get(stage_id, "not_run") for stage_id in STAGE_IDS}
    passed = sum(1 for value in stages.values() if value == "passed")
    return {
        "environment_id": environment_id,
        "stages": stages,
        "passed": passed,
        "total": len(STAGE_IDS),
        "next_stage": next_stage(root, environment_id),
        "complete": passed == len(STAGE_IDS),
        "notes": state.get("notes", {}),
    }


def queue(root: Path, environment_ids, *, batch_id: str, database: str = "",
          note: str = "") -> dict:
    """Record a batch and write the brief for each candidate's next stage."""
    root = Path(root)
    entries = []
    for environment_id in environment_ids:
        directory = environment_directory(root, environment_id)
        status = environment_status(root, environment_id)
        stage_id = status["next_stage"]
        brief = None
        if stage_id is not None:
            brief = str(write_brief(root, environment_id, stage_id).relative_to(root))
        entries.append({
            "environment_id": environment_id,
            "environment_path": str(directory.relative_to(root)),
            "next_stage": stage_id,
            "brief": brief,
        })
    batch = {
        "schema_version": SCHEMA,
        "batch_id": batch_id,
        "created_at": now(),
        "database": database,
        "note": note,
        "environment_ids": [entry["environment_id"] for entry in entries],
        "entries": entries,
    }
    write_batch(root, batch)
    return batch


def refresh_batch(root: Path, batch_id: str) -> dict:
    """Recompute per-entry progress and rewrite the next-stage briefs."""
    root = Path(root)
    batch = read_batch(root, batch_id)
    for entry in batch["entries"]:
        environment_id = entry["environment_id"]
        status = environment_status(root, environment_id)
        entry["next_stage"] = status["next_stage"]
        entry["passed"] = status["passed"]
        entry["complete"] = status["complete"]
        if status["next_stage"] is not None:
            entry["brief"] = str(write_brief(root, environment_id, status["next_stage"])
                                 .relative_to(root))
    write_batch(root, batch)
    return batch


def progress(root: Path, batch_id: str) -> dict:
    """Summarise a batch without touching any environment."""
    batch = refresh_batch(Path(root), batch_id)
    counts: dict[str, int] = {}
    blocked: list[dict] = []
    for entry in batch["entries"]:
        status = environment_status(root, entry["environment_id"])
        counts[status["next_stage"] or "complete"] = counts.get(status["next_stage"] or "complete", 0) + 1
        if status["next_stage"] is not None:
            notes = status["notes"].get(status["next_stage"], {})
            if notes.get("problems"):
                blocked.append({
                    "environment_id": entry["environment_id"],
                    "stage": status["next_stage"],
                    "problems": notes["problems"],
                })
    return {
        "batch_id": batch_id,
        "environments": len(batch["entries"]),
        "complete": counts.get("complete", 0),
        "awaiting_stage": {key: value for key, value in counts.items() if key != "complete"},
        "blocked": blocked,
    }


def run_stage(root: Path, environment_id: str, stage_id: str, *, execute: bool = False,
              timeout: int = 1200) -> dict:
    """Run one gate through the factory and return its outcome."""
    return gate(Path(root), environment_id, stage_id, execute=execute, timeout=timeout)


def run_batch(root: Path, batch_id: str, *, stages=None, execute: bool = False,
              timeout: int = 1200, limit: int | None = None) -> dict:
    """Advance every environment in a batch as far as its gates allow.

    A stage that needs an agent is only attempted when its artifact already exists;
    otherwise the run stops for that environment and reports which brief to work on.
    ``execute`` is required for Docker gates, so a dry run never starts a container.
    """
    root = Path(root)
    wanted = tuple(stages) if stages else STAGE_IDS
    for stage_id in wanted:
        if stage_id not in STAGE_BY_ID:
            raise FactoryError(f"Unknown stage: {stage_id!r}")
    batch = refresh_batch(root, batch_id)
    outcomes = []
    attempted = 0
    for entry in batch["entries"]:
        if limit is not None and attempted >= limit:
            break
        environment_id = entry["environment_id"]
        stage_id = next_stage(root, environment_id)
        if stage_id is None:
            outcomes.append({"environment_id": environment_id, "stage": None,
                             "outcome": "complete"})
            continue
        if stage_id not in wanted:
            outcomes.append({"environment_id": environment_id, "stage": stage_id,
                             "outcome": "skipped", "reason": "stage not selected"})
            continue
        if stage_id in AGENT_STAGES and not _agent_outputs_present(root, environment_id, stage_id):
            outcomes.append({"environment_id": environment_id, "stage": stage_id,
                             "outcome": "awaiting-agent", "brief": entry.get("brief")})
            continue
        if STAGE_BY_ID[stage_id].needs_docker and not execute:
            outcomes.append({"environment_id": environment_id, "stage": stage_id,
                             "outcome": "awaiting-execute"})
            continue
        attempted += 1
        try:
            result = run_stage(root, environment_id, stage_id, execute=execute, timeout=timeout)
        except (FactoryError, ValueError) as error:
            outcomes.append({"environment_id": environment_id, "stage": stage_id,
                             "outcome": "error", "reason": str(error)})
            continue
        outcomes.append({
            "environment_id": environment_id,
            "stage": stage_id,
            "outcome": "passed" if result["passed"] else "failed",
            "problems": result["problems"],
        })
    refresh_batch(root, batch_id)
    return {
        "batch_id": batch_id,
        "execute": execute,
        "attempted": attempted,
        "outcomes": outcomes,
    }


def _agent_outputs_present(root: Path, environment_id: str, stage_id: str) -> bool:
    """Whether the artifacts an agent must author exist already.

    ``build`` is excluded: its Dockerfile and metadata are scaffolded as stubs, so
    presence alone proves nothing and its gate (lint/build) is the real judge.
    """
    if stage_id == "build":
        return True
    research = research_directory(root, environment_id)
    if stage_id == "analyze":
        return (research / "public.md").is_file() and (research / "analyze-res.toml").is_file()
    if stage_id == "generate":
        directory = environment_directory(root, environment_id)
        return (directory / "diagram.toml").is_file() and (directory / "reproduce.py").is_file()
    if stage_id == "solve":
        directory = environment_directory(root, environment_id)
        return (directory / "verify.py").is_file()
    return False


def record_note(root: Path, environment_id: str, stage_id: str, message: str) -> None:
    """Attach a free-form note to a stage without changing its status."""
    state = read_state(Path(root), environment_id)
    note = state.setdefault("notes", {}).setdefault(stage_id, {})
    note.setdefault("messages", []).append({"at": now(), "message": message})
    write_state(Path(root), environment_id, state)
