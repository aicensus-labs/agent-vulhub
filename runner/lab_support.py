"""Small, dependency-free helpers shared by isolated lab entrypoints."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Callable


CONTEXT_KEYS = ("schema_version", "run_id", "case_id", "variant", "scenario")


def read_context(path: str | Path) -> dict[str, Any]:
    context = json.loads(Path(path).read_text(encoding="utf-8"))
    if context.get("schema_version") != 1:
        raise ValueError("unsupported context schema")
    if context.get("variant") not in {"vulnerable", "patched"}:
        raise ValueError("invalid context variant")
    if context.get("scenario") not in {"attack", "benign"}:
        raise ValueError("invalid context scenario")
    if any(not context.get(key) for key in CONTEXT_KEYS):
        raise ValueError("incomplete execution context")
    return context


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_relative_path(name: str) -> Path:
    relative = Path(name)
    if (
        not name
        or relative.is_absolute()
        or ".." in relative.parts
        or not relative.parts
    ):
        raise ValueError(f"unsafe effect path: {name}")
    return relative


def record(
    context: dict[str, Any],
    output: str | Path,
    observation: dict[str, Any],
    effects: dict[str, str | bytes] | None = None,
) -> int:
    """Write independently hashable facts after the product call completes."""
    directory = Path(output)
    directory.mkdir(parents=True, exist_ok=True)
    if not isinstance(observation.get("target_ready"), bool):
        raise ValueError("observation must explicitly record target_ready")
    observation = {
        **observation,
        "schema_version": 1,
        "context": {key: context[key] for key in CONTEXT_KEYS},
    }
    observation_path = directory / "observation.json"
    write_json(observation_path, observation)
    evidence = [{"path": "observation.json", "sha256": sha256(observation_path)}]
    for name, value in (effects or {}).items():
        path = directory / _safe_relative_path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(value, bytes):
            path.write_bytes(value)
        else:
            path.write_text(value, encoding="utf-8")
        evidence.append({"path": name, "sha256": sha256(path)})
    status = observation.get("execution_status", "failed")
    facts = {"schema_version": 1, **{key: context[key] for key in CONTEXT_KEYS}}
    facts.update({"execution_status": status, "evidence": evidence})
    write_json(directory / "facts.json", facts)
    return {"completed": 0, "not_run": 2}.get(status, 1)


def _check_evidence(directory: Path, facts: dict[str, Any]) -> dict[str, Path]:
    evidence = facts.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("missing evidence")
    paths: dict[str, Path] = {}
    for item in evidence:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ValueError("invalid evidence entry")
        name = item["path"]
        if not isinstance(name, str) or not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
            raise ValueError(f"unsafe or missing evidence: {name}")
        relative = _safe_relative_path(name)
        path = directory / relative
        if (not path.is_file()
                or not path.resolve().is_relative_to(directory.resolve())):
            raise ValueError(f"unsafe or missing evidence: {name}")
        current = directory
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                raise ValueError(f"unsafe or missing evidence: {name}")
        if name in paths:
            raise ValueError(f"duplicate evidence: {name}")
        if sha256(path) != item["sha256"]:
            raise ValueError(f"evidence hash mismatch: {name}")
        paths[name] = path
    if "observation.json" not in paths:
        raise ValueError("observation.json must be hash-checked evidence")
    return paths


def verify(
    context_path: str | Path,
    output: str | Path,
    check_effect: Callable[[dict[str, Any], dict[str, Any], dict[str, Path]], tuple[str, bool, str, str]],
) -> int:
    """Create a verdict from facts/effects without invoking application code."""
    context = read_context(context_path)
    directory = Path(output)
    facts = json.loads((directory / "facts.json").read_text(encoding="utf-8"))
    observation_path = directory / "observation.json"
    observation = json.loads(observation_path.read_text(encoding="utf-8"))
    if facts.get("schema_version") != 1 or observation.get("schema_version") != 1:
        raise ValueError("unsupported evidence schema")
    for index, document in enumerate((facts, observation)):
        nested = document.get("context", {})
        if not isinstance(nested, dict):
            raise ValueError("invalid execution context")
        for key in CONTEXT_KEYS:
            expected = context[key]
            if index == 0 and document.get(key) != expected:
                raise ValueError(f"context mismatch: {key}")
            if index == 1 and nested.get(key) != expected:
                raise ValueError(f"context mismatch: {key}")
            if key in document and document[key] != expected:
                raise ValueError(f"context mismatch: {key}")
    if facts.get("execution_status") != "completed" or observation.get("execution_status") != "completed":
        return 2
    paths = _check_evidence(directory, facts)
    required, passed, expected, actual = check_effect(context, observation, paths)
    checks = [
        {
            "id": "target_ready",
            "passed": observation.get("target_ready") is True,
            "expected": "The pinned upstream mechanism completes",
            "actual": observation.get("target_ready"),
            "reason": "The PoC records whether it loaded and invoked the pinned upstream mechanism.",
            "evidence": ["observation.json"],
        },
        {
            "id": required,
            "passed": passed,
            "expected": expected,
            "actual": actual,
            "reason": "The verifier compares only hash-checked facts and effects.",
            "evidence": list(paths),
        },
    ]
    verdict = {**context, "outcome": "passed" if all(item["passed"] for item in checks) else "failed", "checks": checks}
    write_json(directory / "verdict.json", verdict)
    return 0 if verdict["outcome"] == "passed" else 1


def parser(description: str) -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=description)
    result.add_argument("--context", required=True)
    result.add_argument("--output", required=True)
    return result
