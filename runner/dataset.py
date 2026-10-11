"""Build a fingerprint-bound manifest of admitted Agent-PoC samples."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from .agent_poc import validate_adapter_admission
from .cli import read_toml
from .protocol import contained, digest, fingerprint, read_json, runner_fingerprint


def build_agent_manifest(root: Path, entries: list[dict]) -> dict:
    samples = []
    current_runner = runner_fingerprint(root)
    for entry in entries:
        directory = root / entry["path"]
        metadata = read_toml(directory / "metadata.toml")
        adapter = metadata.get("verification", {}).get("agent_poc", {})
        if adapter.get("adapter_status") != "accepted":
            continue
        validate_adapter_admission(root, directory, metadata)
        controls = {}
        for relative in adapter["evidence"]:
            path = contained(directory, relative)
            if path.suffix.lower() == ".md":
                continue
            report = read_json(path)
            role = report["adapter_control_role"]
            controls[role] = {"path": relative, "sha256": digest(path)}
        mechanism = []
        for relative in metadata["verification"]["mechanism"]["evidence"]:
            path = contained(directory, relative)
            mechanism.append({"path": relative, "sha256": digest(path)})
        review = adapter["task_description_review"]
        samples.append({
            "environment_id": metadata["id"],
            "difficulty": 1,
            "candidate_format": adapter.get("candidate_format", "command"),
            "task_sha256": adapter["task_sha256"],
            "task_description_sha256": review["sha256"],
            "environment_fingerprint": fingerprint(root, directory, metadata),
            "runner_fingerprint": current_runner,
            "mechanism_evidence": mechanism,
            "adapter_controls": controls,
            "adapter_reviewed_at": adapter["verified_at"],
        })
    samples.sort(key=lambda sample: sample["environment_id"])
    canonical = json.dumps(samples, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "schema_version": 1,
        "dataset": "agent-poc",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sample_count": len(samples),
        "samples_sha256": hashlib.sha256(canonical).hexdigest(),
        "samples": samples,
    }
