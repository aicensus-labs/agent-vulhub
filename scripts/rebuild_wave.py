"""Select fingerprint-bound source environments for an isolated rebuild wave."""

import argparse
import json
from pathlib import Path
import re
import sys

from runner.cli import ROOT, RegistryError, check_evidence, load_registry, read_toml, split_id
from runner.protocol import (contained, fingerprint, provenance_kind, read_json,
                             runner_fingerprint, validate_report)

DEFAULT_MANIFEST = ROOT / ".github/agent-poc-rebuild-wave-20261011.json"
MAX_BATCH_SIZE = 100
SHA256 = re.compile(r"[0-9a-f]{64}")


class WaveError(ValueError):
    """A rebuild wave is malformed or no longer matches the registry."""


def load_manifest(path: Path) -> dict:
    path = Path(path)
    if path.stat().st_size > 4 * 1024 * 1024:
        raise WaveError("Wave manifest exceeds 4 MiB")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise WaveError(f"Cannot read wave manifest: {error}") from error
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise WaveError("Expected wave manifest schema_version = 1")
    selection = manifest.get("selection", {})
    if (not isinstance(selection, dict) or selection.get("provenance") != "source" or
            selection.get("historical_layer") != "mechanism" or
            selection.get("historical_outcome") != "passed" or
            not isinstance(selection.get("minimum_rounds"), int) or
            selection["minimum_rounds"] < 3):
        raise WaveError("Wave must select historical source mechanism passes with at least three rounds")
    entries = manifest.get("environments")
    if not isinstance(entries, list) or not entries:
        raise WaveError("Wave manifest environments must be a non-empty array")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"environment_id", "fingerprint"}:
            raise WaveError("Each wave entry must contain environment_id and fingerprint")
        environment_id = entry["environment_id"]
        if not isinstance(environment_id, str):
            raise WaveError("Wave environment_id must be a string")
        try:
            split_id(environment_id)
        except RegistryError as error:
            raise WaveError(str(error)) from error
        if environment_id in seen:
            raise WaveError(f"Duplicate environment in wave: {environment_id}")
        seen.add(environment_id)
        if not isinstance(entry["fingerprint"], str) or not SHA256.fullmatch(entry["fingerprint"]):
            raise WaveError(f"Invalid input fingerprint for {environment_id}")
    return manifest


def _current_passed(root: Path, directory: Path, metadata: dict, expected: str) -> bool:
    mechanism = metadata.get("verification", {}).get("mechanism", {})
    if mechanism.get("status") != "passed":
        return False
    try:
        check_evidence(root, directory, metadata)
    except (RegistryError, OSError, ValueError, KeyError, TypeError):
        return False
    current_runner = runner_fingerprint(root)
    for relative in mechanism.get("evidence", []):
        try:
            report_path = contained(directory, relative)
            if not report_path.is_file():
                report_path = contained(root, relative)
            report = read_json(report_path)
            if report.get("environment_id") != metadata["id"] or report.get("layer") != "mechanism":
                continue
            validate_report(report, expected)
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if report.get("runner_fingerprint") == current_runner:
            return True
    return False


def select_batch(root: Path, manifest_path: Path, *, offset: int, limit: int) -> list[dict]:
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise WaveError("offset must be a non-negative integer")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_BATCH_SIZE:
        raise WaveError(f"limit must be between 1 and {MAX_BATCH_SIZE}")
    manifest = load_manifest(manifest_path)
    entries = load_registry(root)
    registered = {entry["id"]: entry for entry in entries}
    selected = []
    for item in manifest["environments"][offset:offset + limit]:
        environment_id = item["environment_id"]
        registry_entry = registered.get(environment_id)
        if registry_entry is None:
            raise WaveError(f"Wave environment is no longer registered: {environment_id}")
        directory = root / registry_entry["path"]
        metadata = read_toml(directory / "metadata.toml")
        if provenance_kind(metadata) != "source":
            raise WaveError(f"Wave environment is no longer source-based: {environment_id}")
        actual = fingerprint(root, directory, metadata)
        if actual != item["fingerprint"]:
            raise WaveError(f"{environment_id}: current input fingerprint differs from the wave manifest")
        if _current_passed(root, directory, metadata, actual):
            continue
        selected.append({
            "environment_id": environment_id,
            "artifact_slug": environment_id.replace("/", "--"),
        })
    return selected


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Select a bounded slice of a fingerprint-bound rebuild wave")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int, default=50)
    args = parser.parse_args(argv)
    try:
        selected = select_batch(ROOT, args.manifest, offset=args.offset, limit=args.limit)
    except (WaveError, RegistryError, OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps({"include": selected}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
