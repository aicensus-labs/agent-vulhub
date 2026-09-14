"""Mechanism PoC for workspace lifecycle hook approval."""

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
    output.mkdir(parents=True, exist_ok=True)
    observation = {
        "schema_version": 1,
        "context": {key: context[key] for key in ("schema_version", "run_id", "case_id", "variant", "scenario")},
        "execution_status": "not_run",
        "target_ready": False,
        "reason": "VT Code session_start reaches its lifecycle path during interactive TUI initialization. The repository protocol requires a stable non-interactive trigger, but this upstream version does not provide one; running the TUI without a terminal cannot distinguish hook execution from startup failure.",
        "marker_command": "printf 'vtcode-session-start-marker\\n' > .vtcode-session-start-marker",
    }
    observation_path = output / "observation.json"
    observation_path.write_text(json.dumps(observation, indent=2) + "\n")
    (output / "facts.json").write_text(json.dumps({
        "schema_version": 1,
        "run_id": context["run_id"],
        "case_id": context["case_id"],
        "variant": context["variant"],
        "scenario": context["scenario"],
        "execution_status": "not_run",
        "evidence": [{"path": "observation.json", "sha256": digest(observation_path)}],
    }, indent=2) + "\n")
    print("Prerequisite not met: stable non-interactive VT Code session-start trigger is unavailable", file=sys.stderr)
    return 2


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
