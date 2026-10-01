"""Drive the pinned upstream gitlab-mcp GraphQL guard at the vulnerable and patched revisions.

The project statement for GHSA-5648-rgj9-v224 is that ``execute_graphql`` accepts a
mutation document in read-only mode when the document begins with an ignored comma,
and (separately) that the tool branch never consults the project allow-list.  Both
facts belong to upstream code, so this entrypoint does not re-implement either
control: it loads the tag-pinned ``utils/graphql-query.ts`` from the revision the
image ships and calls the upstream classifier the guard calls, then reads the
pinned ``index.ts`` to record whether the ``execute_graphql`` branch carries the
project-scope guard that the other project-scoped tools carry.

Inputs come from ``/lab/fixtures/`` (cases.json, allowlist-scope.json, pin.json,
graphql-driver.mjs) and the upstream checkout at the ``repo_dir`` recorded in
pin.json.  Outputs are written under ``--output``: ``driver-results.json`` holds the
raw per-query decisions and structural facts, ``driver-stdout.txt``/``driver-stderr.txt``
hold the raw Node run, and ``facts.json``/``observation.json`` are written by the
shared recorder.

usage: reproduce.py --context <context.json> --output <directory>
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, "/lab")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lab_support import parser, read_context, record  # noqa: E402

FIXTURES = Path("/lab/fixtures")
CASES_FILENAME = "cases.json"
SCOPE_FILENAME = "allowlist-scope.json"
PIN_FILENAME = "pin.json"
DRIVER_FILENAME = "graphql-driver.mjs"
MANIFEST_FILENAME = "manifest.toml"

# The driver is a plain ESM script that imports the pinned TypeScript module; Node
# strips the two type annotations in that module without a build step.
NODE = "node"
NODE_FLAGS = ("--experimental-strip-types", "--disable-warning=ExperimentalWarning")
DRIVER_TIMEOUT_SECONDS = 120


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest_entries() -> dict:
    """Minimal TOML reader for the one table this entrypoint needs to re-check."""
    import tomllib

    path = FIXTURES / MANIFEST_FILENAME
    return tomllib.loads(path.read_text(encoding="utf-8")).get("files", {})


def _check_pin(pin: dict, variant: str) -> None:
    """Refuse to run when the fixture hash does not match the recorded pin."""
    entries = _manifest_entries()
    for name in (CASES_FILENAME, SCOPE_FILENAME, PIN_FILENAME, DRIVER_FILENAME):
        recorded = entries.get(name)
        if not isinstance(recorded, str) or recorded != _sha256(FIXTURES / name):
            raise SystemExit(f"fixture {name} does not match fixtures/manifest.toml")
    revision = pin.get(variant)
    if not isinstance(revision, dict) or not revision.get("repo_dir"):
        raise SystemExit(f"pin.json records no upstream revision for variant {variant!r}")
    if not revision.get("graphql_query_sha256"):
        raise SystemExit("pin.json records no graphql-query module hash")


def _repo_dir(revision: dict) -> str:
    """Resolve the upstream checkout, allowing the image to relocate /lab."""
    recorded = revision["repo_dir"]
    override = os.environ.get("AVH_UPSTREAM_ROOT")
    if override and recorded.startswith("/lab/"):
        return str(Path(override) / recorded[len("/lab/"):])
    return recorded


def _as_text(value) -> str:
    """subprocess may hand back bytes when a timeout truncates a text stream."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def _run_driver(variant: str, cases: Path, repo: str, expected_sha: str,
                results: Path) -> subprocess.CompletedProcess:
    command = [
        NODE, *NODE_FLAGS, str(FIXTURES / DRIVER_FILENAME), str(cases), repo,
        variant, expected_sha, str(results),
    ]
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/root"),
        "NODE_NO_WARNINGS": "1",
        "NO_COLOR": "1",
    }
    return subprocess.run(
        command, capture_output=True, text=True, timeout=DRIVER_TIMEOUT_SECONDS,
        env=environment, cwd=str(FIXTURES),
    )


def main() -> int:
    args = parser(__doc__).parse_args()
    context = read_context(args.context)
    variant = context["variant"]
    scenario = context["scenario"]

    pin = _load(FIXTURES / PIN_FILENAME)
    cases = _load(FIXTURES / CASES_FILENAME)
    scope = _load(FIXTURES / SCOPE_FILENAME)
    _check_pin(pin, variant)
    revision = pin[variant]

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    # Attack and benign scenarios exercise disjoint fixed inputs: the attack
    # document set carries the bypass payloads, the benign set only read queries.
    selected = "attack_queries" if scenario == "attack" else "benign_queries"
    if selected not in cases or not cases[selected]:
        raise SystemExit(f"{CASES_FILENAME} has no {selected} entry")

    driver_input = {
        "schema_version": 1,
        "attack_queries": cases[selected],
        "benign_queries": [],
    }
    temporary_input = output / "driver-input.json"
    temporary_input.write_text(
        json.dumps(driver_input, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    results_path = output / "driver-results.json"
    if results_path.exists():
        results_path.unlink()
    try:
        completed = _run_driver(
            variant, temporary_input, _repo_dir(revision),
            revision["graphql_query_sha256"], results_path,
        )
        driver_stdout, driver_stderr, driver_returncode = (
            _as_text(completed.stdout), _as_text(completed.stderr), completed.returncode)
    except subprocess.TimeoutExpired as expired:
        # A hung driver leaves no verdict: record the timeout as an observable
        # failure instead of letting the entrypoint raise.
        driver_stdout = _as_text(expired.stdout)
        driver_stderr = _as_text(expired.stderr) + (
            f"\nreproduce.py: driver exceeded {DRIVER_TIMEOUT_SECONDS}s\n")
        driver_returncode = None

    (output / "driver-stdout.txt").write_text(driver_stdout, encoding="utf-8")
    (output / "driver-stderr.txt").write_text(driver_stderr, encoding="utf-8")
    temporary_input.unlink()

    driver = _load(results_path) if results_path.is_file() else {}
    queries = driver.get("results", {}).get("queries", {})
    structure = driver.get("results", {}).get("structure", {})
    loaded_sha = driver.get("module", {}).get("sha256")
    target_ready = (
        driver_returncode == 0
        and driver.get("complete") is True
        and loaded_sha == revision["graphql_query_sha256"]
        and isinstance(queries, dict)
        and bool(queries)
    )

    attack_ids = [item["id"] for item in cases["attack_queries"]]
    benign_ids = [item["id"] for item in cases["benign_queries"]]
    observed = {
        # Structural facts are recorded for both scenarios; they come from the
        # pinned index.ts branch, not from executing a request.
        "project_scope_guard_present": structure.get("project_scope_guard_present"),
        "read_only_guard_present": structure.get("read_only_guard_present"),
        "out_of_allowlist_project": scope.get("out_of_allowlist_project"),
        "raw_endpoint": scope.get("raw_endpoint"),
    }
    if scenario == "attack":
        observed.update({
            # The pre-fix classifier reports the leading-comma mutation as a
            # read-only document, so the read-only gate never fires and the
            # mutation is forwarded to the raw GraphQL endpoint.
            "read_only_bypass_observed": queries.get("leading_comma_mutation") is False,
            # Same separator defect seen through a leading comment and a trailing comma.
            "comment_bypass_observed": queries.get("comment_then_comma_mutation") is False,
            "separator_bypass_observed": queries.get("trailing_comma_subscription") is False,
            # Control case: a plainly written mutation is caught by both revisions.
            "plain_mutation_flagged": queries.get("plain_mutation") is True,
            "bypass_query_flagged": queries.get("leading_comma_mutation") is True,
        })
    else:
        # The benign scenario only asserts that ordinary read queries stay allowed;
        # its payload is the disjoint read-only document set.
        observed["benign_queries_allowed"] = all(
            queries.get(identifier) is False for identifier in benign_ids)
    observation = {
        "target_ready": target_ready,
        "execution_status": "completed" if target_ready else "failed",
        "scenario": scenario,
        "variant": variant,
        "upstream_repository": pin.get("upstream_repository"),
        "upstream_commit": revision.get("commit"),
        "upstream_tag": revision.get("tag"),
        "loaded_module": driver.get("module", {}).get("path"),
        "loaded_module_sha256": loaded_sha,
        "driver_returncode": driver_returncode,
        "attack_query_ids": attack_ids,
        "benign_query_ids": benign_ids,
        "observed": observed,
    }
    effects = {
        "driver-results.json": results_path.read_bytes() if results_path.is_file() else b"",
        "driver-stdout.txt": driver_stdout,
        "driver-stderr.txt": driver_stderr,
    }
    return record(context, output, observation, effects)


if __name__ == "__main__":
    raise SystemExit(main())
