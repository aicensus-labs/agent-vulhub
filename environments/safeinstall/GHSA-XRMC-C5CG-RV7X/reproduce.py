"""Mechanism PoC for GHSA-XRMC-C5CG-RV7X: drive the pinned SafeInstall agent guard parser.

The PoC does not reimplement or extract the guard. It locates the upstream
`safeinstall-cli` package in this image, requires its compiled
`dist/guard-commands.js` with Node and calls the exported
`analyzeShellCommand()` on the command texts named by the fixture for the current
scenario. The unmodified parser result for every command is written to
`guard-analysis.json`; the verifier derives its verdict from that file and
`observation.json` alone.

The crafted commands only ever reach that pure analysis function. No package
manager is executed, no registry is contacted and no lifecycle script runs, so
the effect under observation is the guard's own classification: the vulnerable
classifier returns no install, runner or unanalyzable conclusion, while the fixed
classifier returns an install finding (deny/rewrite), a remote-runner finding
(ask) or an explicit failure-closed result.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from lab_support import parser, read_context, record

FIXTURES = Path("/lab/fixtures")
ANALYSIS_EFFECT = "guard-analysis.json"
NODE_TIMEOUT_SECONDS = 120
# The two pinned revisions this environment compares, keyed by context variant.
EXPECTED_UPSTREAM_VERSION = {"vulnerable": "0.10.1", "patched": "0.10.2"}
# Roots a reviewed build recipe may install the pinned package into. Discovery is
# an explicit list so a different package shipped in the base image cannot be
# mistaken for the component under test.
MODULE_ROOTS = (
    "/lab/upstream",
    "/lab/vendor",
    "/lab/src",
    "/lab/node_modules",
    "/opt/safeinstall",
    "/opt",
    "/usr/local/lib/node_modules",
    "/usr/lib/node_modules",
    "/lab",
)
NODE_CANDIDATES = (
    "/usr/local/bin/node",
    "/usr/bin/node",
    "/opt/node/bin/node",
    "/usr/local/node/bin/node",
)
# Read the module path and command list from stdin, call the pinned export and
# copy only the fields the evidence protocol needs.
NODE_SCRIPT = r"""
"use strict";
const fs = require("fs");
const spec = JSON.parse(fs.readFileSync(0, "utf8"));
const upstream = require(spec.module);
const analyze = upstream.analyzeShellCommand;
if (typeof analyze !== "function") {
  throw new Error("pinned module does not export analyzeShellCommand");
}
const asArray = (value) => (Array.isArray(value) ? value : []);
const results = spec.commands.map((entry) => {
  const raw = analyze(entry.command) || {};
  const installs = asArray(raw.installs);
  const runners = asArray(raw.runners);
  const unanalyzable = asArray(raw.unanalyzable);
  return {
    id: entry.id,
    command: entry.command,
    installs: installs.map((item) => ({
      manager: item.manager === undefined ? null : item.manager,
      subcommand: item.command === undefined ? null : item.command,
      segmentText: item.segmentText === undefined ? null : item.segmentText,
    })),
    runners: runners.map((item) => ({
      tool: item.tool === undefined ? null : item.tool,
      packageHint: item.packageHint === undefined ? null : item.packageHint,
      fetchesRemote: item.fetchesRemote === true,
      segmentText: item.segmentText === undefined ? null : item.segmentText,
    })),
    unanalyzable: unanalyzable.map((item) => ({
      segmentText: item.segmentText === undefined ? null : item.segmentText,
      reason: item.reason === undefined ? null : item.reason,
    })),
    usesSafeInstall: raw.usesSafeInstall === true,
    rewrittenCommand: raw.rewrittenCommand === undefined ? null : raw.rewrittenCommand,
    writeTargets: asArray(raw.writeTargets),
  };
});
process.stdout.write(JSON.stringify({ results: results }));
"""


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def find_node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    for candidate in NODE_CANDIDATES:
        if os.access(candidate, os.X_OK):
            return candidate
    return None


def node_version(node: str) -> str:
    try:
        completed = subprocess.run([node, "--version"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout.strip()


def package_identity(module_path: Path) -> tuple[str | None, str | None]:
    """Read name/version from the package.json next to the module's dist/."""
    try:
        data = json.loads((module_path.parent.parent / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, None
    name = data.get("name") if isinstance(data.get("name"), str) else None
    version = data.get("version") if isinstance(data.get("version"), str) else None
    return name, version


def iter_guard_modules(max_depth: int = 8):
    """Yield every ``dist/guard-commands.js`` under the known install roots."""
    seen: set[str] = set()
    for root in MODULE_ROOTS:
        base = Path(root)
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            current = Path(dirpath)
            try:
                depth = len(current.relative_to(base).parts)
            except ValueError:
                depth = 0
            if depth >= max_depth:
                dirnames[:] = []
            if current.name != "dist" or "guard-commands.js" not in filenames:
                continue
            candidate = current / "guard-commands.js"
            if str(candidate) in seen or not candidate.is_file():
                continue
            seen.add(str(candidate))
            yield candidate


def select_guard_module(variant: str) -> Path | None:
    """Pick the pinned revision for this variant, preferring the exact version."""
    override = os.environ.get("SAFEINSTALL_GUARD_MODULE", "").strip()
    if override:
        path = Path(override)
        return path if path.is_file() else None
    expected = EXPECTED_UPSTREAM_VERSION[variant]
    candidates: list[tuple[Path, str | None]] = []
    for candidate in iter_guard_modules():
        name, version = package_identity(candidate)
        if name not in (None, "safeinstall-cli"):
            continue
        candidates.append((candidate, version))
    for candidate, version in candidates:
        if version == expected:
            return candidate
    return candidates[0][0] if candidates else None


def run_analysis(node: str, module_path: Path, entries: list) -> tuple[list | None, str | None]:
    """Call the pinned ``analyzeShellCommand`` for every fixture command."""
    spec = {
        "module": str(module_path),
        "commands": [{"id": entry["id"], "command": entry["command"]} for entry in entries],
    }
    try:
        completed = subprocess.run(
            [node, "-e", NODE_SCRIPT],
            input=json.dumps(spec),
            capture_output=True,
            text=True,
            timeout=NODE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return None, f"upstream guard analysis exceeded {NODE_TIMEOUT_SECONDS}s"
    except OSError as error:
        return None, f"could not execute node: {error}"
    if completed.returncode != 0:
        lines = [line for line in (completed.stderr or completed.stdout or "").strip().splitlines() if line]
        return None, "upstream guard analysis exited %d: %s" % (
            completed.returncode, lines[-1] if lines else "no output")
    try:
        payload = json.loads(completed.stdout)
    except ValueError as error:
        return None, f"upstream guard analysis produced unreadable output: {error}"
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list) or len(results) != len(entries):
        return None, "upstream guard analysis did not return one result per command"
    return results, None


def stop(context: dict, output: str, status: str, reason: str) -> int:
    return record(
        context,
        output,
        {
            "target_ready": False,
            "execution_status": status,
            "reason": reason,
            "scenario": context["scenario"],
            "variant": context["variant"],
        },
    )


def main() -> int:
    args = parser(__doc__).parse_args()
    context = read_context(args.context)
    scenario = context["scenario"]
    variant = context["variant"]

    fixture_path = FIXTURES / f"{scenario}.json"
    try:
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return stop(context, args.output, "not_run", f"fixture {fixture_path} is unreadable: {error}")
    entries = fixture.get("commands") if isinstance(fixture, dict) else None
    if not isinstance(entries, list) or not entries:
        return stop(context, args.output, "not_run", f"fixture {fixture_path} declares no commands")
    for entry in entries:
        if (not isinstance(entry, dict) or not isinstance(entry.get("id"), str)
                or not isinstance(entry.get("command"), str)):
            return stop(context, args.output, "not_run", "fixture entries need a string id and command")

    node = find_node()
    if node is None:
        return stop(context, args.output, "not_run", "node runtime is not available in this image")
    module_path = select_guard_module(variant)
    if module_path is None:
        return stop(context, args.output, "not_run",
                    "pinned safeinstall-cli dist/guard-commands.js was not found in this image")
    name, version = package_identity(module_path)
    if name != "safeinstall-cli":
        return stop(context, args.output, "failed",
                    f"discovered module {module_path} does not identify itself as safeinstall-cli")
    expected = EXPECTED_UPSTREAM_VERSION[variant]
    if version != expected:
        return stop(context, args.output, "failed",
                    f"guard module {module_path} is version {version!r}, "
                    f"but the {variant} revision is pinned to {expected!r}")

    results, error = run_analysis(node, module_path, entries)
    if error is not None:
        return stop(context, args.output, "failed", error)

    # Carry the declared grouping and per-revision expectation of every fixed
    # input alongside the raw parser result, so the verdict can compare the two
    # instead of trusting whichever one it happened to read first.
    declared = {entry["id"]: {key: entry.get(key) for key in
                              ("group", "category", "expect_vulnerable", "expect_patched")}
                for entry in entries}
    for item in results:
        for key, value in declared.get(item["id"], {}).items():
            if value is not None:
                item[key] = value

    guard_sha256 = sha256_file(module_path)
    runtime_version = node_version(node)
    payload = {
        "schema_version": 1,
        "scenario": scenario,
        "variant": variant,
        "upstream": {"module": str(module_path), "name": name, "version": version,
                     "guard_commands_sha256": guard_sha256},
        "runtime": {"node": node, "node_version": runtime_version},
        "commands": results,
    }
    with_finding = [item["id"] for item in results
                    if item["installs"] or item["runners"] or item["unanalyzable"]]
    without_finding = [item["id"] for item in results
                       if not (item["installs"] or item["runners"] or item["unanalyzable"])]
    observation = {
        "target_ready": True,
        "execution_status": "completed",
        "scenario": scenario,
        "variant": variant,
        "upstream_module": str(module_path),
        "upstream_name": name,
        "upstream_version": version,
        "upstream_guard_commands_sha256": guard_sha256,
        "node_version": runtime_version,
        "command_count": len(results),
        "commands_with_finding": with_finding,
        "commands_without_finding": without_finding,
    }
    effects = {ANALYSIS_EFFECT: json.dumps(payload, ensure_ascii=False, indent=2) + "\n"}
    return record(context, args.output, observation, effects)


if __name__ == "__main__":
    raise SystemExit(main())
