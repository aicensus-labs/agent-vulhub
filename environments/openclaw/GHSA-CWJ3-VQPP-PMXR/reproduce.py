"""Drive the pinned OpenClaw gateway config-mutation guard on fixed config writes.

GHSA-CWJ3-VQPP-PMXR lives in one function of the upstream file
``src/agents/tools/gateway-tool.ts``. Release 2026.4.22 decides whether an
agent-driven ``config.apply`` / ``config.patch`` may be persisted by testing a
hand-maintained denylist (``PROTECTED_GATEWAY_CONFIG_PATHS``); release 2026.4.23
replaces it with a fail-closed allowlist (``ALLOWED_GATEWAY_CONFIG_PATHS``).

This program does not re-implement either revision. Inside the lab image it
locates the pinned upstream source tree, confirms the revision by the SHA-256 of
that one file, imports the module with the repository's own TypeScript runner,
and calls the upstream test hook
``assertGatewayConfigMutationAllowedForTest`` with the fixed documents from
``fixtures/``. For every mutation the guard allows it then materialises the
config the product would persist, by calling the upstream ``parseConfigJson5``
and ``applyMergePatch`` helpers. An expected rejection is a completed execution,
not a process error.
"""

from __future__ import annotations

from collections.abc import Iterator
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import Any

from lab_support import parser, read_context, record

GUARD_RELATIVE = ("src", "agents", "tools", "gateway-tool.ts")
IO_RELATIVE = ("src", "config", "io.ts")
MERGE_RELATIVE = ("src", "config", "merge-patch.ts")

# Full 40-hex upstream revisions and the SHA-256 of gateway-tool.ts at each one.
# The hash is the revision check: the module is only imported when it matches.
PINNED_REVISIONS: dict[str, dict[str, str]] = {
    "vulnerable": {
        "version": "2026.4.22",
        "commit": "02a8c135016665f0ef58122cf67bdeade507f645",
        "gateway_tool_sha256": "374c50794112c72a1237427cb4c193468e74d6b96d6c103ffab40f0b7b608e16",
    },
    "patched": {
        "version": "2026.4.23",
        "commit": "bceda6089aa7b3695cc7696b43c61ae3d01bb0ec",
        "gateway_tool_sha256": "6f33eee61ca985a7230060cf070001a26bb74250609449e745f0fa144fcf2e40",
    },
}

# name, action, fixed raw document. Every scenario also runs the control case,
# which changes a path the old denylist and the new allowlist both reject.
SCENARIO_CASES: dict[str, tuple[tuple[str, str, str], ...]] = {
    "attack": (
        ("primary", "config.patch", "attack-patch.json"),
        ("apply", "config.apply", "attack-apply.json"),
        ("control_protected", "config.patch", "control-protected-patch.json"),
    ),
    "benign": (
        ("primary", "config.patch", "benign-patch.json"),
        ("control_protected", "config.patch", "control-protected-patch.json"),
    ),
}

SEARCH_ROOTS = (
    "/lab/src", "/lab/upstream", "/lab/openclaw", "/lab/source", "/lab/repo",
    "/opt/openclaw", "/srv/openclaw", "/usr/src/openclaw", "/workspace", "/app",
    "/repo", "/lab", "/opt", "/srv", "/usr/src", "/root", "/home",
)
SKIP_DIRECTORIES = frozenset({
    "node_modules", ".git", ".pnpm", ".cache", "dist", "build", "coverage",
    "__pycache__", ".next", ".turbo", "tmp",
})
DRIVER_TIMEOUT_SECONDS = 300

DRIVER_SOURCE = r'''
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const requestPath = process.argv[2];
const responsePath = process.argv[3];

function emit(value) {
  writeFileSync(responsePath, JSON.stringify(value, null, 2) + "\n");
}

function fail(message) {
  emit({ driver_status: "failed", error: String(message) });
  process.exit(1);
}

const request = JSON.parse(readFileSync(requestPath, "utf8"));

try {
  const guard = await import(pathToFileURL(request.guard_module).href);
  const io = await import(pathToFileURL(request.io_module).href);
  const merge = await import(pathToFileURL(request.merge_module).href);

  const hook = guard.assertGatewayConfigMutationAllowedForTest;
  if (typeof hook !== "function") {
    fail("pinned gateway-tool module does not export assertGatewayConfigMutationAllowedForTest");
  }
  if (typeof io.parseConfigJson5 !== "function") {
    fail("pinned config io module does not export parseConfigJson5");
  }
  if (typeof merge.applyMergePatch !== "function") {
    fail("pinned merge-patch module does not export applyMergePatch");
  }

  const cases = [];
  for (const item of request.cases) {
    const entry = {
      name: item.name,
      action: item.action,
      raw_sha256: item.raw_sha256,
      guard_outcome: null,
      guard_error: null,
      next_config: null,
    };
    try {
      hook({ action: item.action, currentConfig: item.current_config, raw: item.raw });
      entry.guard_outcome = "allowed";
    } catch (error) {
      entry.guard_outcome = "rejected";
      entry.guard_error = error && error.message ? String(error.message) : String(error);
    }
    if (entry.guard_outcome === "allowed") {
      const parsed = io.parseConfigJson5(item.raw);
      if (!parsed || parsed.ok !== true) {
        fail("upstream parseConfigJson5 rejected the fixed " + item.name + " input");
      }
      entry.next_config =
        item.action === "config.apply"
          ? parsed.parsed
          : merge.applyMergePatch(item.current_config, parsed.parsed, { mergeObjectArraysById: true });
    }
    cases.push(entry);
  }

  emit({ driver_status: "completed", cases });
} catch (error) {
  fail(error && error.stack ? error.stack : error);
}
'''


class PrerequisiteError(RuntimeError):
    """A fixed input, tool or pinned source tree is missing."""


def _fixtures_directory() -> Path:
    override = os.environ.get("AVH_FIXTURES_DIR")
    if override:
        return Path(override)
    installed = Path("/lab/fixtures")
    if installed.is_dir():
        return installed
    return Path(__file__).resolve().parent / "fixtures"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _walk_guard_files(base: Path, max_depth: int = 8) -> Iterator[Path]:
    stack: list[tuple[Path, int]] = [(base, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name in SKIP_DIRECTORIES or depth >= max_depth:
                    continue
                stack.append((entry, depth + 1))
            elif (
                entry.is_file()
                and entry.name == "gateway-tool.ts"
                and entry.parent.name == "tools"
                and entry.parent.parent.name == "agents"
            ):
                yield entry


def _candidate_guard_files() -> Iterator[Path]:
    seen: set[Path] = set()
    for name in ("AVH_OPENCLAW_SOURCE", "OPENCLAW_SOURCE", "AVH_SOURCE"):
        value = os.environ.get(name)
        if value:
            root = Path(value)
            direct = root.joinpath(*GUARD_RELATIVE)
            if direct.is_file():
                seen.add(direct)
                yield direct
    for text in SEARCH_ROOTS:
        root = Path(text)
        direct = root.joinpath(*GUARD_RELATIVE)
        if direct.is_file() and direct not in seen:
            seen.add(direct)
            yield direct
        if root.is_dir():
            for candidate in _walk_guard_files(root):
                if candidate not in seen:
                    seen.add(candidate)
                    yield candidate


def _archive_candidates() -> list[Path]:
    archives: list[Path] = []
    bases = (Path("/inputs"), Path("/lab/inputs"), Path(__file__).resolve().parent / "inputs")
    for base in bases:
        if not base.is_dir():
            continue
        for pattern in ("*.tar.gz", "*.tgz", "*.tar"):
            archives.extend(sorted(base.glob(pattern)))
    return archives


def _extract_tar(archive: Path, destination: Path) -> None:
    root = destination.resolve()
    with tarfile.open(archive, "r:*") as tar:
        for member in tar.getmembers():
            # Source archives need no links or devices to expose the module, and
            # extracting them could escape the destination.
            if member.issym() or member.islnk() or member.isdev():
                continue
            target = (destination / member.name).resolve()
            if target != root and root not in target.parents:
                raise ValueError(f"archive member escapes destination: {member.name}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            stream = tar.extractfile(member)
            if stream is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with stream, target.open("wb") as handle:
                shutil.copyfileobj(stream, handle)


def _ensure_node_modules(repository: Path) -> None:
    """Point an extracted tree at the image's installed dependencies."""
    target = repository / "node_modules"
    if target.exists():
        return
    for candidate in (
        Path("/lab/node_modules"),
        Path("/lab/src/node_modules"),
        repository.parent / "node_modules",
    ):
        if candidate.is_dir():
            try:
                target.symlink_to(candidate, target_is_directory=True)
            except OSError:
                pass
            return


def _validate_repository(repository: Path) -> None:
    for relative in (IO_RELATIVE, MERGE_RELATIVE):
        if not repository.joinpath(*relative).is_file():
            raise PrerequisiteError(
                f"pinned source tree {repository} has no {'/'.join(relative)}"
            )


def _locate_source(variant: str, temporary: list[Path]) -> tuple[Path, Path, str]:
    expected = PINNED_REVISIONS[variant]["gateway_tool_sha256"]
    mismatches: list[str] = []
    for candidate in _candidate_guard_files():
        digest = _sha256_file(candidate)
        if digest == expected:
            repository = candidate.parents[len(GUARD_RELATIVE) - 1]
            _validate_repository(repository)
            return repository, candidate, digest
        mismatches.append(f"{candidate} sha256={digest}")
    for archive in _archive_candidates():
        directory = Path(tempfile.mkdtemp(prefix="avh-upstream-"))
        temporary.append(directory)
        try:
            _extract_tar(archive, directory)
        except (OSError, tarfile.TarError, ValueError) as error:
            mismatches.append(f"{archive}: {type(error).__name__}: {error}")
            continue
        for candidate in _walk_guard_files(directory):
            digest = _sha256_file(candidate)
            if digest == expected:
                repository = candidate.parents[len(GUARD_RELATIVE) - 1]
                _ensure_node_modules(repository)
                _validate_repository(repository)
                return repository, candidate, digest
            mismatches.append(f"{candidate} sha256={digest}")
    detail = "; ".join(mismatches[:8]) if mismatches else "no gateway-tool.ts found"
    raise PrerequisiteError(
        f"pinned {variant} source revision not found "
        f"(expected gateway-tool.ts sha256 {expected}); {detail}"
    )


def _build_request(repository: Path, scenario: str, fixtures: Path) -> dict[str, Any]:
    base = _load_json(fixtures / "current-config.json")
    if not isinstance(base, dict):
        raise PrerequisiteError("fixtures/current-config.json must contain a config object")
    cases: list[dict[str, Any]] = []
    for name, action, filename in SCENARIO_CASES[scenario]:
        path = fixtures / filename
        if not path.is_file():
            raise PrerequisiteError(f"missing fixed input: {path}")
        raw = path.read_text(encoding="utf-8")
        cases.append({
            "name": name,
            "action": action,
            "current_config": base,
            "raw": raw,
            "raw_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        })
    return {
        "guard_module": str(repository.joinpath(*GUARD_RELATIVE)),
        "io_module": str(repository.joinpath(*IO_RELATIVE)),
        "merge_module": str(repository.joinpath(*MERGE_RELATIVE)),
        "cases": cases,
    }


def _runner_commands(node: str | None, repository: Path) -> list[list[str]]:
    commands: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()

    def add(parts: list[str]) -> None:
        key = tuple(parts)
        if key not in seen:
            seen.add(key)
            commands.append(parts)

    candidates: list[Path] = []
    override = os.environ.get("AVH_TSX")
    if override:
        candidates.append(Path(override))
    for base in (repository, Path("/lab"), Path("/usr/local"), Path("/opt")):
        candidates.append(base / "node_modules" / ".bin" / "tsx")
        candidates.append(base / "node_modules" / "tsx" / "dist" / "cli.mjs")
    found = shutil.which("tsx")
    if found:
        candidates.append(Path(found))
    for candidate in candidates:
        if not candidate.is_file():
            continue
        add([str(candidate)])
        if node:
            add([node, str(candidate)])
    if node:
        add([node, "--import", "tsx"])
        add([node, "--import", "tsx/esm"])
    npx = shutil.which("npx")
    if npx:
        add([npx, "--no-install", "tsx"])
    return commands


def _execute_driver(
    repository: Path,
    commands: list[list[str]],
    driver_path: Path,
    request_path: Path,
    response_path: Path,
) -> tuple[list[str], dict[str, Any]]:
    problems: list[str] = []
    for command in commands:
        argv = [*command, str(driver_path), str(request_path), str(response_path)]
        if response_path.exists():
            response_path.unlink()
        try:
            completed = subprocess.run(
                argv, cwd=str(repository), capture_output=True, text=True,
                timeout=DRIVER_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError) as error:
            problems.append(f"{' '.join(command)}: {type(error).__name__}: {error}")
            continue
        if response_path.is_file():
            payload = _load_json(response_path)
            if payload.get("driver_status") == "completed":
                return argv, payload
            problems.append(f"{' '.join(command)}: {payload.get('error')}")
            continue
        tail = (completed.stderr or completed.stdout or "").strip().splitlines()[-3:]
        problems.append(f"{' '.join(command)}: exit {completed.returncode}: {' | '.join(tail)}")
    raise PrerequisiteError(
        "no available TypeScript runner could import the pinned module: " + " ;; ".join(problems)
    )


def main() -> int:
    args = parser(__doc__).parse_args()
    context = read_context(args.context)
    variant = context["variant"]
    scenario = context["scenario"]
    pinned = PINNED_REVISIONS[variant]
    observation: dict[str, Any] = {
        "target_ready": False,
        "execution_status": "not_run",
        "variant": variant,
        "scenario": scenario,
        "pinned_version": pinned["version"],
        "pinned_commit": pinned["commit"],
        "expected_guard_sha256": pinned["gateway_tool_sha256"],
        "guard_module": None,
        "guard_module_sha256": None,
        "runner_command": None,
        "guard_outcome": None,
        "guard_error": None,
        "case_outcomes": {},
    }
    effects: dict[str, str] = {}
    temporary: list[Path] = []
    try:
        fixtures = _fixtures_directory()
        if not fixtures.is_dir():
            raise PrerequisiteError(f"fixtures directory not found: {fixtures}")
        repository, guard_path, digest = _locate_source(variant, temporary)
        observation["guard_module"] = str(guard_path)
        observation["guard_module_sha256"] = digest

        node = shutil.which("node")
        commands = _runner_commands(node, repository)
        if not commands:
            raise PrerequisiteError("neither node nor a TypeScript runner (tsx) is available")

        workdir = Path(tempfile.mkdtemp(prefix="avh-guard-"))
        temporary.append(workdir)
        driver_path = workdir / "guard-driver.mjs"
        driver_path.write_text(DRIVER_SOURCE, encoding="utf-8")
        request_path = workdir / "request.json"
        response_path = workdir / "response.json"
        request = _build_request(repository, scenario, fixtures)
        request_path.write_text(
            json.dumps(request, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

        runner_command, payload = _execute_driver(
            repository, commands, driver_path, request_path, response_path
        )
        observation["runner_command"] = " ".join(runner_command)
        observation["target_ready"] = True
        observation["execution_status"] = "completed"

        summaries: list[dict[str, Any]] = []
        primary_next: Any = None
        for case in payload.get("cases", []):
            summary = {key: value for key, value in case.items() if key != "next_config"}
            summaries.append(summary)
            observation["case_outcomes"][case.get("name")] = case.get("guard_outcome")
            if case.get("name") == "primary":
                primary_next = case.get("next_config")
        primary = next((item for item in summaries if item.get("name") == "primary"), None)
        if primary is None:
            raise PrerequisiteError("pinned guard run produced no primary case result")
        observation["guard_outcome"] = primary.get("guard_outcome")
        observation["guard_error"] = primary.get("guard_error")
        effects["guard-result.json"] = json.dumps({
            "driver_status": "completed",
            "hook": "assertGatewayConfigMutationAllowedForTest",
            "pinned_version": pinned["version"],
            "pinned_commit": pinned["commit"],
            "guard_module": str(guard_path),
            "guard_module_sha256": digest,
            "source_root": str(repository),
            "runner_command": " ".join(runner_command),
            "cases": summaries,
        }, ensure_ascii=False, indent=2) + "\n"
        if primary_next is not None:
            effects["next-config.json"] = json.dumps(
                primary_next, ensure_ascii=False, indent=2, sort_keys=True
            ) + "\n"
    except PrerequisiteError as error:
        observation["execution_status"] = "not_run"
        observation["failure_reason"] = str(error)
    except Exception as error:  # noqa: BLE001 - recorded as evidence, never hidden
        observation["execution_status"] = "failed"
        observation["failure_reason"] = f"{type(error).__name__}: {error}"
    finally:
        for directory in temporary:
            shutil.rmtree(directory, ignore_errors=True)
    return record(context, args.output, observation, effects)


if __name__ == "__main__":
    sys.exit(main())
