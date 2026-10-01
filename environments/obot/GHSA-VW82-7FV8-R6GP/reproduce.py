"""Mechanism reproduction for GHSA-VW82-7FV8-R6GP.

The authorization bypass lives in Obot's own `pkg/api/authz` package: in v0.21.0
the `staticRules[anyGroup]` entry `"/mcp-connect/"` makes `Authorizer.Authorize`
return `true` for every authenticated user before `authorizeAPIResources` ever
reaches `checkMCPID`, and the `/api`-only UI fallback would allow the same path a
second time. v0.21.1 removes both escapes, so the request falls through to the
access-control-rule evaluation.

This script does not restate that logic. It compiles a driver against the pinned
upstream tree (fixtures/harness/zz_ghsa_vw82_harness_test.go inside
pkg/api/authz/) and calls the pinned `Authorizer.Authorize` for every case in the
scenario fixture, then writes the observed decisions to --output.

Layout expected in the image (produced by the build stage):

  /lab/src/vulnerable  pinned v0.21.0 tree     (821a705516116c8035df221611be4a439e238998)
  /lab/src/patched     pinned v0.21.1 tree     (2a2ec3f23ac564b2e2fab6b09fdef4ecd05fd496)
  /lab/fixtures        scenario fixtures and the driver
  go                   pinned Go toolchain (>= 1.26.2) with a populated module cache
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from lab_support import parser, read_context, record

MODULE = "github.com/obot-platform/obot"
HARNESS = Path("harness") / "zz_ghsa_vw82_harness_test.go"
PACKAGE = Path("pkg") / "api" / "authz"
REPORT = "authorize-report.json"
TIMEOUT = 1800

SOURCE_ROOTS = {
    "vulnerable": ("/lab/src/vulnerable", "/lab/source/vulnerable"),
    "patched": ("/lab/src/patched", "/lab/source/patched"),
}


def find_go() -> str:
    found = shutil.which("go")
    if found:
        return found
    for candidate in ("/usr/local/go/bin/go", "/usr/lib/go/bin/go", "/opt/go/bin/go"):
        if Path(candidate).is_file():
            return candidate
    raise RuntimeError("the pinned Go toolchain is not on PATH in this image")


def find_source(variant: str) -> Path:
    """Return the pinned upstream checkout for this variant."""
    wanted = SOURCE_ROOTS.get(variant)
    if wanted is None:
        raise RuntimeError(f"unknown variant: {variant}")
    roots = [Path(item) for item in wanted]
    roots.extend(sorted(Path("/lab").glob(f"*{variant}*")))
    for root in roots:
        gomod = root / "go.mod"
        if gomod.is_file() and f"module {MODULE}" in gomod.read_text(encoding="utf-8", errors="replace"):
            return root
    raise RuntimeError(f"pinned {variant} upstream tree not found under /lab")


def install_harness(source: Path, fixtures: Path) -> Path:
    harness = fixtures / HARNESS
    if not harness.is_file():
        raise RuntimeError(f"harness driver is missing: {harness}")
    target = source / PACKAGE / harness.name
    if not target.parent.is_dir():
        raise RuntimeError(f"upstream package directory is missing: {target.parent}")
    shutil.copyfile(harness, target)
    return target


def run_harness(go: str, source: Path, fixture: Path, context: dict, output: Path) -> tuple[subprocess.CompletedProcess, str]:
    environment = dict(os.environ)
    environment.update({
        "GOTOOLCHAIN": "local",
        "GOFLAGS": "-mod=mod",
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "LAB_HARNESS_FIXTURE": str(fixture),
        "LAB_HARNESS_OUTPUT": str(output),
        "LAB_VARIANT": context["variant"],
        "LAB_SCENARIO": context["scenario"],
        "LAB_COMMIT": os.environ.get("LAB_SOURCE_COMMIT", ""),
    })
    completed = subprocess.run(
        [go, "test", "./pkg/api/authz/", "-run", "TestGeneratorHarness", "-count=1", "-v"],
        cwd=str(source), env=environment, capture_output=True, text=True, timeout=TIMEOUT,
    )
    return completed, (completed.stdout or "") + (completed.stderr or "")


def subtest_verdicts(transcript: str, cases: list[dict]) -> dict:
    """Parse the Go test transcript as a second, independent copy of the result."""
    verdicts = {}
    for case in cases:
        marker = re.escape(str(case["id"]).replace(" ", "_").replace("/", "_"))
        match = re.search(r"--- (PASS|SKIP|FAIL): TestGeneratorHarness/" + marker + r"\b", transcript)
        if match:
            verdicts[case["id"]] = match.group(1)
    return verdicts


def main() -> int:
    args = parser(__doc__).parse_args()
    context = read_context(args.context)
    variant = context["variant"]
    scenario = context["scenario"]
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    observation = {
        "target_ready": False,
        "execution_status": "failed",
        "variant": variant,
        "scenario": scenario,
        "mechanism": "pkg/api/authz Authorize(/mcp-connect/{mcp_id})",
        "cases": [],
        "all_match": False,
    }

    fixture = Path("/lab/fixtures") / f"{scenario}.json"
    completed = None
    try:
        if not fixture.is_file():
            raise RuntimeError(f"scenario fixture is missing: {fixture}")
        go = find_go()
        source = find_source(variant)
        install_harness(source, Path("/lab/fixtures"))
        completed, transcript = run_harness(go, source, fixture, context, output)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        observation["error"] = f"{type(error).__name__}: {error}"
        return record(context, output, observation, {REPORT: ""})

    report_path = output / REPORT
    if not report_path.is_file():
        observation["error"] = "the pinned harness produced no report"
        observation["harness_exit_code"] = completed.returncode if completed else None
        return record(context, output, observation, {REPORT: transcript})

    report = json.loads(report_path.read_text(encoding="utf-8"))
    cases = report.get("cases") or []
    verdicts = subtest_verdicts(transcript, cases)
    observation.update({
        "target_ready": True,
        "execution_status": "completed",
        "source": str(source),
        "commit": report.get("commit", ""),
        "harness_exit_code": completed.returncode,
        "all_match": bool(report.get("all_match")),
        "cases": [
            {
                "id": case.get("id"),
                "path": case.get("path"),
                "method": case.get("method"),
                "uid": case.get("uid"),
                "expected_allowed": case.get("expected_allowed"),
                "allowed": case.get("allowed"),
                "matches_expectation": case.get("matches_expectation"),
                "subtest": verdicts.get(case.get("id"), "missing"),
            }
            for case in cases
        ],
    })
    if not cases:
        observation["error"] = "the pinned harness reported no cases"
    return record(context, output, observation, {REPORT: report_path.read_bytes()})


if __name__ == "__main__":
    sys.exit(main())
