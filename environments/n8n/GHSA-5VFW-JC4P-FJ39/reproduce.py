"""Run the GHSA-5VFW-JC4P-FJ39 mechanism against the pinned upstream releases.

The pinned revisions are n8n@2.29.7 (vulnerable) and n8n@2.29.8 (patched), fixed
by their complete commit SHAs and published npm tarball SHA-256 in
`research/public.md`. This entrypoint does not re-implement the flaw: it loads
the upstream compiled OAuth 2.1 consent and token services from
`/lab/fixtures/upstream/<version>/` after hash-checking every one of them
against `fixtures/manifest.toml`, and drives them through the scenario in
`/lab/fixtures/attack.json` or `/lab/fixtures/benign.json`.

Two gates are exercised, both upstream code:

  * `OAuthConsentService.getConsentDetails/handleConsentDecision`
  * `OAuthTokenService.verifyOAuthAccessToken`

The lab supplies the environment those services run in (in-memory repositories,
a local HS256 signer, and the protected-resource descriptor the workflow MCP
trigger resolver returns). The descriptor carries an `authorize` member only in
the release whose resolver adds one, so the missing check is a property of the
pinned code, not of this file.

Exit status follows the lab contract: 0 completed, 2 not run, 1 failed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

from lab_support import parser, read_context, record, sha256

# The image always mounts the fixtures at /lab/fixtures. The environment variable
# exists only so the Generator can exercise the entrypoints outside the container.
FIXTURES = Path(os.environ.get("LAB_FIXTURES", "/lab/fixtures"))
HARNESS = FIXTURES / "harness" / "runner.js"
UPSTREAM = FIXTURES / "upstream"
SHIMS = FIXTURES / "harness" / "shims"
MANIFEST = FIXTURES / "manifest.toml"
TIMEOUT_SECONDS = 120
VARIANTS = {"vulnerable": "2.29.7", "patched": "2.29.8"}


def _manifest_entries() -> dict[str, str]:
    data = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
    entries = data.get("files")
    if not isinstance(entries, dict) or not entries:
        raise ValueError("fixtures/manifest.toml has no [files] entries")
    return entries


def _check_pinned_files() -> list[str]:
    """Refuse to execute any fixture whose bytes drifted from the manifest."""
    drifted = []
    for relative, expected in _manifest_entries().items():
        path = FIXTURES / relative
        if not path.is_file():
            drifted.append(f"{relative}: missing")
        elif sha256(path) != expected:
            drifted.append(f"{relative}: sha256 mismatch")
    return drifted


def _run_harness(fixture: dict, version: str) -> tuple[dict | None, str | None]:
    node = shutil.which("node")
    if node is None:
        return None, "node runtime is not available in the image"
    command = [
        node, str(HARNESS),
        "--upstream", str(UPSTREAM),
        "--shims", str(SHIMS),
        "--fixture", str(FIXTURES / f"{fixture['scenario']}.json"),
        "--variant", version,
    ]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return None, f"mechanism run exceeded {TIMEOUT_SECONDS}s"
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        return None, detail[-1] if detail else f"mechanism run exited {completed.returncode}"
    try:
        return json.loads(completed.stdout), None
    except json.JSONDecodeError as error:
        return None, f"mechanism run produced unparsable output: {error}"


def main() -> int:
    args = parser(__doc__).parse_args()
    context = read_context(args.context)
    scenario = context["scenario"]
    version = VARIANTS[context["variant"]]

    if not HARNESS.is_file():
        print(f"missing {HARNESS}", file=sys.stderr)
        return record(context, args.output, {
            "target_ready": False,
            "execution_status": "not_run",
            "detail": "the mechanism harness is absent from the image",
        })

    try:
        drifted = _check_pinned_files()
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"cannot read fixture manifest: {error}", file=sys.stderr)
        return record(context, args.output, {
            "target_ready": False,
            "execution_status": "not_run",
            "detail": str(error),
        })
    if drifted:
        print("fixture integrity failure: " + "; ".join(drifted), file=sys.stderr)
        return record(context, args.output, {
            "target_ready": False,
            "execution_status": "failed",
            "detail": "fixture integrity failure: " + "; ".join(drifted),
        })

    fixture = json.loads((FIXTURES / f"{scenario}.json").read_text(encoding="utf-8"))
    artifact, failure = _run_harness(fixture, version)

    observation: dict = {
        "target_ready": artifact is not None,
        "execution_status": "failed",
        "upstream_version": version,
        "scenario": scenario,
        "fixture": f"{scenario}.json",
        "subject": fixture.get("subject", {}).get("id"),
        "resource": fixture.get("resource", {}).get("url"),
    }
    if artifact is None:
        observation["detail"] = failure
        print(f"mechanism run failed: {failure}", file=sys.stderr)
        return record(context, args.output, observation)

    consent = artifact.get("consent", {})
    details = consent.get("details") or {}
    effects = {"effects.json": json.dumps(artifact, ensure_ascii=False, indent=2) + "\n"}
    observation.update({
        "execution_status": "completed",
        "outcome": artifact.get("outcome"),
        "resource_authorize_present": artifact.get("resource_authorize_present"),
        "resource_authorize_consulted": artifact.get("resource_authorize_consulted"),
        "consent_code_minted": consent.get("code_minted"),
        "consent_status": consent.get("http_status"),
        "consent_reason": details.get("reason"),
        "consent_resource_name": details.get("resourceName"),
        "token_accepted": artifact.get("token", {}).get("accepted"),
        "token_reason": artifact.get("token", {}).get("reason"),
        "token_user": artifact.get("token", {}).get("user"),
        "workflow_executed": artifact.get("workflow_executed"),
        "executed_in_owner_context": artifact.get("executed_in_owner_context"),
        "execution_owner": artifact.get("execution_owner"),
        "blocked": artifact.get("blocked"),
        "blocked_by": artifact.get("blocked_by"),
        "authorized_user_expected": artifact.get("authorized_user_expected"),
    })
    if artifact.get("fatal"):
        observation["detail"] = artifact["fatal"]
    return record(context, args.output, observation, effects)


if __name__ == "__main__":
    raise SystemExit(main())
