"""Judge the recorded GHSA-PC2W-4MQ8-32QW evidence without re-running the attack.

This verifier is read-only and offline.  It never imports or invokes the pinned
``@dynatrace-oss/dynatrace-mcp-server`` bundle, never speaks MCP and never opens
a network socket.  It consumes only the hash-checked artefacts ``reproduce.py``
wrote through ``lab_support.record``:

* ``observation.json`` -- the PoC's structured observations (loaded by
  ``lab_support.verify`` and passed in here);
* ``mock_requests.json`` -- every HTTP request the controlled HTTPS receiver
  actually accepted, including the method, path and body bytes;
* ``tool_exchange.json`` -- the MCP initialize result, the approval requests the
  client received and the ``tools/call`` result.

The decisive question for each ``(variant, scenario)`` pair is answered from the
requests the receiver really recorded, not from any ``success`` flag:

* ``attack`` + ``vulnerable`` -> ``vulnerable_effect_observed``: a ``POST`` to
  ``/platform/document/v1/documents`` carries the attacker marker and the
  attacker-chosen notebook name, and no human approval was ever requested.
* ``attack`` + ``patched`` -> ``patched_effect_blocked``: the tool call returns
  the upstream "Operation cancelled" refusal and **no** document request is
  recorded at all.
* ``benign`` + either variant -> ``benign_task_passed``: the operator-approved
  notebook is still persisted (and, on the patched build, the approval gate was
  actually consulted first).

A run that never loaded the pinned mechanism, never returned from the tool call
or left no effect file can therefore never be read as "the patch blocked it":
``lab_support.verify`` returns ``not_run`` (2) unless facts and observation both
record ``execution_status = completed``, and every branch below additionally
demands that the tool call returned, that the bundle classified as the expected
variant, and that the receiver evidence agrees with the observation counters.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lab_support import parser, read_context, verify

# Effect files declared by reproduce.py and therefore present in the evidence map.
REQUESTS_EFFECT = "mock_requests.json"
EXCHANGE_EFFECT = "tool_exchange.json"
STDERR_EFFECT = "server_stderr.txt"

# Document store path the vulnerable callback writes to (reproduce.DOCUMENT_PATH).
DOCUMENT_PATH = "/platform/document/v1/documents"

# Exact fail-closed message the fixed callback returns (v1.8.7, fix commit
# 2851d3ce29d834c93b67f0db903c10e0b488e7ac).
PATCH_REFUSAL = "Operation cancelled: Human approval was not granted"
REFUSAL_HINTS = ("cancel", "not granted", "approval")

CLASS_VULNERABLE = "vulnerable"
CLASS_PATCHED = "patched"


# --------------------------------------------------------------------------- #
# Evidence readers (paths come from the hash-checked facts inventory)
# --------------------------------------------------------------------------- #
def _load_json(path: Path | None) -> Any:
    if path is None:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _load_text(path: Path | None) -> str:
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _requests(paths: dict[str, Path]) -> tuple[list[dict[str, Any]], str]:
    """Return (records, problem). ``problem`` is empty when the effect is usable."""
    path = paths.get(REQUESTS_EFFECT)
    if path is None:
        return [], f"{REQUESTS_EFFECT} is missing from the recorded evidence"
    value = _load_json(path)
    if not isinstance(value, list):
        return [], f"{REQUESTS_EFFECT} is not a JSON list"
    records = [item for item in value if isinstance(item, dict)]
    if len(records) != len(value):
        return [], f"{REQUESTS_EFFECT} contains non-object entries"
    return records, ""


def _normalized_path(record: dict[str, Any]) -> str:
    raw = record.get("path")
    if not isinstance(raw, str) or not raw:
        target = record.get("target")
        raw = target if isinstance(target, str) else ""
    return raw.split("?", 1)[0].rstrip("/")


def _is_document_post(record: dict[str, Any]) -> bool:
    method = record.get("method")
    return (
        isinstance(method, str)
        and method.upper() == "POST"
        and _normalized_path(record) == DOCUMENT_PATH
    )


def _body(record: dict[str, Any]) -> str:
    body = record.get("body")
    return body if isinstance(body, str) else ""


def _document_bodies(records: list[dict[str, Any]]) -> list[str]:
    return [_body(item) for item in records if _is_document_post(item)]


def _all_bodies(records: list[dict[str, Any]]) -> str:
    return "\n".join(_body(item) for item in records)


def _fail(check_id: str, expected: str, actual: str) -> tuple[str, bool, str, str]:
    return check_id, False, expected, actual


# --------------------------------------------------------------------------- #
# Per-case decisions
# --------------------------------------------------------------------------- #
def _base_problem(context: dict[str, Any], observation: dict[str, Any]) -> str:
    """Common preconditions; returns an empty string when the run is usable."""
    if observation.get("target_ready") is not True:
        return "the pinned upstream mechanism did not complete (target_ready is not true)"
    if observation.get("execution_status") != "completed":
        return f"execution_status is {observation.get('execution_status')!r}, not 'completed'"
    if observation.get("scenario") != context["scenario"]:
        return f"observation scenario {observation.get('scenario')!r} != {context['scenario']!r}"
    if observation.get("variant") != context["variant"]:
        return f"observation variant {observation.get('variant')!r} != {context['variant']!r}"
    classification = observation.get("upstream_classification")
    if classification != context["variant"]:
        return (
            f"loaded bundle classified as {classification!r}, expected {context['variant']!r}"
        )
    if observation.get("mcp_initialized") is not True:
        return "the MCP server was never initialized"
    if observation.get("tool_call_returned") is not True:
        return "the tools/call did not return (server crashed or timed out)"
    return ""


def _consistent_counters(
    observation: dict[str, Any], document_count: int, marker_seen: bool
) -> str:
    """Cross-check the receiver evidence against the PoC's own counters."""
    recorded = observation.get("document_requests")
    if recorded != document_count:
        return (
            f"observation document_requests={recorded!r} disagrees with the "
            f"receiver evidence ({document_count} document requests)"
        )
    recorded_marker = observation.get("marker_seen_in_document_request")
    if recorded_marker is not marker_seen:
        return (
            f"observation marker_seen_in_document_request={recorded_marker!r} disagrees "
            f"with the receiver evidence ({marker_seen})"
        )
    return ""


def _attack_vulnerable(
    context: dict[str, Any], observation: dict[str, Any], paths: dict[str, Path]
) -> tuple[str, bool, str, str]:
    check_id = "vulnerable_effect_observed"
    expected = (
        "The vulnerable build POSTs the attacker-controlled notebook "
        "(marker and name) to /platform/document/v1/documents without any human approval."
    )
    problem = _base_problem(context, observation)
    if problem:
        return _fail(check_id, expected, problem)

    records, problem = _requests(paths)
    if problem:
        return _fail(check_id, expected, problem)

    marker = observation.get("payload_marker")
    name = observation.get("expected_notebook_name")
    if not isinstance(marker, str) or not marker:
        return _fail(check_id, expected, "observation has no payload marker to look for")
    if not isinstance(name, str) or not name:
        return _fail(check_id, expected, "observation has no expected notebook name")

    bodies = _document_bodies(records)
    marker_seen = any(marker in body for body in bodies)
    name_seen = any(name in body for body in bodies)
    approvals = observation.get("approval_requests")
    result_text = observation.get("tool_result_text") or ""

    problem = _consistent_counters(observation, len(bodies), marker_seen)
    if problem:
        return _fail(check_id, expected, problem)

    actual = (
        f"document_requests={len(bodies)}, marker_persisted={marker_seen}, "
        f"notebook_name_persisted={name_seen}, approval_requests={approvals!r}, "
        f"tool_result={result_text[:200]!r}"
    )
    passed = (
        len(bodies) >= 1
        and marker_seen
        and name_seen
        and approvals == 0
        and not any(hint in result_text.lower() for hint in ("cancel", "not granted"))
    )
    return check_id, passed, expected, actual


def _attack_patched(
    context: dict[str, Any], observation: dict[str, Any], paths: dict[str, Path]
) -> tuple[str, bool, str, str]:
    check_id = "patched_effect_blocked"
    expected = (
        "The patched build's approval gate refuses the unapproved call and no "
        "request to /platform/document/v1/documents is ever recorded."
    )
    problem = _base_problem(context, observation)
    if problem:
        return _fail(check_id, expected, problem)

    records, problem = _requests(paths)
    if problem:
        return _fail(check_id, expected, problem)

    marker = observation.get("payload_marker")
    if not isinstance(marker, str) or not marker:
        return _fail(check_id, expected, "observation has no payload marker to look for")

    bodies = _document_bodies(records)
    marker_seen = any(marker in body for body in bodies)
    marker_anywhere = marker in _all_bodies(records)
    result_text = (observation.get("tool_result_text") or "")
    lowered = result_text.lower()
    refused = PATCH_REFUSAL.lower() in lowered or any(hint in lowered for hint in REFUSAL_HINTS)

    problem = _consistent_counters(observation, len(bodies), marker_seen)
    if problem:
        return _fail(check_id, expected, problem)

    actual = (
        f"document_requests={len(bodies)}, marker_persisted={marker_seen}, "
        f"marker_in_any_request={marker_anywhere}, tool_result={result_text[:200]!r}"
    )
    # A crash or a missing tool result is not a block: the callback must have
    # returned the gate's refusal and the sink must have stayed untouched.
    passed = (
        len(bodies) == 0
        and not marker_anywhere
        and refused
    )
    return check_id, passed, expected, actual


def _benign(
    context: dict[str, Any], observation: dict[str, Any], paths: dict[str, Path]
) -> tuple[str, bool, str, str]:
    check_id = "benign_task_passed"
    expected = (
        "The operator-approved notebook write still succeeds in this build "
        "(and the patched build consults the approval gate first)."
    )
    problem = _base_problem(context, observation)
    if problem:
        return _fail(check_id, expected, problem)

    records, problem = _requests(paths)
    if problem:
        return _fail(check_id, expected, problem)

    marker = observation.get("payload_marker")
    name = observation.get("expected_notebook_name")
    if not isinstance(marker, str) or not marker:
        return _fail(check_id, expected, "observation has no payload marker to look for")
    if not isinstance(name, str) or not name:
        return _fail(check_id, expected, "observation has no expected notebook name")

    bodies = _document_bodies(records)
    marker_seen = any(marker in body for body in bodies)
    name_seen = any(name in body for body in bodies)
    approvals = observation.get("approval_requests")
    result_text = observation.get("tool_result_text") or ""

    problem = _consistent_counters(observation, len(bodies), marker_seen)
    if problem:
        return _fail(check_id, expected, problem)

    gate_ok = True
    if context["variant"] == CLASS_PATCHED:
        gate_ok = isinstance(approvals, int) and approvals >= 1

    actual = (
        f"document_requests={len(bodies)}, marker_persisted={marker_seen}, "
        f"notebook_name_persisted={name_seen}, approval_requests={approvals!r}, "
        f"tool_result={result_text[:200]!r}"
    )
    passed = (
        len(bodies) >= 1
        and marker_seen
        and name_seen
        and gate_ok
        and not any(hint in result_text.lower() for hint in ("cancel", "not granted"))
    )
    return check_id, passed, expected, actual


def check(context: dict[str, Any], observation: dict[str, Any], paths: dict[str, Path]):
    """Return one (check_id, passed, expected, actual) tuple for this case."""
    if context["scenario"] == "benign":
        return _benign(context, observation, paths)
    if context["variant"] == CLASS_VULNERABLE:
        return _attack_vulnerable(context, observation, paths)
    return _attack_patched(context, observation, paths)


def main() -> int:
    args = parser(__doc__).parse_args()
    read_context(args.context)
    return verify(args.context, args.output, check)


if __name__ == "__main__":
    raise SystemExit(main())
