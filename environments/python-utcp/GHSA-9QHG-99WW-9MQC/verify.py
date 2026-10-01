"""Independent evidence checks for GHSA-9QHG-99WW-9MQC (utcp-http redirect SSRF).

This verifier never invokes the vulnerable code, aiohttp, or any attack code. It
reads only the hash-checked evidence that ``reproduce.py`` already recorded and
decides whether the redirect SSRF actually happened:

* ``attack`` + ``vulnerable``: the attacker endpoint answered ``3xx``, the
  ``Location`` named the non-loopback internal service, the pinned utcp-http
  followed it, and that service's protected canary body came back to the caller.
* ``attack`` + ``patched``: the same attacker hop was reached but the redirect
  target was never contacted, ``call_tool`` raised instead of returning, and no
  canary reached the caller. Reaching the attacker endpoint first is required, so
  a start-up failure or an initial-URL rejection cannot masquerade as a block.
* ``benign``: a direct loopback tool call still returns its benign marker on
  either revision, so the fix does not break the allowed path.

Every fact is read from ``facts.json`` / ``observation.json`` / the declared
effect files; ``lab_support`` re-hashes each declared effect (including
``observation.json``) before ``check`` runs, and the runner re-hashes them again
in ``validate_verdict``. The causal link between the attacker redirect and the
internal body is checked explicitly, not assumed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from lab_support import read_context, verify


CANARY_MARKER = "AVH-CANARY-9QHG-99WW-9MQC"
BENIGN_MARKER = "AVH-BENIGN-OK-9QHG-99WW-9MQC"
ATTACK_EFFECT = "attack_result.json"
BENIGN_EFFECT = "benign_result.json"
TOOL_RESULT = "tool_result.json"

Condition = tuple[str, bool, Any]


def _text(paths: dict[str, Path], name: str) -> str:
    """Return the content of a declared effect file, or "" when it is missing."""
    path = paths.get(name)
    if path is None:
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _json(paths: dict[str, Path], name: str) -> Any:
    text = _text(paths, name)
    if not text.strip():
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _host(url: Any) -> str:
    if not isinstance(url, str):
        return ""
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


def _is_loopback(host: str) -> bool:
    return host in {"localhost", "::1"} or host.startswith("127.")


def _error_message(error: Any) -> str:
    if isinstance(error, dict) and isinstance(error.get("message"), str):
        return error["message"]
    return ""


def _verdict(check_id: str, expected: str, conditions: list[Condition]):
    unmet = [name for name, ok, _ in conditions if not ok]
    actual: dict[str, Any] = {name: value for name, _, value in conditions}
    if unmet:
        actual["unmet"] = unmet
    return check_id, not unmet, expected, actual


def _redirect_link(observation, effect, internal_host):
    """The redirect hop must be recorded by the product and point at the target."""
    location = observation.get("redirect_location")
    effect_location = effect.get("redirect_location")
    return [
        ("redirect_location_recorded", isinstance(location, str) and bool(location),
         location),
        ("effect_redirect_location_recorded",
         isinstance(effect_location, str) and bool(effect_location), effect_location),
        ("redirect_crosses_host", bool(internal_host) and internal_host != _host(observation.get("tool_url")),
         {"tool_host": _host(observation.get("tool_url")), "internal_host": internal_host}),
        ("internal_target_is_non_loopback", bool(internal_host) and not _is_loopback(internal_host),
         internal_host),
        ("redirect_location_targets_internal",
         bool(internal_host) and _host(location) == internal_host,
         {"location_host": _host(location), "internal_host": internal_host}),
        ("effect_redirect_location_targets_internal",
         bool(internal_host) and _host(effect_location) == internal_host,
         {"location_host": _host(effect_location), "internal_host": internal_host}),
    ]


def _vulnerable_attack(context, observation, paths):
    """The redirect was followed to the internal service and the canary leaked."""
    effect = _json(paths, ATTACK_EFFECT)
    effect = effect if isinstance(effect, dict) else {}
    tool_text = _text(paths, TOOL_RESULT)
    internal_host = _host(observation.get("internal_service_url"))
    conditions: list[Condition] = [
        ("target_ready", observation.get("target_ready") is True,
         observation.get("target_ready")),
        ("attacker_endpoint_contacted", observation.get("attacker_requests", 0) >= 1,
         observation.get("attacker_requests")),
        ("effect_attacker_endpoint_contacted", effect.get("attacker_requests", 0) >= 1,
         effect.get("attacker_requests")),
        ("internal_service_contacted", observation.get("internal_service_requests", 0) >= 1,
         observation.get("internal_service_requests")),
        *_redirect_link(observation, effect, internal_host),
        ("call_returned", observation.get("call_returned") is True,
         observation.get("call_returned")),
        ("effect_call_returned", effect.get("call_returned") is True,
         effect.get("call_returned")),
        ("no_call_error", observation.get("call_error") is None,
         observation.get("call_error")),
        ("canary_marker_matches", observation.get("canary_marker") == CANARY_MARKER,
         observation.get("canary_marker")),
        ("canary_observed", observation.get("canary_observed") is True,
         observation.get("canary_observed")),
        ("canary_in_response_excerpt", CANARY_MARKER in (observation.get("response_excerpt") or ""),
         observation.get("response_excerpt", "")[:120]),
        ("canary_in_tool_result", CANARY_MARKER in tool_text,
         tool_text[:200]),
        ("effect_internal_service_contacted", effect.get("internal_service_requests", 0) >= 1,
         effect.get("internal_service_requests")),
        ("effect_canary_observed", effect.get("canary_observed") is True,
         effect.get("canary_observed")),
    ]
    expected = ("vulnerable utcp-http follows the attacker redirect to the non-loopback "
                "internal service and returns its protected canary body")
    return _verdict("vulnerable_effect_observed", expected, conditions)


def _patched_attack(context, observation, paths):
    """The patched revision re-validated the hop, so the internal target was never reached."""
    effect = _json(paths, ATTACK_EFFECT)
    effect = effect if isinstance(effect, dict) else {}
    tool_text = _text(paths, TOOL_RESULT)
    error = observation.get("call_error")
    internal_host = _host(observation.get("internal_service_url"))
    message = _error_message(error)
    conditions: list[Condition] = [
        ("target_ready", observation.get("target_ready") is True,
         observation.get("target_ready")),
        ("attacker_endpoint_contacted", observation.get("attacker_requests", 0) >= 1,
         observation.get("attacker_requests")),
        ("effect_attacker_endpoint_contacted", effect.get("attacker_requests", 0) >= 1,
         effect.get("attacker_requests")),
        ("internal_service_not_contacted", observation.get("internal_service_requests", 0) == 0,
         observation.get("internal_service_requests")),
        ("call_not_returned", observation.get("call_returned") is False,
         observation.get("call_returned")),
        ("effect_call_not_returned", effect.get("call_returned") is False,
         effect.get("call_returned")),
        ("rejected_with_error",
         isinstance(error, dict) and isinstance(error.get("type"), str) and bool(error["type"]),
         error),
        ("error_references_redirect_target",
         bool(internal_host) and internal_host in message,
         {"internal_host": internal_host, "message": message[:300]}),
        ("canary_marker_matches", observation.get("canary_marker") == CANARY_MARKER,
         observation.get("canary_marker")),
        ("canary_not_observed", observation.get("canary_observed") is False,
         observation.get("canary_observed")),
        ("canary_not_in_response_excerpt", CANARY_MARKER not in (observation.get("response_excerpt") or ""),
         observation.get("response_excerpt", "")[:120]),
        ("canary_not_in_tool_result", CANARY_MARKER not in tool_text,
         tool_text[:200]),
        ("effect_internal_service_not_contacted", effect.get("internal_service_requests", 0) == 0,
         effect.get("internal_service_requests")),
        ("effect_canary_not_observed", effect.get("canary_observed") is False,
         effect.get("canary_observed")),
    ]
    expected = ("patched utcp-http rejects the redirect hop before contacting the "
                "internal service, so no canary reaches the caller")
    return _verdict("patched_effect_blocked", expected, conditions)


def _benign(context, observation, paths):
    """A direct loopback tool call still returns its benign marker."""
    effect = _json(paths, BENIGN_EFFECT)
    effect = effect if isinstance(effect, dict) else {}
    tool_text = _text(paths, TOOL_RESULT)
    conditions: list[Condition] = [
        ("target_ready", observation.get("target_ready") is True,
         observation.get("target_ready")),
        ("endpoint_contacted", observation.get("endpoint_requests", 0) >= 1,
         observation.get("endpoint_requests")),
        ("call_returned", observation.get("call_returned") is True,
         observation.get("call_returned")),
        ("effect_call_returned", effect.get("call_returned") is True,
         effect.get("call_returned")),
        ("no_call_error", observation.get("call_error") is None,
         observation.get("call_error")),
        ("benign_marker_matches", observation.get("benign_marker") == BENIGN_MARKER,
         observation.get("benign_marker")),
        ("benign_marker_observed", observation.get("benign_marker_observed") is True,
         observation.get("benign_marker_observed")),
        ("benign_marker_in_response_excerpt",
         BENIGN_MARKER in (observation.get("response_excerpt") or ""),
         observation.get("response_excerpt", "")[:120]),
        ("benign_marker_in_tool_result", BENIGN_MARKER in tool_text,
         tool_text[:200]),
        ("tool_result_not_empty", bool(tool_text.strip()),
         tool_text[:200]),
        ("effect_benign_marker_observed", effect.get("benign_marker_observed") is True,
         effect.get("benign_marker_observed")),
    ]
    expected = "the benign loopback tool call still returns its benign marker"
    return _verdict("benign_task_passed", expected, conditions)


def check(context, observation, paths):
    """Decide one scenario strictly from already-recorded, hash-checked evidence."""
    if context["scenario"] == "benign":
        return _benign(context, observation, paths)
    if context["variant"] == "patched":
        return _patched_attack(context, observation, paths)
    return _vulnerable_attack(context, observation, paths)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    read_context(args.context)
    return verify(args.context, args.output, check)


if __name__ == "__main__":
    raise SystemExit(main())
