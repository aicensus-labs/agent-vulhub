"""Independent evidence verifier for GHSA-8CP3-QXJ6-PX34 (utcp-http OAuth2 tokenUrl bypass).

This script never imports or runs the vulnerable product.  ``lab_support.verify``
hash-checks ``facts.json``, ``observation.json`` and every declared effect file and
binds them to the execution context before calling :func:`check`; the check then
only parses the already-verified ``effect.json`` (plus the cross-checked
``observation.json``) and decides one of three verdicts:

* ``vulnerable_effect_observed`` — 1.1.3 attack: the malicious document was fetched
  from the first-party loopback origin, the converted ``OAuth2Auth`` kept the
  attacker's non-loopback plaintext ``tokenUrl`` and the real client credentials
  were POSTed to that attacker endpoint.
* ``patched_effect_blocked`` — 1.1.4 attack: the *same* malicious document was
  fetched from the first-party origin, an upstream security guard rejected the
  insecure token URL (conversion-time or token-sink), and no request at all ever
  reached the attacker endpoint.
* ``benign_task_passed`` — either variant: the first-party loopback token endpoint
  still served the OAuth2 flow and the tool call returned its payload.

Every verdict is refused unless the observation reports a completed, ready run and
the evidence is internally consistent; a missing effect file, a context mismatch,
a spec that was never fetched, an attacker endpoint that is not actually
non-loopback plaintext HTTP, or an ambiguous block (a bare boolean with no upstream
security message) all fail the check instead of passing it.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from lab_support import parser, read_context, verify

TOKEN_PATH = "/token"
SPEC_PATH = "/openapi.json"
CONVERSION_GUARD = "OAuth2 tokenUrl in OpenAPI spec"
SINK_GUARD = "OAuth2 token URL"


def _check_id(scenario: str, variant: str) -> str:
    if scenario == "benign":
        return "benign_task_passed"
    return "vulnerable_effect_observed" if variant == "vulnerable" else "patched_effect_blocked"


def _loopback(host: str) -> bool:
    host = (host or "").strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host in {"localhost", "127.0.0.1", "::1"} or host.startswith("127.")


def _host_of_authority(authority: str) -> str:
    authority = (authority or "").strip()
    if authority.startswith("["):
        end = authority.find("]")
        return authority[1:end] if end != -1 else authority
    return authority.rsplit(":", 1)[0] if ":" in authority else authority


def _host_of_url(url: str) -> str:
    return urlsplit(url or "").hostname or ""


def _requests(effect: dict[str, Any]) -> list[dict[str, Any]]:
    entries = effect.get("listener_requests")
    return [item for item in entries if isinstance(item, dict)] if isinstance(entries, list) else []


def _attacker_requests(effect: dict[str, Any]) -> list[dict[str, Any]]:
    entries = effect.get("attacker_token_requests")
    return [item for item in entries if isinstance(item, dict)] if isinstance(entries, list) else []


def _body(request: dict[str, Any]) -> dict[str, Any]:
    body = request.get("body")
    return body if isinstance(body, dict) else {}


def _carries_credentials(request: dict[str, Any], client_id: Any, secret: Any) -> bool:
    body = _body(request)
    return (
        request.get("method") == "POST"
        and str(request.get("path", "")).split("?", 1)[0] == TOKEN_PATH
        and isinstance(client_id, str)
        and bool(client_id)
        and body.get("client_id") == client_id
        and body.get("client_secret") == secret
    )


def _credentials(effect: dict[str, Any]) -> tuple[Any, Any]:
    expected = effect.get("expected_credentials")
    expected = expected if isinstance(expected, dict) else {}
    return expected.get("client_id"), expected.get("client_secret")


def _spec_gets(effect: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        item for item in _requests(effect)
        if item.get("method") == "GET" and str(item.get("path", "")).split("?", 1)[0] == SPEC_PATH
    ]


def _first_party_spec_fetched(effect: dict[str, Any]) -> bool:
    """The malicious document must have been fetched from a loopback (first-party) host."""
    return any(
        _loopback(_host_of_authority(str(item.get("host") or ""))) for item in _spec_gets(effect)
    )


def _attacker_endpoint(effect: dict[str, Any]) -> tuple[str, str, list[str]]:
    """Return (authority, token_url, problems) for a non-loopback plaintext attack URL."""
    authority = str(effect.get("attacker_authority") or "")
    token_url = str(effect.get("token_url") or "")
    problems: list[str] = []
    if not authority or _loopback(_host_of_authority(authority)):
        problems.append(f"attacker authority {authority!r} is not a non-loopback endpoint")
    elif _host_of_url(token_url) != _host_of_authority(authority):
        problems.append(f"token_url {token_url!r} is not on the attacker authority {authority!r}")
    if urlsplit(token_url).scheme != "http":
        problems.append(f"token_url {token_url!r} is not plaintext HTTP")
    return authority, token_url, problems


def _ready_problems(observation: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    if observation.get("target_ready") is not True:
        problems.append("observation does not report target_ready=True")
    if observation.get("execution_status") != "completed":
        problems.append(
            f"observation execution_status is {observation.get('execution_status')!r}, not 'completed'"
        )
    return problems


def _fail(check_id: str, expected: str, *problems: str) -> tuple[str, bool, str, str]:
    return check_id, False, expected, "; ".join(problem for problem in problems if problem)


def _vulnerable_attack(effect: dict[str, Any], observation: dict[str, Any]) -> tuple[str, bool, str, str]:
    check_id = "vulnerable_effect_observed"
    expected = (
        "1.1.3 fetches the malicious document from the first-party origin, registers the "
        "attacker tokenUrl and POSTs the configured client credentials to that "
        "non-loopback plaintext endpoint"
    )
    client_id, secret = _credentials(effect)
    authority, token_url, endpoint_problems = _attacker_endpoint(effect)
    outcome = effect.get("outcome") if isinstance(effect.get("outcome"), dict) else {}
    tool_call = outcome.get("tool_call") if isinstance(outcome.get("tool_call"), dict) else {}

    leaks = [item for item in _attacker_requests(effect) if _carries_credentials(item, client_id, secret)]
    problems: list[str] = list(_ready_problems(observation)) + endpoint_problems
    if not isinstance(client_id, str) or not client_id or not isinstance(secret, str) or not secret:
        problems.append("effect.json does not record the synthetic client credentials")
    if not leaks:
        problems.append("no attacker token POST carried the configured client credentials")
    if not all(item.get("host") == authority for item in leaks):
        problems.append("the credential-bearing POST did not target the attacker authority")
    if effect.get("credentials_exfiltrated") is not True or observation.get("credentials_exfiltrated") is not True:
        problems.append("credentials_exfiltrated is not True in both effect.json and observation.json")
    if outcome.get("security_error_observed") is not False or observation.get("security_error_observed") is not False:
        problems.append("a security guard fired during the vulnerable attack, so the leak is ambiguous")
    if outcome.get("registration_succeeded") is not True or observation.get("registration_succeeded") is not True:
        problems.append("registration of the malicious manual did not succeed")
    if outcome.get("manual_token_url") != token_url or observation.get("manual_token_url") != token_url:
        problems.append("the converted manual tokenUrl does not match the attacker endpoint")
    if int(observation.get("attacker_token_requests") or 0) != len(_attacker_requests(effect)):
        problems.append("observation and effect disagree on the attacker request count")
    if not _first_party_spec_fetched(effect):
        problems.append("the malicious OpenAPI document was not fetched from the first-party loopback origin")
    if tool_call.get("called") is not True or tool_call.get("result") != effect.get("expected_benign_payload"):
        problems.append("the OAuth2 tool call did not complete with the served tool payload")
    if problems:
        return _fail(check_id, expected, *problems)
    return check_id, True, expected, (
        f"{len(leaks)} POST(s) carrying client_id={client_id!r} reached the non-loopback "
        f"attacker endpoint {authority}; registration succeeded and the tool call returned its payload"
    )


def _patched_attack(effect: dict[str, Any], observation: dict[str, Any]) -> tuple[str, bool, str, str]:
    check_id = "patched_effect_blocked"
    expected = (
        "1.1.4 fetches the same malicious spec from the first-party origin, rejects the "
        "insecure non-loopback plaintext tokenUrl with an upstream security error and never "
        "sends any request to the attacker endpoint"
    )
    client_id, secret = _credentials(effect)
    _authority, _token_url, endpoint_problems = _attacker_endpoint(effect)
    outcome = effect.get("outcome") if isinstance(effect.get("outcome"), dict) else {}
    runtime = outcome.get("runtime_token_check") if isinstance(outcome.get("runtime_token_check"), dict) else {}
    tool_call = outcome.get("tool_call") if isinstance(outcome.get("tool_call"), dict) else {}
    errors = " | ".join(str(item) for item in (outcome.get("registration_errors") or []))
    guard_reported = CONVERSION_GUARD in errors
    runtime_error = str(runtime.get("error") or "")
    runtime_blocked = (
        runtime.get("performed") is True
        and runtime.get("blocked") is True
        and SINK_GUARD in runtime_error
    )

    leaks = [item for item in _attacker_requests(effect) if _carries_credentials(item, client_id, secret)]
    problems: list[str] = list(_ready_problems(observation)) + endpoint_problems
    if not isinstance(client_id, str) or not client_id or not isinstance(secret, str) or not secret:
        problems.append("effect.json does not record the synthetic client credentials")
    if leaks:
        problems.append(f"{len(leaks)} attacker token POST(s) still carried the client credentials")
    if effect.get("credentials_exfiltrated") is not False or observation.get("credentials_exfiltrated") is not False:
        problems.append("credentials_exfiltrated is not False in both effect.json and observation.json")
    if int(observation.get("attacker_token_requests") or 0) != 0 or _attacker_requests(effect):
        problems.append("the attacker endpoint still received token requests")
    if not _first_party_spec_fetched(effect):
        problems.append("the malicious spec was never fetched from the first-party origin, so the block is not evidenced")
    if not (guard_reported or runtime_blocked):
        problems.append("no upstream security guard rejected the insecure tokenUrl")
    if guard_reported and outcome.get("registration_succeeded") is True:
        problems.append("the conversion guard reported an error but registration still succeeded")
    if outcome.get("registration_succeeded") is True and tool_call.get("called") is True:
        problems.append("the attack path still registered and called the OAuth2 tool")
    if problems:
        return _fail(check_id, expected, *problems)
    detail = "conversion-time guard" if guard_reported else "token-sink guard"
    return check_id, True, expected, (
        f"the {detail} rejected the non-loopback plaintext tokenUrl; "
        "0 requests reached the attacker endpoint"
    )


def _benign(effect: dict[str, Any], observation: dict[str, Any]) -> tuple[str, bool, str, str]:
    check_id = "benign_task_passed"
    expected = (
        "the first-party loopback token endpoint completes the OAuth2 flow and the "
        "tool call returns its payload without touching the attacker endpoint"
    )
    client_id, secret = _credentials(effect)
    outcome = effect.get("outcome") if isinstance(effect.get("outcome"), dict) else {}
    tool_call = outcome.get("tool_call") if isinstance(outcome.get("tool_call"), dict) else {}
    manual_token_url = str(outcome.get("manual_token_url") or "")
    declared_token_url = str(effect.get("token_url") or "")
    payload = effect.get("expected_benign_payload")

    loopback_token_posts = [
        item for item in _requests(effect)
        if _carries_credentials(item, client_id, secret) and _loopback(_host_of_authority(str(item.get("host") or "")))
    ]
    tool_gets = [
        item for item in _requests(effect)
        if item.get("method") == "GET" and str(item.get("path", "")).split("?", 1)[0].startswith("/v1/")
    ]
    problems: list[str] = _ready_problems(observation)
    if not isinstance(client_id, str) or not client_id or not isinstance(secret, str) or not secret:
        problems.append("effect.json does not record the synthetic client credentials")
    if not _loopback(_host_of_url(declared_token_url)):
        problems.append(f"benign token_url {declared_token_url!r} is not a loopback endpoint")
    if manual_token_url != declared_token_url or not _loopback(_host_of_url(manual_token_url)):
        problems.append(f"benign manual tokenUrl {manual_token_url!r} does not match the loopback token_url")
    if outcome.get("security_error_observed") is True or observation.get("security_error_observed") is True:
        problems.append("a security guard fired during the benign flow")
    if outcome.get("registration_succeeded") is not True or observation.get("registration_succeeded") is not True:
        problems.append("registration of the benign manual did not succeed")
    if not loopback_token_posts:
        problems.append("no loopback token POST carried the client credentials")
    if not _first_party_spec_fetched(effect):
        problems.append("the benign OpenAPI document was not fetched from the first-party loopback origin")
    if not tool_gets:
        problems.append("the benign tool endpoint was never called")
    if not all(_loopback(_host_of_authority(str(item.get("host") or ""))) for item in tool_gets):
        problems.append("the benign tool call did not target a loopback host")
    if tool_call.get("called") is not True or tool_call.get("result") != payload:
        problems.append("the benign tool call did not return the served tool payload")
    if effect.get("benign_task_completed") is not True or observation.get("benign_task_completed") is not True:
        problems.append("benign_task_completed is not True in both effect.json and observation.json")
    if effect.get("credentials_exfiltrated") is not False or observation.get("credentials_exfiltrated") is not False:
        problems.append("the benign run reports credential exfiltration")
    if int(observation.get("attacker_token_requests") or 0) != 0 or _attacker_requests(effect):
        problems.append("the benign run contacted the attacker endpoint")
    if observation.get("manual_token_url") != outcome.get("manual_token_url"):
        problems.append("observation and effect disagree on the manual tokenUrl")
    if problems:
        return _fail(check_id, expected, *problems)
    return check_id, True, expected, (
        f"loopback token endpoint served {len(loopback_token_posts)} credential POST(s) and the tool call "
        f"returned {json.dumps(payload, sort_keys=True)}"
    )


def check(context: dict[str, Any], observation: dict[str, Any],
          paths: dict[str, Any]) -> tuple[str, bool, str, str]:
    """Judge one case from hash-checked evidence only."""
    scenario = context["scenario"]
    variant = context["variant"]
    check_id = _check_id(scenario, variant)
    if "effect.json" not in paths:
        return _fail(check_id, "the declared effect.json evidence is present", "effect.json is missing from evidence")
    if observation.get("scenario") != scenario:
        return _fail(
            check_id,
            "observation.json was produced for this scenario",
            f"observation records scenario={observation.get('scenario')!r}",
        )
    try:
        effect = json.loads(paths["effect.json"].read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return _fail(check_id, "the declared effect.json is readable JSON", f"unreadable effect.json: {error}")
    if not isinstance(effect, dict):
        return _fail(check_id, "effect.json is a JSON object", f"effect.json is {type(effect).__name__}")
    if effect.get("scenario") != scenario or effect.get("variant") != variant:
        return _fail(
            check_id,
            "effect.json was produced for this variant and scenario",
            f"effect.json records variant={effect.get('variant')!r} scenario={effect.get('scenario')!r}",
        )
    if scenario == "benign":
        return _benign(effect, observation)
    if variant == "vulnerable":
        return _vulnerable_attack(effect, observation)
    return _patched_attack(effect, observation)


def main() -> int:
    args = parser(__doc__).parse_args()
    read_context(args.context)
    return verify(args.context, args.output, check)


if __name__ == "__main__":
    raise SystemExit(main())
