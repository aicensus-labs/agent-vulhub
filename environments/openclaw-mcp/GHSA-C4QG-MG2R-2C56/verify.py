"""Independent evidence checks for GHSA-C4QG-MG2R-2C56 (cross-client async task leakage).

The verifier never starts the server, never speaks MCP and never imports the
pinned package. It re-derives every verdict from the hash-checked
``observation.json`` and ``effect.json`` that ``reproduce.py`` recorded, plus the
pinned fixtures. The PoC's own ``derived`` booleans are deliberately ignored:
they are re-computed here from the raw tool responses captured over the wire.

check ids:
  vulnerable_effect_observed  vulnerable + attack  (the intruder reads the victim task)
  patched_effect_blocked      patched + attack     (the intruder is denied)
  benign_task_passed          either variant + benign (everyone reads its own task)

Blocking is judged strictly: a patched run only counts as blocked when the
intruder's task list is empty/denied **and** its status call for the victim task
is actively refused with a tool error. A successful foreign lookup that merely
happens to omit the result would still disclose the victim task's existence, so
it must not satisfy ``patched_effect_blocked``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lab_support import parser, verify

EFFECT_NAME = "effect.json"

# Fallbacks, used only when the pinned fixture cannot be read. They mirror
# fixtures/attack.json and fixtures/benign.json verbatim.
FALLBACK: dict[str, dict[str, Any]] = {
    "attack": {
        "reply_prefix": "OPENCLAW-LAB-ATTACK-REPLY:",
        "clients": [
            {"label": "probe-client-a", "role": "victim", "session_id": "session-victim",
             "message": "OPENCLAW-LAB-ATTACK-PROMPT-2f6c1a90"},
            {"label": "probe-client-b", "role": "intruder", "session_id": "session-intruder",
             "message": ""},
        ],
    },
    "benign": {
        "reply_prefix": "OPENCLAW-LAB-BENIGN-REPLY:",
        "clients": [
            {"label": "probe-client-a", "role": "owner", "session_id": "session-benign-a",
             "message": "OPENCLAW-LAB-BENIGN-A-4b1d"},
            {"label": "probe-client-b", "role": "owner", "session_id": "session-benign-b",
             "message": "OPENCLAW-LAB-BENIGN-B-9e70"},
        ],
    },
}


def _fixture(scenario: str) -> dict[str, Any]:
    """Read the pinned fixture, degrading to the inlined copy if it is absent."""
    path = Path(__file__).resolve().parent / "fixtures" / f"{scenario}.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return FALLBACK[scenario]
    if not isinstance(document, dict) or document.get("scenario") != scenario:
        return FALLBACK[scenario]
    clients = document.get("clients")
    gateway = document.get("gateway")
    if not isinstance(clients, list) or not clients or not isinstance(gateway, dict):
        return FALLBACK[scenario]
    if not all(isinstance(client, dict) for client in clients):
        return FALLBACK[scenario]
    return {
        "reply_prefix": str(gateway.get("reply_prefix", "")),
        "clients": clients,
    }


def _probe(step: Any) -> tuple[dict[str, Any] | None, bool, str]:
    """Return (parsed_json_body, is_error, raw_text) for one recorded tool call."""
    if not isinstance(step, dict):
        return None, False, ""
    text = step.get("text")
    is_error = step.get("isError") is True
    if not isinstance(text, str):
        return None, is_error, ""
    try:
        body = json.loads(text)
    except ValueError:
        body = None
    return (body if isinstance(body, dict) else None), is_error, text


def _status_object(step: Any) -> tuple[dict[str, Any] | None, bool, str]:
    """Return (parsed_status, is_error, raw_text) for a recorded task status.

    The attack probes are stored as ``{isError, text}`` envelopes, while the benign
    run stores the already-parsed status object (``reproduce.py`` only keeps it when
    the status call succeeded). Accept both shapes.
    """
    if isinstance(step, dict) and "isError" not in step and any(
            key in step for key in ("status", "task_id", "result")):
        return step, False, json.dumps(step, ensure_ascii=False)
    return _probe(step)


def _read_effect(paths: dict[str, Path]) -> dict[str, Any] | None:
    path = paths.get(EFFECT_NAME)
    if path is None or not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return document if isinstance(document, dict) else None


def _gateway_requests(effect: dict[str, Any]) -> list[dict[str, Any]]:
    requests = effect.get("gateway_requests")
    if not isinstance(requests, list):
        return []
    return [item for item in requests if isinstance(item, dict)]


def _attack_check(context: dict[str, Any], observation: dict[str, Any],
                  paths: dict[str, Path]) -> tuple[str, bool, str, Any]:
    check_id = ("vulnerable_effect_observed" if context["variant"] == "vulnerable"
                else "patched_effect_blocked")
    if context["variant"] == "vulnerable":
        expected = (
            "The intruder connection reads the victim task id from the task list and the "
            "victim model result from the task status, without ever contacting the model."
        )
    else:
        expected = (
            "The intruder connection is refused: its task list is empty or denied and its "
            "status call for the victim task returns an error, so neither the victim task "
            "id nor its model result is disclosed."
        )
    effect = _read_effect(paths)
    if effect is None:
        return check_id, False, expected, {"error": f"{EFFECT_NAME} missing or unparsable"}

    fixture = _fixture("attack")
    prefix = fixture["reply_prefix"]
    specs = {str(client.get("label")): client for client in fixture["clients"]}
    victim = next((c for c in fixture["clients"] if c.get("role") == "victim"), None)
    intruder = next((c for c in fixture["clients"] if c.get("role") == "intruder"), None)

    problems: list[str] = []
    if effect.get("scenario") != "attack":
        problems.append("effect scenario is not attack")
    if effect.get("server_started") is not True or observation.get("server_started") is not True:
        problems.append("the pinned upstream server did not start")
    if victim is None or intruder is None:
        problems.append("fixture lacks a victim/intruder role")
        return check_id, False, expected, {"problems": problems}
    victim_label, intruder_label = str(victim.get("label")), str(intruder.get("label"))
    if effect.get("victim") != victim_label or effect.get("intruder") != intruder_label:
        problems.append("effect did not probe the fixture's victim/intruder connections")

    victim_message = str(victim.get("message", ""))
    victim_session = str(victim.get("session_id", ""))
    intruder_session = str(intruder.get("session_id", ""))
    expected_reply = f"{prefix}{victim_message}"

    owner_task_id = effect.get("owner_task_id")
    owner_result = effect.get("owner_observed_result")
    owner_ok = (
        isinstance(owner_task_id, str) and bool(owner_task_id)
        and isinstance(owner_result, str) and owner_result == expected_reply
        and effect.get("owner_task_completed") is True
    )
    if not owner_ok:
        problems.append("the victim connection did not complete its own task with the model reply")

    list_body, list_error, list_text = _probe(effect.get("intruder_task_list"))
    status_body, status_error, status_text = _probe(effect.get("intruder_task_status"))
    if not isinstance(effect.get("intruder_task_list"), dict) or not isinstance(
            effect.get("intruder_task_status"), dict):
        problems.append("the intruder probes were never recorded")

    # The leak is re-derived from the raw responses, not from PoC-reported booleans.
    sees_owner = (
        not list_error and isinstance(owner_task_id, str) and bool(owner_task_id)
        and owner_task_id in list_text
    )
    reads_owner = (
        not status_error and isinstance(owner_result, str) and bool(owner_result)
        and owner_result in status_text
    )

    # The model gateway proves the intruder never produced this data itself.
    requests = _gateway_requests(effect)
    sessions = [str(item.get("session")) for item in requests]
    gateway_ok = (
        bool(requests)
        and victim_session in sessions
        and intruder_session not in sessions
        and all(str(item.get("message", "")) == victim_message
                for item in requests if str(item.get("session")) == victim_session)
    )
    if not gateway_ok:
        problems.append("the model gateway did not see exactly the victim's own request")

    list_total = None
    if isinstance(list_body, dict):
        stats = list_body.get("stats")
        if isinstance(stats, dict) and isinstance(stats.get("total"), int):
            list_total = stats["total"]
    tasks = list_body.get("tasks") if isinstance(list_body, dict) else None
    list_empty = (list_total == 0) or (isinstance(tasks, list) and not tasks)
    list_denied = list_error or list_empty
    # The pinned patched revision answers a foreign task with the MCP tool error
    # "Task not found: <id>". Requiring that error (rather than merely the absence
    # of the result) rejects a foreign lookup that succeeds while returning only
    # metadata, which would still leak the victim task's existence.
    status_refused = bool(status_error) and not reads_owner

    actual = {
        "owner_completed_with_model_reply": owner_ok,
        "intruder_list_discloses_owner_task": sees_owner,
        "intruder_status_discloses_owner_result": reads_owner,
        "intruder_list_denied_or_empty": list_denied,
        "intruder_status_refused": status_refused,
        "gateway_saw_only_victim_session": gateway_ok,
    }
    if problems:
        actual["problems"] = problems

    if context["variant"] == "vulnerable":
        passed = owner_ok and sees_owner and reads_owner and gateway_ok and not problems
    else:
        passed = (owner_ok and gateway_ok and not sees_owner and not reads_owner
                  and list_denied and status_refused and not problems)
    return check_id, passed, expected, actual


def _benign_check(context: dict[str, Any], observation: dict[str, Any],
                  paths: dict[str, Path]) -> tuple[str, bool, str, Any]:
    check_id = "benign_task_passed"
    expected = "Every connection queues and reads back only its own task with its own model reply."
    effect = _read_effect(paths)
    if effect is None:
        return check_id, False, expected, {"error": f"{EFFECT_NAME} missing or unparsable"}

    fixture = _fixture("benign")
    prefix = fixture["reply_prefix"]
    records = effect.get("clients")
    if not isinstance(records, list) or not records:
        return check_id, False, expected, {"error": "effect records no clients"}
    by_label = {str(item.get("label")): item for item in records if isinstance(item, dict)}

    problems: list[str] = []
    if effect.get("scenario") != "benign":
        problems.append("effect scenario is not benign")
    if effect.get("server_started") is not True or observation.get("server_started") is not True:
        problems.append("the pinned upstream server did not start")

    task_ids: list[str] = []
    own_replies: list[bool] = []
    for spec in fixture["clients"]:
        label = str(spec.get("label"))
        message = str(spec.get("message", ""))
        record = by_label.get(label)
        if not isinstance(record, dict):
            problems.append(f"client {label} recorded nothing")
            own_replies.append(False)
            continue
        task_id = record.get("task_id")
        _, chat_error, chat_text = _probe(record.get("chat_async"))
        status_body, status_error, status_text = _status_object(record.get("task_status"))
        own = False
        if not isinstance(task_id, str) or not task_id:
            problems.append(f"client {label} got no task id")
        else:
            task_ids.append(task_id)
        if status_error or not isinstance(status_body, dict):
            problems.append(f"client {label} could not read its task status")
        else:
            if status_body.get("task_id") != task_id:
                problems.append(f"client {label} read a task that is not its own")
            if status_body.get("status") != "completed":
                problems.append(f"client {label} task did not complete")
            if status_body.get("result") != f"{prefix}{message}":
                problems.append(f"client {label} did not receive its own model reply")
            else:
                own = True
        if chat_error or task_id not in chat_text:
            problems.append(f"client {label} did not queue its task over its own connection")
        own_replies.append(own)

    distinct_task_ids = len(task_ids) == len(fixture["clients"]) and len(set(task_ids)) == len(task_ids)
    if not distinct_task_ids:
        problems.append("clients did not each get a distinct task id")

    requests = _gateway_requests(effect)
    seen = {(str(item.get("session")), str(item.get("message", ""))) for item in requests}
    gateway_ok = all(
        (str(spec.get("session_id")), str(spec.get("message", ""))) in seen
        for spec in fixture["clients"]
    ) and len(requests) == len(fixture["clients"])
    if not gateway_ok:
        problems.append("the model gateway did not see exactly one request per connection")

    actual = {
        "clients": len(fixture["clients"]),
        "own_reply_per_client": own_replies,
        "distinct_task_ids": distinct_task_ids,
        "gateway_saw_one_request_per_connection": gateway_ok,
    }
    if problems:
        actual["problems"] = problems
    passed = all(own_replies) and distinct_task_ids and gateway_ok and not problems
    return check_id, passed, expected, actual


def check(context: dict[str, Any], observation: dict[str, Any],
          paths: dict[str, Path]) -> tuple[str, bool, str, Any]:
    if context["scenario"] == "benign":
        return _benign_check(context, observation, paths)
    return _attack_check(context, observation, paths)


def main() -> int:
    args = parser(__doc__).parse_args()
    return verify(args.context, args.output, check)


if __name__ == "__main__":
    raise SystemExit(main())
