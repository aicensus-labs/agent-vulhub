"""Independent evidence check for the n8n agent node-tool privilege escalation.

Reads only ``facts.json``, ``observation.json`` and the hash-checked effect files
left by ``reproduce.py``; it never reloads the product code and never reruns the
attack. The decisive evidence is the *raw* harness record
(``harness-observation.json``), i.e. what ``AgentRuntimeReconstructionService``
and ``EphemeralNodeExecutor`` actually did, not the PoC's own reduction of it:
every check re-derives the executor calls, resolved tools and tool invocations
from that raw record and only then confirms ``effect.json`` agrees, so a summary
that disagrees with the product effect fails the case.

The vulnerable build must show the Project Viewer's node tool reaching
``EphemeralNodeExecutor`` with the project credential and the canary result; the
patched build must show the filter running, dropping that node tool while keeping
the custom one, and never calling the executor; the benign build must show a
permitted node tool surviving (the patched filter included) and still running.
"""

import json
from pathlib import Path

from lab_support import parser, read_context, verify

ATTACK_NODE = "n8n-nodes-base.executeCommandTool"
BENIGN_NODE = "n8n-nodes-base.httpRequestTool"
ATTACK_TOOL = "Run Shell"
ATTACK_TOOL_SLUG = "run_shell"
CUSTOM_TOOL = "Echo Note"
BENIGN_TOOL = "Fetch Status"
BENIGN_TOOL_SLUG = "fetch_status"
ATTACK_CREDENTIAL = "cred-exec"
BENIGN_CREDENTIAL = "cred-api"
ATTACK_MARKER = "AVH-N8N-W46P-EXEC"
BENIGN_MARKER = "AVH-N8N-W46P-BENIGN"


def load_json(paths, name):
    path = paths.get(name)
    if path is None:
        raise KeyError(f"missing evidence file {name}")
    return json.loads(Path(path).read_text(encoding="utf-8"))


def raw_facts(paths):
    """Re-derive the observable effect from the raw harness record."""
    raw = load_json(paths, "harness-observation.json")
    if not isinstance(raw, dict):
        raise ValueError("harness-observation.json is not an object")
    calls = raw.get("executor_calls") or []
    resolved = raw.get("resolved_tools") or []
    invocations = raw.get("node_tool_invocations") or []
    if not isinstance(calls, list) or not isinstance(resolved, list) or not isinstance(invocations, list):
        raise ValueError("harness-observation.json has malformed collections")
    return {
        "mechanism_loaded": raw.get("mechanism_loaded"),
        "filter_present": raw.get("filter_tools_for_user_present"),
        "filter_kept": raw.get("filter_tools_for_user_kept"),
        "resolved_names": [tool.get("name") for tool in resolved],
        "resolved_kinds": [tool.get("kind") for tool in resolved],
        "executor_node_types": [call.get("nodeType") for call in calls],
        "executor_credential_ids": sorted(
            detail["id"]
            for call in calls
            for detail in (call.get("credentialDetails") or {}).values()
            if isinstance(detail, dict) and detail.get("id")
        ),
        "invoked_tools": [entry.get("tool") for entry in invocations],
        "invocation_results": [entry.get("result") for entry in invocations],
    }


def result_markers(results):
    """Collect every canary marker the pipeline reported back to the caller."""
    markers = []
    for result in results:
        if not isinstance(result, dict):
            continue
        for item in result.get("data") or []:
            payload = item.get("json") if isinstance(item, dict) else None
            if isinstance(payload, dict) and payload.get("marker") is not None:
                markers.append(payload["marker"])
    return markers


def result_statuses(results):
    return [result.get("status") for result in results if isinstance(result, dict)]


def cross_check(raw, summary):
    """Fail loudly when the PoC's summary contradicts the raw product effect."""
    agreed = (
        summary.get("mechanism_loaded") is raw["mechanism_loaded"]
        and summary.get("resolved_tool_names") == raw["resolved_names"]
        and summary.get("executor_node_types") == raw["executor_node_types"]
        and summary.get("executor_credential_ids") == raw["executor_credential_ids"]
        and summary.get("node_tool_invoked") is bool(raw["invoked_tools"])
    )
    return {
        "summary_matches_raw": agreed,
        "summary_executor_node_types": summary.get("executor_node_types"),
        "raw_executor_node_types": raw["executor_node_types"],
        "summary_resolved_tool_names": summary.get("resolved_tool_names"),
        "raw_resolved_tool_names": raw["resolved_names"],
        "summary_credential_ids": summary.get("executor_credential_ids"),
        "raw_credential_ids": raw["executor_credential_ids"],
    }


def vulnerable_attack(context, observation, paths):
    raw = raw_facts(paths)
    summary = load_json(paths, "effect.json")
    agreement = cross_check(raw, summary)
    markers = result_markers(raw["invocation_results"])
    passed = (
        raw["mechanism_loaded"] is True
        and raw["filter_present"] is False
        and raw["resolved_names"] == [ATTACK_TOOL_SLUG]
        and raw["resolved_kinds"] == ["node"]
        and raw["executor_node_types"] == [ATTACK_NODE]
        and raw["executor_credential_ids"] == [ATTACK_CREDENTIAL]
        and raw["invoked_tools"] == [ATTACK_TOOL_SLUG]
        and "success" in result_statuses(raw["invocation_results"])
        and ATTACK_MARKER in markers
        and agreement["summary_matches_raw"] is True
    )
    return (
        "vulnerable_effect_observed",
        passed,
        f"the project viewer's {ATTACK_TOOL} node tool reaches the executor as "
        f"{ATTACK_NODE} with {ATTACK_CREDENTIAL} and returns the {ATTACK_MARKER} canary",
        {
            "executor_node_types": raw["executor_node_types"],
            "executor_credential_ids": raw["executor_credential_ids"],
            "resolved_tool_names": raw["resolved_names"],
            "filter_tools_for_user_present": raw["filter_present"],
            "tool_invocations": raw["invoked_tools"],
            "result_statuses": result_statuses(raw["invocation_results"]),
            "result_markers": markers,
            **agreement,
        },
    )


def patched_attack(context, observation, paths):
    raw = raw_facts(paths)
    summary = load_json(paths, "effect.json")
    agreement = cross_check(raw, summary)
    kept = raw["filter_kept"]
    passed = (
        raw["mechanism_loaded"] is True
        and raw["filter_present"] is True
        and isinstance(kept, list)
        and CUSTOM_TOOL in kept            # the filter ran and kept the custom tool
        and ATTACK_TOOL not in kept        # ...while dropping the privileged node tool
        and raw["resolved_names"] == []
        and raw["executor_node_types"] == []
        and raw["executor_credential_ids"] == []
        and raw["invoked_tools"] == []
        and agreement["summary_matches_raw"] is True
    )
    return (
        "patched_effect_blocked",
        passed,
        f"the patched runtime's filterToolsForUser drops {ATTACK_TOOL} (keeping the custom tool) "
        "and the executor is never called",
        {
            "executor_node_types": raw["executor_node_types"],
            "resolved_tool_names": raw["resolved_names"],
            "filter_tools_for_user_present": raw["filter_present"],
            "filter_tools_for_user_kept": kept,
            "tool_invocations": raw["invoked_tools"],
            **agreement,
        },
    )


def benign_task(context, observation, paths):
    raw = raw_facts(paths)
    summary = load_json(paths, "effect.json")
    agreement = cross_check(raw, summary)
    markers = result_markers(raw["invocation_results"])
    # The patched build runs the same permitted tool only if the filter kept it.
    filter_ok = raw["filter_present"] is False or (
        isinstance(raw["filter_kept"], list) and BENIGN_TOOL in raw["filter_kept"]
    )
    passed = (
        raw["mechanism_loaded"] is True
        and raw["resolved_names"] == [BENIGN_TOOL_SLUG]
        and raw["resolved_kinds"] == ["node"]
        and raw["executor_node_types"] == [BENIGN_NODE]
        and raw["executor_credential_ids"] == [BENIGN_CREDENTIAL]
        and raw["invoked_tools"] == [BENIGN_TOOL_SLUG]
        and "success" in result_statuses(raw["invocation_results"])
        and BENIGN_MARKER in markers
        and filter_ok
        and agreement["summary_matches_raw"] is True
    )
    return (
        "benign_task_passed",
        passed,
        f"a user holding workflow:execute and credential:read still runs {BENIGN_TOOL} "
        f"as {BENIGN_NODE} with {BENIGN_CREDENTIAL} and gets the {BENIGN_MARKER} canary",
        {
            "executor_node_types": raw["executor_node_types"],
            "executor_credential_ids": raw["executor_credential_ids"],
            "resolved_tool_names": raw["resolved_names"],
            "filter_tools_for_user_present": raw["filter_present"],
            "filter_tools_for_user_kept": raw["filter_kept"],
            "tool_invocations": raw["invoked_tools"],
            "result_markers": markers,
            **agreement,
        },
    )


def required_check(scenario, variant):
    if scenario == "benign":
        return "benign_task_passed"
    return "vulnerable_effect_observed" if variant == "vulnerable" else "patched_effect_blocked"


def check(context, observation, paths):
    scenario = context["scenario"]
    variant = context["variant"]
    try:
        if scenario == "benign":
            return benign_task(context, observation, paths)
        if variant == "vulnerable":
            return vulnerable_attack(context, observation, paths)
        return patched_attack(context, observation, paths)
    except (OSError, ValueError, KeyError, TypeError) as error:
        return required_check(scenario, variant), False, "a readable, self-consistent raw effect record", f"unreadable evidence: {error}"


def main() -> int:
    args = parser(__doc__).parse_args()
    context = read_context(args.context)
    return verify(args.context, args.output, check)


if __name__ == "__main__":
    raise SystemExit(main())
