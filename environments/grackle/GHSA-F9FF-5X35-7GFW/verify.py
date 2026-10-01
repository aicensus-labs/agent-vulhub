"""Independent verifier for grackle/GHSA-F9FF-5X35-7GFW.

The advisory describes fail-open authorization in the Grackle MCP tool layer
(CWE-639 / CWE-862): a scoped agent can drive task and session mutations on
targets outside its own task subtree because the central scope gate is absent,
so the tool handler runs unchecked and the backend receives the mutation.

This file never imports the pinned package and never re-runs the attack. It
reads only hash-checked evidence collected by ``reproduce.py``:

* ``context`` carries the (variant, scenario) pair under judgement;
* ``observation.json`` records ``target_ready`` and the upstream revision facts;
* ``scenario-input.json`` is the driver input actually used, so the verifier can
  recompute, from the synthetic task/session tree, which probes are
  unauthorized (the caller is not an ancestor of the target, or the target is in
  another workspace);
* ``tool-calls.json`` records what each tool handler and the backend actually
  did, including every RPC the backend received.

The verdict compares the recorded backend mutations against the probe's own
intent, so a build that merely reports success without reaching the backend
cannot pass, and an over-broad fix that also blocks the caller's own descendants
fails the benign check.

Three pieces of evidence are required per mutation, not one:

* the mutating RPC was received on the probe's own target (``_mutation_seen``);
* the backend snapshot taken after the call shows the target actually
  transitioned (``_state_effect_seen``), so a recorded call with no effect on the
  product's state cannot be counted;
* the run is bound to the pinned revision: the package version is the one built
  for this variant and the central scope gate is present exactly on the patched
  one (``_upstream_problems``).

Conversely, a blocked mutation must show all three absent: PERMISSION_DENIED,
no handler invocation, no mutating RPC and an unchanged backend snapshot.
"""

from __future__ import annotations

import json

from lab_support import parser, verify

# tool -> (mutating backend RPC, argument naming the target, request fields that
# must carry the probe's intent)
MUTATIONS = {
    "task_delete": ("orchestration.deleteTask", "taskId", ()),
    "task_update": ("orchestration.updateTask", "taskId", ("title",)),
    "task_resume": ("orchestration.resumeTask", "taskId", ()),
    "session_kill": ("core.killAgent", "sessionId", ()),
}

DENIED = 7  # gRPC PERMISSION_DENIED

# The release each variant is pinned to. The central scope gate only ships in the
# patched release, so a run that reports the wrong version (e.g. a mismatched or
# stale image) cannot satisfy either attack check.
EXPECTED_VERSION = {"vulnerable": "0.132.1", "patched": "0.133.0"}


def _tasks(environment):
    return {task.get("id"): task for task in environment.get("tasks", []) if isinstance(task, dict)}


def _sessions(environment):
    return {session.get("id"): session for session in environment.get("sessions", []) if isinstance(session, dict)}


def _target_task(environment, probe):
    """Resolve a probe to the id of the task whose subtree it touches."""
    args = probe.get("args") or {}
    value = args.get(MUTATIONS[probe["tool"]][1])
    sessions = _sessions(environment)
    if value in sessions:
        return sessions[value].get("taskId")
    return value


def _within_subtree(tasks, ancestor, node):
    seen = set()
    current = node
    while current and current not in seen:
        if current == ancestor:
            return True
        seen.add(current)
        current = (tasks.get(current) or {}).get("parentTaskId") or ""
    return False


def _authorized(environment, probe):
    """An api-key caller keeps full access; a scoped caller may only reach its own subtree."""
    if probe.get("actor") != "scoped":
        return True, "non-scoped caller keeps full tool access"
    claims = environment.get("scoped_token_claims") or {}
    caller = claims.get("sub")
    workspace = claims.get("pid")
    target = _target_task(environment, probe)
    task = _tasks(environment).get(target) or {}
    if workspace and task.get("workspaceId") != workspace:
        return False, "target %s lies in workspace %s, not %s" % (target, task.get("workspaceId"), workspace)
    if _within_subtree(_tasks(environment), caller, target):
        return True, "caller %s is an ancestor of %s" % (caller, target)
    return False, "caller %s is not an ancestor of %s" % (caller, target)


def _mutation_seen(entry, probe):
    """True when the backend received this probe's mutating RPC on its own target."""
    method, arg_name, extra = MUTATIONS[probe["tool"]]
    args = probe.get("args") or {}
    target = args.get(arg_name)
    for effect in entry.get("backend_effects") or []:
        if not isinstance(effect, dict) or effect.get("method") != method:
            continue
        request = effect.get("request")
        if not isinstance(request, dict) or request.get("id") != target:
            continue
        if all(request.get(field) == args.get(field) for field in extra):
            return True
    return False


def _state_effect_seen(entry, probe, environment):
    """True when the post-call backend snapshot shows the probe's mutation applied.

    ``_mutation_seen`` proves the RPC was received; this proves the product then
    transitioned the target away from its original value, so a call that is
    merely logged (or a no-op rewrite) does not count as an observed effect.
    """
    tool = probe["tool"]
    args = probe.get("args") or {}
    state = entry.get("backend_state") or {}
    if tool == "task_delete":
        target = args.get("taskId")
        return target in _tasks(environment) and target not in (state.get("tasks") or {})
    if tool == "task_update":
        target = args.get("taskId")
        original = _tasks(environment).get(target) or {}
        task = (state.get("tasks") or {}).get(target)
        if not isinstance(task, dict) or not original:
            return False
        changed = False
        for field in ("title", "description", "sessionId", "status"):
            value = args.get(field)
            if not value:
                continue
            if task.get(field) != value:
                return False
            if original.get(field) != value:
                changed = True
        return changed
    if tool == "session_kill":
        target = args.get("sessionId")
        original = _sessions(environment).get(target) or {}
        session = (state.get("sessions") or {}).get(target)
        return (isinstance(session, dict) and session.get("status") == "killed"
                and original.get("status") != "killed")
    # task_resume: the harness records the RPC only; the backend double models no
    # state transition for it, so the RPC itself is the observable effect.
    return tool == "task_resume"


def _upstream_problems(context, observation):
    """Bind the run to the pinned revision the image was built from."""
    upstream = observation.get("upstream") or {}
    variant = context["variant"]
    expected = EXPECTED_VERSION.get(variant)
    actual = upstream.get("package_version")
    problems = []
    if actual != expected:
        problems.append("package_version=%r (expected %r for %s)" % (actual, expected, variant))
    gate_expected = variant == "patched"
    gate_actual = upstream.get("central_scope_gate_present")
    if gate_actual is not gate_expected:
        problems.append("central_scope_gate_present=%r (expected %r for %s)"
                        % (gate_actual, gate_expected, variant))
    return problems


def check(context, observation, paths):
    if context["scenario"] == "benign":
        check_id = "benign_task_passed"
    elif context["variant"] == "vulnerable":
        check_id = "vulnerable_effect_observed"
    else:
        check_id = "patched_effect_blocked"

    try:
        driver_input = json.loads(paths["scenario-input.json"].read_text(encoding="utf-8"))
        recorded = json.loads(paths["tool-calls.json"].read_text(encoding="utf-8"))
    except (KeyError, OSError, ValueError) as error:
        return check_id, False, "recorded inputs and tool calls are readable", "unreadable evidence: %s" % error

    environment = driver_input.get("environment") or {}
    probes = driver_input.get("probes") or []
    entries = {entry.get("id"): entry for entry in recorded if isinstance(entry, dict)}
    observed_ids = sorted(str(item.get("id")) for item in (observation.get("probes") or []) if isinstance(item, dict))
    if sorted(str(key) for key in entries) != observed_ids or len(observed_ids) != len(observation.get("probes") or []):
        return check_id, False, "one recorded tool call per observed probe", \
            "observation ids %s vs tool-calls.json ids %s" % (observed_ids, sorted(str(k) for k in entries))

    unsupported = [probe.get("tool") for probe in probes if probe.get("tool") not in MUTATIONS]
    if unsupported or not probes:
        return check_id, False, "every probe uses a modelled mutating tool", \
            "unsupported or empty probe set: %s" % unsupported

    unauthorized = [probe for probe in probes if not _authorized(environment, probe)[0]]

    # ------------------------------------------------------------------ benign
    if context["scenario"] == "benign":
        failures = list(_upstream_problems(context, observation))
        for probe in probes:
            entry = entries.get(probe["id"]) or {}
            if not (entry.get("handler_invoked") is True
                    and entry.get("handler_is_error") is False
                    and entry.get("handler_error") is None
                    and _mutation_seen(entry, probe)
                    and _state_effect_seen(entry, probe, environment)):
                failures.append(
                    "%s tool=%s mutation=%r state_changed=%r" % (
                        probe["id"], probe["tool"], _mutation_seen(entry, probe),
                        _state_effect_seen(entry, probe, environment)))
        passed = not failures
        return check_id, passed, \
            "every legitimate probe reaches the backend and mutates its own target", \
            "failed probes: %s" % (failures or "none")

    if not unauthorized:
        return check_id, False, "the attack set contains non-descendant targets", \
            "no unauthorized probe in %s" % [probe.get("id") for probe in probes]

    # --------------------------------------------------- vulnerable revision
    if context["variant"] == "vulnerable":
        problems = list(_upstream_problems(context, observation))
        for probe in unauthorized:
            entry = entries.get(probe["id"]) or {}
            if not (entry.get("gate_denied") is False
                    and entry.get("handler_invoked") is True
                    and entry.get("handler_is_error") is False
                    and entry.get("handler_error") is None
                    and _mutation_seen(entry, probe)
                    and _state_effect_seen(entry, probe, environment)):
                problems.append(
                    "%s gate_denied=%r handler_invoked=%r handler_error=%r mutation=%r state_changed=%r" % (
                        probe["id"], entry.get("gate_denied"), entry.get("handler_invoked"),
                        entry.get("handler_error") or entry.get("handler_is_error"),
                        _mutation_seen(entry, probe),
                        _state_effect_seen(entry, probe, environment)))
        return check_id, not problems, \
            "each non-descendant mutation runs unchecked and reaches the backend", \
            "; ".join(problems) or "%d unauthorized probes mutated their targets" % len(unauthorized)

    # ------------------------------------------------------ patched revision
    problems = list(_upstream_problems(context, observation))
    for probe in unauthorized:
        entry = entries.get(probe["id"]) or {}
        error = entry.get("gate_error") or {}
        if not (entry.get("gate_denied") is True
                and entry.get("handler_invoked") is False
                and error.get("code") == DENIED
                and not _mutation_seen(entry, probe)
                and not _state_effect_seen(entry, probe, environment)):
            problems.append(
                "%s gate_denied=%r code=%r handler_invoked=%r mutation=%r state_changed=%r" % (
                    probe["id"], entry.get("gate_denied"), error.get("code"),
                    entry.get("handler_invoked"), _mutation_seen(entry, probe),
                    _state_effect_seen(entry, probe, environment)))
    return check_id, not problems, \
        "each non-descendant mutation is denied with PERMISSION_DENIED and never reaches the backend", \
        "; ".join(problems) or "%d unauthorized probes were blocked before the handler" % len(unauthorized)


def main() -> int:
    args = parser(__doc__).parse_args()
    return verify(args.context, args.output, check)


if __name__ == "__main__":
    raise SystemExit(main())
