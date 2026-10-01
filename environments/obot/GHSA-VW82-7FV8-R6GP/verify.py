"""Independent evidence verifier for GHSA-VW82-7FV8-R6GP.

This entrypoint never invokes the vulnerable code path: it reads only the
hash-checked `facts.json`, `observation.json` and the `authorize-report.json`
effect written by the pinned Go harness in reproduce.py, and re-derives the
verdict from those bytes.

The mechanism under test is Obot's `pkg/api/authz` authorizer for
`/mcp-connect/{mcp_id}`. The attack fixture registers one catalog MCP server and
an access-control rule that grants it to `authorized-uid` only, then asks the
unprivileged `attacker-uid` to connect to the same server. The scenarios are
therefore judged as:

  * vulnerable + attack -> the non-subject user is *allowed* (the bypass),
    while the granted user is still allowed;
  * patched + attack    -> the non-subject user is *denied*, while the granted
    user is still allowed (the fix does not break legitimate access);
  * benign (either)     -> every owner/grantee case is allowed as expected.

There are three independent copies of the same run:

  1. the raw `authorize-report.json` written by the Go harness;
  2. `observation.json`, reproduce.py's parse of that same report;
  3. the Go test transcript, whose per-subtest `PASS` verdict reproduce.py keeps
     in `observation.cases[*].subtest`.

A verdict requires all three to agree case-by-case on the request identity
(path/method/uid/expected_allowed) and on the observed decision, and it
recomputes `all_match` from the cases rather than trusting the declared flag, so
a stale, edited or partially forged observation cannot pass on its own.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

from lab_support import parser, read_context, verify

VULNERABLE_EFFECT = "vulnerable_effect_observed"
PATCHED_EFFECT = "patched_effect_blocked"
BENIGN_TASK = "benign_task_passed"

REPORT = "authorize-report.json"

IDENTITY_FIELDS = ("path", "method", "uid", "expected_allowed")


def _cases_by_id(document: object) -> dict[str, dict]:
    if not isinstance(document, dict):
        return {}
    result: dict[str, dict] = {}
    for case in document.get("cases") or []:
        if isinstance(case, dict) and isinstance(case.get("id"), str):
            result[case["id"]] = case
    return result


def _decisions(document: dict) -> str:
    """Render observed decisions so the verdict carries the real values."""
    ordered = sorted(_cases_by_id(document).values(), key=lambda case: case["id"])
    return "; ".join(
        f"{case['id']}: expected_allowed={case.get('expected_allowed')!r} "
        f"allowed={case.get('allowed')!r}"
        for case in ordered
    ) or "<no cases>"


def _case_matches(case: dict) -> bool:
    """Recompute the per-case verdict from the two recorded values."""
    return bool(case.get("allowed")) == bool(case.get("expected_allowed"))


def _recomputed_all_match(cases: dict[str, dict]) -> bool:
    return all(_case_matches(case) for case in cases.values())


def _cross_checks(context: dict, observation: dict, report: dict) -> list[str]:
    """Evidence-integrity checks shared by all three outcomes."""
    problems: list[str] = []
    if report.get("schema_version") != 1:
        problems.append(f"report schema_version is {report.get('schema_version')!r}")
    if report.get("variant") != context["variant"]:
        problems.append(f"report variant is {report.get('variant')!r}")
    if report.get("scenario") != context["scenario"]:
        problems.append(f"report scenario is {report.get('scenario')!r}")

    if observation.get("execution_status") != "completed":
        problems.append(f"observation execution_status is {observation.get('execution_status')!r}")
    if observation.get("target_ready") is not True:
        problems.append(f"observation target_ready is {observation.get('target_ready')!r}")
    if observation.get("harness_exit_code") != 0:
        problems.append(f"harness exit code is {observation.get('harness_exit_code')!r}")

    source = observation.get("source")
    if not isinstance(source, str) or Path(source).name != context["variant"]:
        problems.append(
            f"the compiled tree was {source!r}, not the pinned {context['variant']} checkout")

    observed = _cases_by_id(observation)
    recorded = _cases_by_id(report)
    if not observed:
        problems.append("observation records no cases")
    if not recorded:
        problems.append("harness report records no cases")
    if set(observed) != set(recorded):
        problems.append("observation and report disagree on the case set")
    for case_id in sorted(set(observed) & set(recorded)):
        first, second = observed[case_id], recorded[case_id]
        if bool(first.get("allowed")) != bool(second.get("allowed")):
            problems.append(f"case {case_id}: observation and report disagree on allowed")
        for field in IDENTITY_FIELDS:
            if first.get(field) != second.get(field):
                problems.append(f"case {case_id}: observation and report disagree on {field}")
        # observation.cases[*].subtest comes from the Go test transcript, a copy
        # that does not pass through the JSON report at all.
        if first.get("subtest") != "PASS":
            problems.append(
                f"case {case_id}: the Go subtest did not report PASS ({first.get('subtest')!r})")
        for case in (first, second):
            expected = case.get("expected_allowed")
            allowed = bool(case.get("allowed"))
            if case.get("matches_expectation") is not None:
                if bool(case.get("matches_expectation")) != (allowed == bool(expected)):
                    problems.append(f"case {case_id}: matches_expectation is inconsistent")

    # Recompute all_match instead of trusting the declared flag in either copy.
    if recorded and report.get("all_match") is not _recomputed_all_match(recorded):
        problems.append("harness report all_match is inconsistent with its own cases")
    if observed and observation.get("all_match") is not _recomputed_all_match(observed):
        problems.append("observation all_match is inconsistent with its own cases")
    if observation.get("all_match") is not report.get("all_match"):
        problems.append("observation.all_match disagrees with the harness report")
    return problems


def check(context: dict, observation: dict, paths: dict):
    variant = context["variant"]
    scenario = context["scenario"]
    if scenario == "benign":
        check_id = BENIGN_TASK
    elif variant == "vulnerable":
        check_id = VULNERABLE_EFFECT
    else:
        check_id = PATCHED_EFFECT

    report_path = paths.get(REPORT)
    if report_path is None:
        return check_id, False, f"hash-checked evidence {REPORT} exists", "missing effect file"
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return check_id, False, f"{REPORT} parses as JSON", f"{type(error).__name__}: {error}"

    problems = _cross_checks(context, observation, report)
    by_id = _cases_by_id(observation)
    denied = [case for case in by_id.values() if case.get("expected_allowed") is False]
    allowed = [case for case in by_id.values() if case.get("expected_allowed") is True]

    if scenario == "benign":
        expected = "every normal owner/grantee gateway request is allowed"
        if not by_id:
            problems.append("no benign case was observed")
        for case_id, case in sorted(by_id.items()):
            if case.get("allowed") is not True:
                problems.append(f"benign case {case_id} was not allowed")
            if case.get("matches_expectation") is not True:
                problems.append(f"benign case {case_id} did not match its expectation")
        if observation.get("all_match") is not True:
            problems.append("benign run did not match every expectation")
    elif variant == "vulnerable":
        expected = (
            "an authenticated user outside the access-control rule is allowed to "
            "/mcp-connect/{mcp_id} (authorization bypass) while the granted user is allowed"
        )
        if not denied:
            problems.append("attack fixture has no case that the access-control rule denies")
        for case in denied:
            if case.get("allowed") is not True:
                problems.append(f"non-subject case {case.get('id')} was not allowed; no bypass observed")
        if not allowed:
            problems.append("attack fixture has no legitimately granted case")
        for case in allowed:
            if case.get("allowed") is not True:
                problems.append(f"granted case {case.get('id')} was unexpectedly denied")
        if observation.get("all_match") is not False:
            problems.append("vulnerable run matched every expectation; bypass evidence is absent")
    else:
        expected = (
            "a user outside the access-control rule is denied /mcp-connect/{mcp_id} "
            "while the granted user is still allowed"
        )
        if not denied:
            problems.append("attack fixture has no case that the access-control rule denies")
        for case in denied:
            if case.get("allowed") is not False:
                problems.append(f"non-subject case {case.get('id')} was allowed; the fix did not block it")
        if not allowed:
            problems.append("attack fixture has no legitimately granted case")
        for case in allowed:
            if case.get("allowed") is not True:
                problems.append(f"granted case {case.get('id')} was blocked; the fix broke legitimate access")
        if observation.get("all_match") is not True:
            problems.append("patched run did not match every expectation")

    actual = _decisions(observation)
    if problems:
        actual = f"{actual} | problems: {'; '.join(problems)}"
    return check_id, not problems, expected, actual


def main() -> int:
    args = parser(__doc__).parse_args()
    read_context(args.context)
    return verify(args.context, args.output, check)


if __name__ == "__main__":
    sys.exit(main())
