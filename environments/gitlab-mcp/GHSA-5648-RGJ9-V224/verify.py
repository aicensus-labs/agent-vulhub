"""Judge GHSA-5648-rgj9-v224 from hash-checked evidence only.

This entrypoint never invokes the upstream module and never replays the attack.
``lab_support.verify`` first hash-checks every file listed in ``facts.json`` and
then hands the parsed ``observation.json`` plus the verified effect paths to
:func:`check`.  The authoritative effect is ``driver-results.json``: it holds the
raw per-query decisions the pinned upstream classifier returned at run time and
the two structural facts read out of the pinned ``index.ts``.  The boolean
summaries in ``observation.json`` are only used as a consistency cross-check, so
a self-reported ``success``-style field can never carry the verdict on its own.

The structural fact is pinned harder than a boolean: the driver records the
SHA-256 of the brace-matched ``execute_graphql`` branch and of the
``rejectIfProjectScopedDeployment`` helper, and both hashes must equal the values
that belong to the revision the module hash already pins.  A rewritten
``index.ts`` that flips ``project_scope_guard_present`` therefore fails closed
instead of talking the verifier into a pass.

Expected revisions are the constants below (mirrored by ``fixtures/pin.json``);
if the on-disk pin disagrees the check fails closed instead of silently judging
against a moved target.

usage: verify.py --context <context.json> --output <directory>
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, "/lab")
from lab_support import parser, verify  # noqa: E402

FIXTURES = Path("/lab/fixtures")

# SHA-256 of the brace-matched rejectIfProjectScopedDeployment helper body.  The
# helper itself is introduced before v2.1.28 and its text is identical in both
# revisions, so one constant pins the definition in every scenario.
SCOPE_GUARD_DEFINITION_SHA256 = (
    "0a70ef44c63f73cd705d8a9124b6c34ee15fe6b625ddf8ce395bef93529ba9f8")

# Revisions pinned by fixtures/pin.json, by the image build assertions, and by the
# SHA-256 of the execute_graphql branch in the pinned index.ts.  The two branch
# hashes were computed independently from the tag tarballs recorded in
# metadata.toml build.inputs.
EXPECTED_REVISIONS = {
    "vulnerable": {
        "graphql_query_sha256":
            "0ee49475446ca2eb4add393eca0014ad04e526281bd3d3171c538f04729e47e7",
        "commit": "139a479147a52f65d47e8fee142214c4d5392468",
        "tag": "v2.1.28",
        "execute_graphql_branch_sha256":
            "f7f1ba951ae5e1bbd83fc3a802c02aee791fe8914dfdf9edbc82b99073963959",
        "read_only_guard_present": True,
        "project_scope_guard_present": False,
    },
    "patched": {
        "graphql_query_sha256":
            "4fc7128c866cf4fb24fb3a723853a25c2582f4437bb4c3ae3533a9a191a7b6e5",
        "commit": "cff3ebeec272d7cc609d9b3cab57f52cb15fae96",
        "tag": "v2.1.30",
        "execute_graphql_branch_sha256":
            "30288628fe2aaebe76590ee66ac2e1a9001e3300504a4ac4e08c47372d5bb286",
        "read_only_guard_present": True,
        "project_scope_guard_present": True,
    },
}

# Attack documents whose separator defect must be misread as read-only pre-fix
# and must be read as a write post-fix, plus the plainly written control mutation.
BYPASS_QUERY_IDS = (
    "leading_comma_mutation",
    "comment_then_comma_mutation",
    "trailing_comma_subscription",
)
CONTROL_QUERY_ID = "plain_mutation"
ATTACK_QUERY_IDS = (*BYPASS_QUERY_IDS, CONTROL_QUERY_ID)

# Read-only documents that must stay allowed in both revisions.
BENIGN_QUERY_IDS = (
    "read_current_user",
    "read_project_metadata",
    "read_subscription_field_name",
    "read_alias_mutation_word",
)


def _read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _same_bool(left: object, right: object) -> bool:
    return isinstance(left, bool) and isinstance(right, bool) and left is right


def _pin_matches(variant: str, expected: dict) -> bool:
    """Cross-check the hardcoded pin against fixtures/pin.json; fail closed if absent."""
    path = FIXTURES / "pin.json"
    if not path.is_file():
        return False
    try:
        pin = _read_json(path)
    except (OSError, ValueError):
        return False
    entry = pin.get(variant) if isinstance(pin, dict) else None
    if not isinstance(entry, dict):
        return False
    return (
        entry.get("graphql_query_sha256") == expected["graphql_query_sha256"]
        and entry.get("execute_graphql_branch_sha256")
        == expected["execute_graphql_branch_sha256"]
        and entry.get("scope_guard_definition_sha256")
        == SCOPE_GUARD_DEFINITION_SHA256
        and _same_bool(entry.get("read_only_guard_present"),
                       expected["read_only_guard_present"])
        and _same_bool(entry.get("project_scope_guard_present"),
                       expected["project_scope_guard_present"])
    )


def _required_check_id(context: dict) -> str:
    if context["scenario"] == "benign":
        return "benign_task_passed"
    if context["variant"] == "vulnerable":
        return "vulnerable_effect_observed"
    return "patched_effect_blocked"


def _sections(driver: dict) -> tuple[dict, dict, dict]:
    results = driver.get("results") if isinstance(driver.get("results"), dict) else {}
    queries = results.get("queries") if isinstance(results.get("queries"), dict) else {}
    structure = results.get("structure") if isinstance(results.get("structure"), dict) else {}
    module = driver.get("module") if isinstance(driver.get("module"), dict) else {}
    return queries, structure, module


def check(context: dict, observation: dict, paths: dict) -> tuple[str, bool, str, str]:
    """Return the one required effect check derived from the collected evidence."""
    check_id = _required_check_id(context)
    variant = context["variant"]
    scenario = context["scenario"]
    expected = EXPECTED_REVISIONS[variant]
    expected_sha = expected["graphql_query_sha256"]

    try:
        driver = _read_json(paths["driver-results.json"])
    except (OSError, ValueError, KeyError) as error:
        return (check_id, False,
                "driver-results.json is readable, complete, and pins the expected module hash",
                f"driver evidence unreadable: {error}")

    queries, structure, module = _sections(driver)
    observed = observation.get("observed") if isinstance(observation.get("observed"), dict) else {}
    driver_sha = module.get("sha256")

    # The structural facts are pinned by hash, not by the driver's own booleans:
    # the recorded execute_graphql branch and scope-guard helper text must hash to
    # the values belonging to the revision the module hash already pins.
    branch_ok = (
        structure.get("execute_graphql_branch_sha256")
        == expected["execute_graphql_branch_sha256"]
        and structure.get("scope_guard_definition_sha256")
        == SCOPE_GUARD_DEFINITION_SHA256
    )

    # Every scenario needs a complete driver run against the variant-pinned module;
    # a mislabelled image (wrong revision) can never satisfy this.
    base_ok = (
        driver.get("schema_version") == 1
        and driver.get("complete") is True
        and driver.get("variant") == variant
        and module.get("export") == "graphqlQueryContainsWriteOperation"
        and driver_sha == expected_sha
        and observation.get("loaded_module_sha256") == expected_sha
        and _pin_matches(variant, expected)
        and branch_ok
    )
    base_actual = {
        "variant": driver.get("variant"),
        "complete": driver.get("complete"),
        "module_sha256": driver_sha,
        "expected_module_sha256": expected_sha,
        "observation_module_sha256": observation.get("loaded_module_sha256"),
        "execute_graphql_branch_sha256": structure.get("execute_graphql_branch_sha256"),
        "expected_execute_graphql_branch_sha256":
            expected["execute_graphql_branch_sha256"],
        "scope_guard_definition_sha256": structure.get("scope_guard_definition_sha256"),
        "expected_scope_guard_definition_sha256": SCOPE_GUARD_DEFINITION_SHA256,
        "pin_matches": _pin_matches(variant, expected),
    }

    read_only_guard = structure.get("read_only_guard_present")
    project_scope_guard = structure.get("project_scope_guard_present")
    structure_ok = (
        _same_bool(read_only_guard, expected["read_only_guard_present"])
        and _same_bool(project_scope_guard, expected["project_scope_guard_present"])
    )

    if scenario == "benign":
        allowed = {qid: queries.get(qid) for qid in BENIGN_QUERY_IDS}
        passed = (
            base_ok
            and structure_ok
            and set(queries) == set(BENIGN_QUERY_IDS)
            and all(value is False for value in allowed.values())
        )
        expected_text = ("every benign read-only document is classified as read-only "
                         "(False) by the variant-pinned module and the pinned "
                         "execute_graphql structure matches the revision")
        actual = {**base_actual, "benign_queries": allowed}
        return (check_id, passed, expected_text, json.dumps(actual, sort_keys=True))

    bypass = {qid: queries.get(qid) for qid in BYPASS_QUERY_IDS}
    control = queries.get(CONTROL_QUERY_ID)

    if variant == "vulnerable":
        # Pre-fix: the separator defect makes all three payloads read-only, so the
        # read-only gate never fires; the execute_graphql branch also has no
        # project allow-list guard.
        passed = (
            base_ok
            and structure_ok
            and set(queries) == set(ATTACK_QUERY_IDS)
            and all(value is False for value in bypass.values())
            and control is True
            and observed.get("read_only_bypass_observed") is True
            and observed.get("comment_bypass_observed") is True
            and observed.get("separator_bypass_observed") is True
            and observed.get("plain_mutation_flagged") is True
            and observed.get("project_scope_guard_present") is False
        )
        expected_text = ("the three comma/comment/trailing separator payloads are "
                         "misclassified as read-only (False), the plain mutation is a "
                         "write (True), the read-only gate is present, and the "
                         "execute_graphql branch (branch hash pinned) has no project "
                         "allow-list guard")
    else:
        # Post-fix: the state machine reads the same payloads as writes and the
        # branch rejects project-scoped deployments before parsing arguments.
        passed = (
            base_ok
            and structure_ok
            and set(queries) == set(ATTACK_QUERY_IDS)
            and all(value is True for value in bypass.values())
            and control is True
            and observed.get("bypass_query_flagged") is True
            and observed.get("read_only_bypass_observed") is False
            and observed.get("comment_bypass_observed") is False
            and observed.get("separator_bypass_observed") is False
            and observed.get("project_scope_guard_present") is True
        )
        expected_text = ("the same three payloads are classified as writes (True), the "
                         "plain mutation stays a write (True), and the execute_graphql "
                         "branch (branch hash pinned) carries the project allow-list guard")

    actual = {
        **base_actual,
        "bypass_queries": bypass,
        "control_query": control,
        "read_only_guard_present": read_only_guard,
        "project_scope_guard_present": project_scope_guard,
        "expected_read_only_guard_present": expected["read_only_guard_present"],
        "expected_project_scope_guard_present": expected["project_scope_guard_present"],
        "observed": observed,
    }
    return (check_id, passed, expected_text, json.dumps(actual, sort_keys=True))


def main() -> int:
    args = parser(__doc__).parse_args()
    return verify(args.context, args.output, check)


if __name__ == "__main__":
    raise SystemExit(main())
