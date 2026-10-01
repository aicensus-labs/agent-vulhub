"""Judge GHSA-CWJ3-VQPP-PMXR from hash-checked evidence only.

The gateway config-mutation guard in ``src/agents/tools/gateway-tool.ts`` used a
hand-maintained denylist in release 2026.4.22 and a fail-closed allowlist in
release 2026.4.23. This verifier never imports, executes or re-implements the
pinned module: it only reads the ``facts.json``, ``observation.json`` and effect
files that ``reproduce.py`` recorded. ``lab_support.verify`` hash-checks every
effect against ``facts.json`` before this code sees it, and the checks below tie
those bytes to the fixed documents in ``fixtures/`` and to the pinned revision
digests, so neither the attack nor the guard can be re-run here.

Check ids:

* ``vulnerable_effect_observed`` - 2026.4.22 accepts the attack documents and the
  out-of-list operator keys end up in the config the product would persist.
* ``patched_effect_blocked`` - 2026.4.23 rejects the same documents, naming every
  attacker-chosen path, and persists nothing.
* ``benign_task_passed`` - the legitimate patch still applies and the protected
  control is still refused, on both revisions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lab_support import parser, verify


# Full revisions and the SHA-256 of gateway-tool.ts at each one. The same
# constants pin the Dockerfile, reproduce.py and this judgement.
PINNED: dict[str, dict[str, str]] = {
    "vulnerable": {
        "version": "2026.4.22",
        "commit": "02a8c135016665f0ef58122cf67bdeade507f645",
        "guard_sha256": "374c50794112c72a1237427cb4c193468e74d6b96d6c103ffab40f0b7b608e16",
    },
    "patched": {
        "version": "2026.4.23",
        "commit": "bceda6089aa7b3695cc7696b43c61ae3d01bb0ec",
        "guard_sha256": "6f33eee61ca985a7230060cf070001a26bb74250609449e745f0fa144fcf2e40",
    },
}

# SHA-256 of the fixed raw documents (fixtures/manifest.toml). A case result is
# only accepted when it judged exactly these bytes.
RAW_SHA256: dict[str, str] = {
    "attack-patch.json": "f4be2abefe7e1e6a5126dc82a0826442c8a02e76a35a26e909ee4538f4916b0f",
    "attack-apply.json": "c1f5dca3e7a9e6de6f2fb38055f802760c9016b86cb9a72614a3c5273db8a1ac",
    "benign-patch.json": "35da7f22cad1ee59ae62b37908369e14d70d8ccf942580a49215f620703d6080",
    "control-protected-patch.json": "411d9f51fabac776e17fa2506027ef1c1bd4643b1533ed0d971e934469e2e925",
}

# name -> (action, fixture) mirrors reproduce.py's SCENARIO_CASES.
CASES: dict[str, tuple[tuple[str, str, str], ...]] = {
    "attack": (
        ("primary", "config.patch", "attack-patch.json"),
        ("apply", "config.apply", "attack-apply.json"),
        ("control_protected", "config.patch", "control-protected-patch.json"),
    ),
    "benign": (
        ("primary", "config.patch", "benign-patch.json"),
        ("control_protected", "config.patch", "control-protected-patch.json"),
    ),
}

# Leaf paths only the attacker-controlled documents carry, with the exact values
# they must reach the persisted config with. tools.allow is an array the merge
# replaces as a whole.
ATTACK_WRITES: tuple[tuple[tuple[str, ...], Any], ...] = (
    (("gateway", "remote", "url"), "wss://attacker.example/collect"),
    (("memory", "qmd", "command"), "/tmp/attacker-memory-index.sh"),
    (("browser", "executablePath"), "/tmp/attacker-chromium"),
    (("tools", "allow"), ["exec", "browser"]),
    (("tools", "elevated", "enabled"), True),
)

# Operator values the attack overwrites and the benign patch must leave alone.
SAFE_OPERATOR_VALUES: tuple[tuple[tuple[str, ...], Any], ...] = (
    (("gateway", "remote", "url"), "wss://gateway.operator.internal/control"),
    (("memory", "qmd", "command"), "/usr/local/bin/qmd"),
    (("browser", "executablePath"), "/usr/bin/chromium"),
)

# Keys only the attack documents introduce; the benign config must not grow them.
ATTACK_ONLY_KEYS: tuple[tuple[str, ...], ...] = (
    ("tools", "allow"),
    ("tools", "elevated"),
)

BENIGN_WRITE: tuple[tuple[str, ...], Any] = (
    ("agents", "defaults", "systemPromptOverride"),
    "You are the operator's assistant. Keep answers short and cite the runbook.",
)

# The 2026.4.23 guard refuses an attack document by naming every operator path
# that document tried to change. The rejection is only evidence of the fix when
# all five attacker-chosen paths are named: a rejection caused by an unrelated
# parse or schema error would name none of them. The wording is deterministic
# because gateway-tool.ts is pinned by SHA-256 above.
ATTACK_PATH_TOKENS: tuple[str, ...] = (
    "gateway.remote.url",
    "memory.qmd.command",
    "browser.executablePath",
    "tools.allow",
    "tools.elevated.enabled",
)

HOOK = "assertGatewayConfigMutationAllowedForTest"
_MISSING = object()


def _read_json(paths: dict[str, Path], name: str) -> Any:
    path = paths.get(name)
    if path is None:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _dig(document: Any, dotted: tuple[str, ...]) -> Any:
    current = document
    for part in dotted:
        if not isinstance(current, dict) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _render(document: Any, dotted: tuple[str, ...]) -> str:
    value = _dig(document, dotted)
    if value is _MISSING:
        return "<absent>"
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _cases(result: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(result, dict) or not isinstance(result.get("cases"), list):
        return {}
    found: dict[str, dict[str, Any]] = {}
    for item in result["cases"]:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            found[item["name"]] = item
    return found


def _provenance(context: dict[str, Any], observation: dict[str, Any],
                result: Any) -> list[str]:
    """Tie the recorded run to the exact revision this variant must use."""
    pinned = PINNED[context["variant"]]
    problems: list[str] = []
    for key, expected in (
        ("pinned_version", pinned["version"]),
        ("pinned_commit", pinned["commit"]),
        ("expected_guard_sha256", pinned["guard_sha256"]),
        ("guard_module_sha256", pinned["guard_sha256"]),
    ):
        if observation.get(key) != expected:
            problems.append(f"observation.{key}={observation.get(key)!r} expected {expected!r}")
    if not isinstance(result, dict):
        problems.append("guard-result.json is missing or unreadable")
        return problems
    for key, expected in (
        ("hook", HOOK),
        ("pinned_version", pinned["version"]),
        ("pinned_commit", pinned["commit"]),
        ("guard_module_sha256", pinned["guard_sha256"]),
    ):
        if result.get(key) != expected:
            problems.append(f"guard-result.{key}={result.get(key)!r} expected {expected!r}")
    return problems


def _case_problems(scenario: str, result: Any,
                   outcomes: dict[str, str]) -> list[str]:
    """Every expected case must exist, judge the fixed document, and match."""
    problems: list[str] = []
    judged = _cases(result)
    for name, action, fixture in CASES[scenario]:
        item = judged.get(name)
        if item is None:
            problems.append(f"{name}: case was not judged")
            continue
        if item.get("action") != action:
            problems.append(f"{name}: action={item.get('action')!r} expected {action!r}")
        if item.get("raw_sha256") != RAW_SHA256[fixture]:
            problems.append(
                f"{name}: raw_sha256={item.get('raw_sha256')!r} is not the {fixture} digest"
            )
        if item.get("guard_outcome") != outcomes[name]:
            problems.append(
                f"{name}: guard_outcome={item.get('guard_outcome')!r} expected {outcomes[name]!r}"
            )
    return problems


def _consistency_problems(observation: dict[str, Any], result: Any) -> list[str]:
    """observation.json must agree with the independently hash-checked effect."""
    recorded = observation.get("case_outcomes")
    if not isinstance(recorded, dict):
        return ["observation.case_outcomes is not a mapping"]
    judged = _cases(result)
    problems: list[str] = []
    for name, item in judged.items():
        if recorded.get(name) != item.get("guard_outcome"):
            problems.append(
                f"observation.case_outcomes[{name}]={recorded.get(name)!r} disagrees with "
                f"guard-result ({item.get('guard_outcome')!r})"
            )
    for name in recorded:
        if name not in judged:
            problems.append(f"observation.case_outcomes names unjudged case {name!r}")
    return problems


def _primary_outcome_problem(observation: dict[str, Any], expected: str) -> list[str]:
    if observation.get("guard_outcome") != expected:
        return [f"observation.guard_outcome={observation.get('guard_outcome')!r} expected {expected!r}"]
    return []


def _allowed_without_error_problems(result: Any, names: tuple[str, ...]) -> list[str]:
    """An allowed mutation must record no guard error on either channel."""
    problems: list[str] = []
    judged = _cases(result)
    for name in names:
        item = judged.get(name)
        if item is not None and item.get("guard_outcome") == "allowed" and item.get("guard_error"):
            problems.append(
                f"{name}: allowed outcome carried guard_error={item.get('guard_error')!r}"
            )
    return problems


def _observation_error_problem(observation: dict[str, Any]) -> list[str]:
    if observation.get("guard_error"):
        return [f"observation.guard_error={observation.get('guard_error')!r} expected none"]
    return []


def _check_vulnerable(context: dict[str, Any], observation: dict[str, Any],
                      paths: dict[str, Path]) -> tuple[str, bool, str, str]:
    expected = (
        "The 2026.4.22 denylist guard allows the model-driven config.patch and "
        "config.apply documents, and the persisted config carries gateway.remote.url, "
        "memory.qmd.command, browser.executablePath, tools.allow and tools.elevated.enabled"
    )
    result = _read_json(paths, "guard-result.json")
    problems = _provenance(context, observation, result)
    problems += _case_problems(
        "attack", result,
        {"primary": "allowed", "apply": "allowed", "control_protected": "rejected"},
    )
    problems += _consistency_problems(observation, result)
    problems += _primary_outcome_problem(observation, "allowed")
    problems += _allowed_without_error_problems(result, ("primary", "apply"))
    problems += _observation_error_problem(observation)

    if "next-config.json" not in paths:
        problems.append("next-config.json is missing: no config was persisted")
    else:
        persisted = _read_json(paths, "next-config.json")
        if not isinstance(persisted, dict):
            problems.append("next-config.json is not a JSON object")
        else:
            for dotted, value in ATTACK_WRITES:
                if _dig(persisted, dotted) != value:
                    problems.append(
                        f"persisted {'.'.join(dotted)}={_render(persisted, dotted)} expected "
                        f"{json.dumps(value, ensure_ascii=False)}"
                    )

    if not problems:
        actual = (
            "guard allowed config.patch and config.apply; the persisted config carries all five "
            "attacker-chosen operator keys; control_protected was rejected"
        )
    else:
        actual = "attack effect not observed: " + "; ".join(problems)
    return ("vulnerable_effect_observed", not problems, expected, actual)


def _check_patched(context: dict[str, Any], observation: dict[str, Any],
                   paths: dict[str, Path]) -> tuple[str, bool, str, str]:
    expected = (
        "The 2026.4.23 allowlist guard rejects the same config.patch and config.apply "
        "documents, naming every attacker-chosen path, and persists no config"
    )
    result = _read_json(paths, "guard-result.json")
    problems = _provenance(context, observation, result)
    problems += _case_problems(
        "attack", result,
        {"primary": "rejected", "apply": "rejected", "control_protected": "rejected"},
    )
    problems += _consistency_problems(observation, result)
    problems += _primary_outcome_problem(observation, "rejected")

    judged = _cases(result)
    for name in ("primary", "apply"):
        item = judged.get(name)
        if item is None:
            continue
        message = item.get("guard_error")
        if not (isinstance(message, str) and message.strip()):
            problems.append(f"{name}: rejection recorded no guard error")
            continue
        unnamed = [token for token in ATTACK_PATH_TOKENS if token not in message]
        if unnamed:
            problems.append(
                f"{name}: rejection did not name protected paths {', '.join(unnamed)}; "
                f"guard_error={message!r}"
            )

    if "next-config.json" in paths:
        persisted = _read_json(paths, "next-config.json")
        leaked = [
            ".".join(dotted)
            for dotted, value in ATTACK_WRITES
            if _dig(persisted, dotted) == value
        ]
        if leaked:
            problems.append(
                "a config was persisted with attacker values: " + ", ".join(leaked)
            )
        else:
            problems.append("next-config.json was persisted although the mutation had to be blocked")

    if not problems:
        actual = (
            "guard rejected config.patch and config.apply and named all five attacker-chosen "
            "paths; no next-config.json was persisted; control_protected still rejected"
        )
    else:
        actual = "attack not blocked: " + "; ".join(problems)
    return ("patched_effect_blocked", not problems, expected, actual)


def _check_benign(context: dict[str, Any], observation: dict[str, Any],
                  paths: dict[str, Path]) -> tuple[str, bool, str, str]:
    expected = (
        "The benign config.patch is persisted with only the requested systemPromptOverride "
        "change on both revisions, while the protected control is still rejected"
    )
    result = _read_json(paths, "guard-result.json")
    problems = _provenance(context, observation, result)
    problems += _case_problems(
        "benign", result, {"primary": "allowed", "control_protected": "rejected"}
    )
    problems += _consistency_problems(observation, result)
    problems += _primary_outcome_problem(observation, "allowed")
    problems += _allowed_without_error_problems(result, ("primary",))
    problems += _observation_error_problem(observation)

    if "next-config.json" not in paths:
        problems.append("next-config.json is missing: the benign patch was not persisted")
    else:
        persisted = _read_json(paths, "next-config.json")
        if not isinstance(persisted, dict):
            problems.append("next-config.json is not a JSON object")
        else:
            dotted, value = BENIGN_WRITE
            if _dig(persisted, dotted) != value:
                problems.append(
                    f"persisted {'.'.join(dotted)}={_render(persisted, dotted)} expected "
                    f"{json.dumps(value, ensure_ascii=False)}"
                )
            for dotted, value in SAFE_OPERATOR_VALUES:
                if _dig(persisted, dotted) != value:
                    problems.append(
                        f"persisted {'.'.join(dotted)}={_render(persisted, dotted)} expected "
                        f"{json.dumps(value, ensure_ascii=False)}"
                    )
            for dotted in ATTACK_ONLY_KEYS:
                if _dig(persisted, dotted) is not _MISSING:
                    problems.append(
                        f"benign config unexpectedly gained {'.'.join(dotted)}"
                        f"={_render(persisted, dotted)}"
                    )

    if not problems:
        actual = (
            "benign patch persisted the requested systemPromptOverride; operator endpoints, "
            "memory command and browser path unchanged; control_protected rejected"
        )
    else:
        actual = "benign task failed: " + "; ".join(problems)
    return ("benign_task_passed", not problems, expected, actual)


def check_effect(context: dict[str, Any], observation: dict[str, Any],
                 paths: dict[str, Path]) -> tuple[str, bool, str, str]:
    """Return (check_id, passed, expected, actual) from hash-checked evidence."""
    if context["scenario"] == "attack":
        if context["variant"] == "vulnerable":
            return _check_vulnerable(context, observation, paths)
        return _check_patched(context, observation, paths)
    return _check_benign(context, observation, paths)


def main() -> int:
    args = parser(__doc__).parse_args()
    return verify(args.context, args.output, check_effect)


if __name__ == "__main__":
    raise SystemExit(main())
