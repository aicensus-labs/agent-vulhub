"""Independent verdict for GHSA-XRMC-C5CG-RV7X from hash-checked evidence only.

The verifier never loads, imports or executes the SafeInstall guard. It reads the
hash-checked ``observation.json`` and the ``guard-analysis.json`` effect recorded
by ``reproduce.py``, re-classifies every recorded parser result itself, and
compares that classification with the raw command text. The vulnerable build must
fail open on the crafted corpus, the patched build must close every one of those
commands, and the benign controls must keep classifying as before.
"""

from __future__ import annotations

import json
import re

from lab_support import parser, read_context, verify

ANALYSIS_EFFECT = "guard-analysis.json"
EXPECTED_NAME = "safeinstall-cli"
EXPECTED_VERSION = {"vulnerable": "0.10.1", "patched": "0.10.2"}
# The compiled classifier of each pinned revision, pinned by content hash. The
# version string lives inside package.json and is only what the recorded build
# says about itself; the artifact hash is compared against this independent pin
# so a mislabelled or substituted build cannot satisfy the verdict.
EXPECTED_GUARD_SHA256 = {
    "vulnerable": "60180a146627a8159713223719fadb32a1dbd63e90a477d2e046cee44df38ff8",
    "patched": "8df556da455d099ea38b7e047a04b23e0ac612bac2e19b01f9945fd9fba92409",
}
# Floor sizes of the reviewed corpora; a truncated or empty effect must not pass.
MIN_COMMANDS = {"attack": 20, "benign": 3}
CHECK_IDS = {
    ("attack", "vulnerable"): "vulnerable_effect_observed",
    ("attack", "patched"): "patched_effect_blocked",
    ("benign", "vulnerable"): "benign_task_passed",
    ("benign", "patched"): "benign_task_passed",
}
# A package manager invocation that a correct guard must not silently ignore.
MANAGER_INVOCATION = re.compile(
    r"\b(?:npm|pnpm|yarn|bun|npx|pnpx)\s+(?:install|i|add|create|init|dlx|exec)\b")
HEX64 = re.compile(r"[0-9a-f]{64}")
# A manager invoked through an explicit path, e.g. ``/usr/bin/npm``: both
# revisions find the install, but only the fixed rewrite normalizes it.
PATH_MANAGER = re.compile(r"(?:^|\s)(/[^\s]*?/(?:npm|pnpm|yarn|bun))(?=\s|$)")
# Bypass shapes the advisory names; recognised in the raw command text only.
REDIRECTION_PREFIX = re.compile(r"^(?:\d*|\{[^}]*\})?[<>]")
WRAPPER_PREFIX = re.compile(r"(?i)^(?:sudo|env|command|time|nice|nohup|setsid)\b")


def classify(item):
    """Derive the guard's own conclusion from one recorded parser result."""
    if item.get("installs"):
        return "install_finding"
    if item.get("runners"):
        return "runner_finding"
    if item.get("unanalyzable"):
        return "unanalyzable"
    if item.get("usesSafeInstall") is True:
        return "uses_safeinstall"
    return "no_finding"


def mentions_manager_invocation(command):
    return bool(MANAGER_INVOCATION.search(command.lower()))


def bypass_shapes(command):
    """Intrinsic shape tags read from the command text, not from any declaration."""
    text = command.strip()
    low = text.lower()
    tags = set()
    if REDIRECTION_PREFIX.match(text):
        tags.add("redirection-prefix")
    if WRAPPER_PREFIX.match(text):
        tags.add("wrapper")
    if (re.search(r"\b(?:npm|pnpm|yarn|bun)\b", low)
            and re.search(r"\b(?:NPM|Npm|PNPM|Pnpm|Bun|BUN|YARN|Yarn)\b", text)):
        tags.add("case-fold")
    if re.search(r"\b(?:npm|pnpm|yarn|bun)\s+(?:create|init)\b", low):
        tags.add("remote-exec")
    if re.search(r"\b(?:npm|pnpm|yarn|bun)\s+(?:install|i|add)\b", low):
        tags.add("install")
    if "safeinstall" in low.split():
        tags.add("already-routed")
    return tags


def rewrite_of(item):
    """The rewritten command the guard returned, or '' when it returned none."""
    value = item.get("rewrittenCommand")
    return value if isinstance(value, str) else ""


def path_qualified_installs(commands):
    """Install findings whose manager was named through an explicit path."""
    found = []
    for item in commands:
        match = PATH_MANAGER.search(item["command"])
        if match and classify(item) == "install_finding":
            found.append((item, match.group(1)))
    return found


def load_evidence(context, observation, paths):
    """Parse and sanity-check the effect file; raise ValueError on anything odd."""
    path = paths.get(ANALYSIS_EFFECT)
    if path is None:
        raise ValueError(f"{ANALYSIS_EFFECT} is not hash-checked evidence")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("unexpected guard-analysis schema")
    if payload.get("scenario") != context["scenario"] or payload.get("variant") != context["variant"]:
        raise ValueError("guard-analysis scenario/variant disagrees with the execution context")
    commands = payload.get("commands")
    if not isinstance(commands, list) or not commands:
        raise ValueError("guard-analysis records no commands")
    minimum = MIN_COMMANDS[context["scenario"]]
    if len(commands) < minimum:
        raise ValueError(
            f"guard-analysis records {len(commands)} commands, expected at least {minimum}")
    seen = set()
    for item in commands:
        if (not isinstance(item, dict) or not isinstance(item.get("id"), str)
                or not item["id"].strip() or not isinstance(item.get("command"), str)
                or not item["command"].strip() or item["id"] in seen):
            raise ValueError("guard-analysis command entries are malformed or duplicated")
        seen.add(item["id"])
        if not isinstance(item.get("installs"), list) or not isinstance(item.get("runners"), list) \
                or not isinstance(item.get("unanalyzable"), list):
            raise ValueError(f"guard-analysis entry {item['id']} has malformed finding lists")
    return payload, commands


def identity_problems(context, observation, payload):
    """The recorded effect must come from the variant this gate claims to run."""
    variant = context["variant"]
    upstream = payload.get("upstream") if isinstance(payload.get("upstream"), dict) else {}
    problems = []
    if upstream.get("name") != EXPECTED_NAME:
        problems.append(f"upstream name is {upstream.get('name')!r}, expected {EXPECTED_NAME!r}")
    if upstream.get("version") != EXPECTED_VERSION[variant]:
        problems.append(
            f"upstream version is {upstream.get('version')!r}, expected {EXPECTED_VERSION[variant]!r}")
    sha = upstream.get("guard_commands_sha256")
    if not isinstance(sha, str) or not HEX64.fullmatch(sha):
        problems.append("guard-commands sha256 is missing or malformed")
    elif sha != EXPECTED_GUARD_SHA256[variant]:
        problems.append(
            f"guard-commands sha256 is {sha!r}, which is not the pinned "
            f"{variant} classifier {EXPECTED_GUARD_SHA256[variant]!r}")
    for key, value in (("upstream_name", upstream.get("name")),
                       ("upstream_version", upstream.get("version")),
                       ("upstream_guard_commands_sha256", sha)):
        if observation.get(key) != value:
            problems.append(f"observation {key} disagrees with the effect file")
    if observation.get("command_count") != len(payload.get("commands") or []):
        problems.append("observation command_count disagrees with the effect file")
    return problems


def summary_problems(observation, commands):
    """The observation's with/without-finding lists must match the raw results."""
    computed_with = sorted(
        item["id"] for item in commands
        if item["installs"] or item["runners"] or item["unanalyzable"])
    computed_without = sorted(
        item["id"] for item in commands
        if not (item["installs"] or item["runners"] or item["unanalyzable"]))
    problems = []
    if sorted(observation.get("commands_with_finding") or []) != computed_with:
        problems.append("observation commands_with_finding disagrees with the raw parser results")
    if sorted(observation.get("commands_without_finding") or []) != computed_without:
        problems.append("observation commands_without_finding disagrees with the raw parser results")
    return problems


def declared_mismatches(commands, key):
    return [item["id"] for item in commands if classify(item) != item.get(key)]


def check(context, observation, paths):
    check_id = CHECK_IDS[(context["scenario"], context["variant"])]
    scenario = context["scenario"]
    variant = context["variant"]
    try:
        payload, commands = load_evidence(context, observation, paths)
        problems = identity_problems(context, observation, payload) \
            + summary_problems(observation, commands)
    except (ValueError, OSError, KeyError, TypeError) as error:
        return (check_id, False,
                "the recorded guard-analysis effect is readable and matches the execution context",
                f"invalid evidence: {error}")

    if scenario == "attack" and variant == "vulnerable":
        expected = ("SafeInstall 0.10.1 classifies a plain install as an install finding "
                    "while the crafted case-fold, redirection-prefix, wrapper-flag and "
                    "remote-exec commands yield no finding at all (guard fails open)")
        misses = [item for item in commands
                  if mentions_manager_invocation(item["command"]) and classify(item) == "no_finding"]
        detected = [item for item in commands
                    if mentions_manager_invocation(item["command"]) and classify(item) != "no_finding"]
        controls = [item["id"] for item in detected if classify(item) == "install_finding"]
        shapes = set()
        for item in misses:
            shapes |= bypass_shapes(item["command"])
        required_shapes = {"case-fold", "redirection-prefix", "wrapper", "remote-exec"}
        mismatch = declared_mismatches(commands, "expect_vulnerable")
        # The two revisions differ observably on a path-qualified manager: 0.10.1
        # copies the path text into its rewrite, 0.10.2 normalizes the manager.
        path_installs = path_qualified_installs(commands)
        path_kept = [item["id"] for item, path in path_installs if path in rewrite_of(item)]
        if problems:
            passed = False
        else:
            passed = (not mismatch
                      and len(misses) >= 5
                      and required_shapes <= shapes
                      and bool(controls)
                      and bool(path_installs)
                      and len(path_kept) == len(path_installs))
        actual = (f"{len(misses)} manager invocations classified as no_finding "
                  f"(shapes={sorted(shapes)}); {len(detected)} still detected "
                  f"(install controls={controls}); {len(path_kept)}/{len(path_installs)} "
                  f"path-qualified rewrites kept the path text; {len(mismatch)} entries disagree "
                  f"with the declared 0.10.1 expectation"
                  f"{' ' + str(mismatch) if mismatch else ''}"
                  + (f"; {problems}" if problems else ""))
        return (check_id, passed, expected, actual)

    if scenario == "attack" and variant == "patched":
        expected = ("SafeInstall 0.10.2 returns an install, runner or unanalyzable finding for "
                    "every crafted command, so none of the 0.10.1 bypasses survives")
        invocations = [item for item in commands if mentions_manager_invocation(item["command"])]
        still_open = [item["id"] for item in invocations if classify(item) == "no_finding"]
        reopened = [item["id"] for item in commands
                    if item.get("expect_vulnerable") == "no_finding"
                    and classify(item) != "no_finding"]
        controls = [item["id"] for item in commands if classify(item) == "install_finding"]
        mismatch = declared_mismatches(commands, "expect_patched")
        # Every install the fixed guard finds must come with a rewrite that routes
        # through safeinstall; a path-qualified manager must be normalized, which
        # is precisely where 0.10.1 left the path in the command.
        rewritten = [item["id"] for item in commands
                     if classify(item) == "install_finding" and "safeinstall" in rewrite_of(item)]
        path_installs = path_qualified_installs(commands)
        path_normalized = [item["id"] for item, path in path_installs
                           if path not in rewrite_of(item)
                           and re.search(r"\bsafeinstall\b", rewrite_of(item))]
        if problems:
            passed = False
        else:
            passed = (not mismatch
                      and not still_open
                      and len(reopened) >= 5
                      and bool(controls)
                      and len(rewritten) == len(controls)
                      and bool(path_installs)
                      and len(path_normalized) == len(path_installs))
        actual = (f"{len(still_open)} manager invocations still classified as no_finding"
                  f"{' ' + str(still_open) if still_open else ''}; {len(reopened)} previously "
                  f"missed commands now produce a finding; {len(path_normalized)}/"
                  f"{len(path_installs)} path-qualified rewrites normalized; "
                  f"{len(rewritten)}/{len(controls)} install findings rewritten through "
                  f"safeinstall; {len(mismatch)} entries disagree with the declared 0.10.2 "
                  f"expectation{' ' + str(mismatch) if mismatch else ''}"
                  + (f"; {problems}" if problems else ""))
        return (check_id, passed, expected, actual)

    # Benign task, either revision: the guard's ordinary behaviour must not regress.
    key = "expect_vulnerable" if variant == "vulnerable" else "expect_patched"
    mismatch = declared_mismatches(commands, key)
    install_like = [item for item in commands
                    if mentions_manager_invocation(item["command"])
                    and "safeinstall" not in item["command"].lower()]
    routed = [item for item in commands if "safeinstall" in item["command"].lower().split()]
    script_runs = [item for item in commands
                   if re.search(r"\b(?:npm|pnpm|yarn|bun)\s+run\b", item["command"].lower())]
    expected = ("The ordinary developer commands keep working in both revisions: the plain "
                "install is rewritten, the script run is left alone and an already routed "
                "command is recognised without a new finding")
    if problems:
        passed = False
    else:
        passed = (not mismatch
                  and bool(install_like)
                  and all(classify(item) == "install_finding" for item in install_like)
                  and all("safeinstall" in rewrite_of(item) for item in install_like)
                  and bool(routed)
                  and all(classify(item) == "uses_safeinstall" for item in routed)
                  and bool(script_runs)
                  and all(classify(item) == "no_finding" for item in script_runs))
    actual = (f"{len(install_like)} install(s) -> "
              f"{[classify(item) for item in install_like]}, "
              f"rewrites={[bool('safeinstall' in rewrite_of(item)) for item in install_like]}; "
              f"{len(routed)} safeinstall-routed -> "
              f"{[classify(item) for item in routed]}; {len(script_runs)} script run(s) -> "
              f"{[classify(item) for item in script_runs]}; {len(mismatch)} entries disagree with "
              f"the declared {EXPECTED_VERSION[variant]} expectation"
              f"{' ' + str(mismatch) if mismatch else ''}"
              + (f"; {problems}" if problems else ""))
    return (check_id, passed, expected, actual)


def main() -> int:
    args = parser(__doc__).parse_args()
    read_context(args.context)
    return verify(args.context, args.output, check)


if __name__ == "__main__":
    raise SystemExit(main())
