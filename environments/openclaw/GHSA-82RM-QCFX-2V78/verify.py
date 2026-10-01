"""Independent evidence checks for openclaw GHSA-82RM-QCFX-2V78.

The verifier only reads the hash-checked ``facts.json`` / ``observation.json``
and the recorded effect files. It never imports, loads or executes the pinned
openclaw package, so a verdict cannot be produced by rerunning the attack.

Two layers of evidence are checked independently of ``reproduce.py``'s
transcription in ``observation.json``:

* the raw ``driver-report.json`` the pinned product's driver wrote, including
  the release version and the content-hashed delivery-queue chunk, so a verdict
  can only be about the revision under test; and
* the structural ``queued-entry.json`` write-ahead record plus the actual bytes
  of the canary media the product's ``readFile`` capability returned.

Vulnerable effect (group tool policy denies ``read``):
  the delivery-queue recovery replays the queued media delivery without the
  group session context, the group policy cannot be resolved, and the media
  read capability is granted anyway: the canary media bytes are actually read.

Patched effect (same denied group):
  the recovered parameters still carry the session, the group policy resolves,
  the media read capability is withheld and the recorded media effect is empty.

Benign effect (group policy allows ``read``):
  the same queued media replay still reads the canary in both revisions; on the
  patched revision the session and the ``allow read`` policy are demonstrably
  present, on the vulnerable revision the benign read succeeds even though the
  policy context is still lost.
"""

from __future__ import annotations

import hashlib
import json

from lab_support import parser, read_context, verify

# Synthetic media marker pinned by fixtures/manifest.toml (canary-media.txt).
# Both the expected digest and the literal prefix are fixed inputs, not values
# self-reported by the PoC.
CANARY_SHA256 = "00fa0b5b903e14c90a028854e062f4b9ce151d378fb557536dcfcba8269dba43"
CANARY_PREFIX = b"AVH-CANARY-MEDIA-"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

MEDIA_EFFECT = "media-read.bin"
REPORT_EFFECT = "driver-report.json"
QUEUE_EFFECT = "queued-entry.json"

# Release identity pinned by the environment's build inputs.  The chunk name is
# the content hash of the bundle that holds the write-ahead delivery queue, so a
# report mentioning any other revision cannot be evidence about this revision.
REVISIONS = {
    "vulnerable": ("2026.4.10", "delivery-queue-wYNXw79t.js"),
    "patched": ("2026.4.14", "delivery-queue-cUZQxuAc.js"),
}

DENIED_TOOL = "read"

# Decision fields the verifier re-derives from raw evidence instead of trusting
# reproduce.py's transcription.  Any disagreement fails the check.
DECISION_KEYS = (
    "package_version",
    "queue_chunk",
    "queued_id",
    "recovered_deliver_calls",
    "stored_entry_available",
    "stored_entry_has_session",
    "recovered_params_has_session",
    "group_policy_present",
    "group_policy_resolved",
    "media_read_file_granted",
    "media_read_bytes_sha256",
)


def _read_json(paths: dict, name: str):
    path = paths.get(name)
    if path is None:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _media(paths: dict) -> tuple[bytes, str]:
    """Read the recorded media effect as verified local evidence."""
    raw = paths[MEDIA_EFFECT].read_bytes() if MEDIA_EFFECT in paths else b""
    return raw, hashlib.sha256(raw).hexdigest()


def _policy_decision(resolved) -> str:
    """Reduce the product's resolved group tool policy to allow/deny/none."""
    if not isinstance(resolved, dict):
        return "none"
    deny = resolved.get("deny")
    allow = resolved.get("allow")
    if isinstance(deny, list) and DENIED_TOOL in deny:
        return "deny"
    if isinstance(allow, list) and DENIED_TOOL in allow:
        return "allow"
    return "none"


def _session_kept(queued) -> bool:
    return bool(
        isinstance(queued, dict)
        and isinstance(queued.get("session"), dict)
        and queued["session"].get("key")
    )


def _ground_truth(context: dict, observation: dict, paths: dict) -> tuple[dict | None, dict | None, list[str]]:
    """Re-derive the decision facts from the raw, hash-checked effect files."""
    problems: list[str] = []
    report = _read_json(paths, REPORT_EFFECT)
    queued = _read_json(paths, QUEUE_EFFECT)
    if not isinstance(report, dict):
        problems.append(f"{REPORT_EFFECT} is missing or unreadable")
    else:
        for key in DECISION_KEYS:
            if key in report and observation.get(key) != report[key]:
                problems.append(
                    f"{key} transcription mismatch: observation={observation.get(key)!r} report={report[key]!r}"
                )
        version, chunk = REVISIONS[context["variant"]]
        if report.get("package_version") != version:
            problems.append(f"package_version={report.get('package_version')!r}, expected {version!r}")
        if report.get("queue_chunk") != chunk:
            problems.append(f"queue_chunk={report.get('queue_chunk')!r}, expected {chunk!r}")
        if report.get("load_chunk") != chunk:
            problems.append(f"load_chunk={report.get('load_chunk')!r}, expected {chunk!r}")
    if not isinstance(queued, dict) or not queued.get("id"):
        problems.append(f"{QUEUE_EFFECT} is missing the enqueued delivery id")
    elif isinstance(report, dict) and queued.get("id") != report.get("queued_id"):
        problems.append(
            f"queued id {queued.get('id')!r} does not match the replayed delivery {report.get('queued_id')!r}"
        )
    calls = observation.get("recovered_deliver_calls")
    if not isinstance(calls, int) or calls < 1:
        problems.append(f"restart recovery never replayed the queued delivery (recovered_deliver_calls={calls!r})")
    if observation.get("stored_entry_available") is not True:
        problems.append("the write-ahead queue entry could not be read back before recovery")
    return report, queued, problems


def _verdict(problems: list[str], expected: str, summary: str) -> tuple[bool, str, str]:
    """Return (passed, expected, actual) for the lab_support check contract."""
    if problems:
        return False, expected, "FAILED: " + "; ".join(problems) + " | observed: " + summary
    return True, expected, summary


def _vulnerable_attack(context: dict, observation: dict, paths: dict) -> tuple[bool, str, str]:
    report, queued, problems = _ground_truth(context, observation, paths)
    raw, digest = _media(paths)
    if observation.get("stored_entry_has_session") is not False:
        problems.append("the write-ahead queue entry kept the group session context")
    if observation.get("recovered_params_has_session") is not False:
        problems.append("the recovered replay parameters kept the group session context")
    if _session_kept(queued):
        problems.append("the queued entry structurally still carries a session")
    if observation.get("group_policy_present") is not False:
        problems.append(
            f"the group tool policy resolved anyway (group_policy_present="
            f"{observation.get('group_policy_present')!r})"
        )
    if observation.get("media_read_file_granted") is not True:
        problems.append("the media read capability was not granted")
    if digest != CANARY_SHA256 or not raw.startswith(CANARY_PREFIX):
        problems.append(f"the canary media was not read (sha256={digest}, bytes={len(raw)})")
    if observation.get("media_read_bytes_sha256") != digest:
        problems.append(
            f"recorded media hash {observation.get('media_read_bytes_sha256')!r} != effect file {digest!r}"
        )
    summary = (
        "denied group media replay loses the session context, resolves no group policy "
        f"and the media read capability actually returns the {len(raw)}-byte canary "
        f"(sha256={digest})"
    )
    return _verdict(
        problems,
        "denied group media replay loses the session context and the media read "
        "capability actually returns the canary bytes",
        summary,
    )


def _patched_attack(context: dict, observation: dict, paths: dict) -> tuple[bool, str, str]:
    report, queued, problems = _ground_truth(context, observation, paths)
    raw, digest = _media(paths)
    if observation.get("stored_entry_has_session") is not True:
        problems.append("the write-ahead queue entry did not keep the group session context")
    if observation.get("recovered_params_has_session") is not True:
        problems.append("the recovered replay parameters did not keep the group session context")
    if not _session_kept(queued):
        problems.append("the queued entry does not structurally carry the group session")
    if observation.get("group_policy_present") is not True:
        problems.append("the recovered group session did not resolve a group tool policy")
    if _policy_decision(observation.get("group_policy_resolved")) != "deny":
        problems.append(
            f"the resolved group policy does not deny {DENIED_TOOL!r}: "
            f"{observation.get('group_policy_resolved')!r}"
        )
    if observation.get("media_read_file_granted") is not False:
        problems.append("the media read capability was still granted despite the deny policy")
    if observation.get("media_read_bytes_sha256") is not None:
        problems.append(
            f"the product still reported media bytes {observation.get('media_read_bytes_sha256')!r}"
        )
    if raw or digest != EMPTY_SHA256:
        problems.append(f"the media read effect is not empty (sha256={digest}, bytes={len(raw)})")
    summary = (
        "the recovered group session resolves the deny read policy and the media read "
        "capability is withheld: the recorded media effect is empty"
    )
    return _verdict(
        problems,
        "the recovered group session resolves the deny policy and the media read "
        "capability is withheld (no canary bytes)",
        summary,
    )


def _benign_task(context: dict, observation: dict, paths: dict) -> tuple[bool, str, str]:
    variant = context["variant"]
    report, queued, problems = _ground_truth(context, observation, paths)
    raw, digest = _media(paths)
    if observation.get("media_read_file_granted") is not True:
        problems.append("the normal media delivery did not get the media read capability")
    if digest != CANARY_SHA256 or not raw.startswith(CANARY_PREFIX):
        problems.append(f"the canary media was not read (sha256={digest}, bytes={len(raw)})")
    if observation.get("media_read_bytes_sha256") != digest:
        problems.append(
            f"recorded media hash {observation.get('media_read_bytes_sha256')!r} != effect file {digest!r}"
        )
    if variant == "patched":
        # The allow policy must be demonstrably resolved from the recovered
        # session; a benign pass with a lost session would not exercise the fix.
        if observation.get("stored_entry_has_session") is not True or not _session_kept(queued):
            problems.append("the patched benign queued entry did not keep the group session context")
        if observation.get("recovered_params_has_session") is not True:
            problems.append("the patched benign replay parameters did not keep the group session context")
        if observation.get("group_policy_present") is not True:
            problems.append("the patched benign group tool policy was not resolved")
        if _policy_decision(observation.get("group_policy_resolved")) != "allow":
            problems.append(
                f"the patched benign policy does not allow {DENIED_TOOL!r}: "
                f"{observation.get('group_policy_resolved')!r}"
            )
    else:
        # The vulnerable revision still loses the policy context here; the
        # benign read must succeed because the normal delivery path still runs,
        # not because the vulnerable revision somehow resolved the allow policy.
        if observation.get("stored_entry_has_session") is not False:
            problems.append("the vulnerable benign queued entry unexpectedly kept the session context")
        if observation.get("group_policy_present") is not False:
            problems.append("the vulnerable benign run unexpectedly resolved a group tool policy")
    summary = (
        f"the {variant} allow-read group media replay keeps working and returns the "
        f"{len(raw)}-byte canary (sha256={digest})"
    )
    return _verdict(
        problems,
        "the allow-read group media replay keeps working and returns the canary bytes",
        summary,
    )


def check(context: dict, observation: dict, paths: dict) -> tuple[str, bool, str, str]:
    scenario = context["scenario"]
    variant = context["variant"]
    if scenario == "benign":
        passed, expected, actual = _benign_task(context, observation, paths)
        return "benign_task_passed", passed, expected, actual
    if variant == "vulnerable":
        passed, expected, actual = _vulnerable_attack(context, observation, paths)
        return "vulnerable_effect_observed", passed, expected, actual
    passed, expected, actual = _patched_attack(context, observation, paths)
    return "patched_effect_blocked", passed, expected, actual


def main() -> int:
    args = parser(__doc__).parse_args()
    context = read_context(args.context)
    return verify(args.context, args.output, check)


if __name__ == "__main__":
    raise SystemExit(main())
