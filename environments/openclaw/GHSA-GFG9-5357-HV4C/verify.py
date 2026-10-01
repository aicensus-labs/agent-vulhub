"""Independent evidence verifier for GHSA-GFG9-5357-HV4C.

``reproduce.py`` drives the pinned upstream
``buildWebchatAudioContentBlocksFromReplyPayloads`` implementation and records
the exact value it returned plus the base64 payload of every returned audio
block.  This module never calls that function, never opens a network socket and
never runs a subprocess: it only reads the hash-checked ``observation.json`` and
the two declared effect files handed over through ``paths``.

The vulnerability is "a reply payload's ``mediaUrl`` is read from outside the
allowed local media roots".  So the discriminating evidence is the *content* of
the embedded audio, not a self-reported boolean:

  * vulnerable + attack  -> two audio blocks whose decoded bytes are byte-for-byte
    the two synthetic out-of-root fixture files; the pinned module has no
    containment check.
  * patched + attack     -> zero audio blocks, no out-of-root bytes anywhere, and
    the upstream ``onLocalAudioAccessDenied`` callback fired once per
    out-of-root target.
  * benign (both builds) -> exactly one audio block whose decoded bytes are
    byte-for-byte the in-root ``greeting`` fixture, and no denial.

Two independent cross-checks make forgery harder than editing an effect file:

  * the decoded bytes must equal the exact fixture literals below (not merely
    contain a marker substring), and
  * ``observation.json`` must report the SHA-256 of the pinned upstream module
    for the variant, matching the digest of the hash-pinned source archive named
    in ``metadata.toml`` ``build.inputs`` (so a mislabelled or substituted image
    cannot be presented as the vulnerable / patched revision).

The literals are the byte content of ``fixtures/*.mp3`` documented in
``fixtures/README.md``; the verifier compares decoded evidence against them and
cross-checks that ``media_blocks.json`` and ``embedded_audio_base64.txt`` agree.
"""

from __future__ import annotations

import base64
import binascii
import json

from lab_support import parser, read_context, verify

# Exact synthetic byte content of the fixture audio files, copied verbatim from
# fixtures/*.mp3 (fixtures/README.md, "Expected observable effects").  The
# verifier requires the decoded embedded bytes to equal these literals exactly,
# so appending garbage or a second marker cannot turn a failure into a pass.
VOICE_MEMO_AUDIO = (
    "AVH-SYNTHETIC-AUDIO-MARKER voice-memo\n"
    "GHSA-GFG9-5357-HV4C local audio file that lives OUTSIDE the allowed media root\n"
    "The vulnerable webchat audio embedding path embeds these bytes as base64.\n"
)
MEETING_NOTES_AUDIO = (
    "AVH-SYNTHETIC-AUDIO-MARKER meeting-notes\n"
    "GHSA-GFG9-5357-HV4C second out-of-root target, referenced through a file: URL\n"
    "instead of a plain absolute path.\n"
)
GREETING_AUDIO = (
    "AVH-SYNTHETIC-AUDIO-MARKER greeting\n"
    "GHSA-GFG9-5357-HV4C benign local audio file that lives INSIDE the allowed\n"
    "media root, so both revisions may embed it.\n"
)

OUT_OF_ROOT_AUDIO = (VOICE_MEMO_AUDIO, MEETING_NOTES_AUDIO)
IN_ROOT_AUDIO = GREETING_AUDIO

# First line of each fixture, used for the human-readable summary only.
OUT_OF_ROOT_MARKERS = tuple(text.splitlines()[0] for text in OUT_OF_ROOT_AUDIO)
IN_ROOT_MARKER = IN_ROOT_AUDIO.splitlines()[0]

# SHA-256 of the pinned upstream module
# ``src/gateway/server-methods/chat-webchat-media.ts`` inside each image,
# computed from the hash-pinned archives in metadata.toml ``build.inputs``:
#   vulnerable = v2026.4.14 = 323493fa1b6adc1e10b9954a68d5eaa5a6ef1170
#   patched    = v2026.4.15 = 041266a6699cac3baef8ef39db41fa26f29f9db3 (the fix)
MODULE_SHA256 = {
    "vulnerable": "c917223f6541607c25d608fe0aa9f956c1b6028ec2c49a6258125141fa922e29",
    "patched": "051b717f91b8976ff4f1da062ce0c4970fcaab734378fc519da47318b996b1e1",
}

CHECK_IDS = {
    ("vulnerable", "attack"): "vulnerable_effect_observed",
    ("patched", "attack"): "patched_effect_blocked",
}


def _check_id(variant: str, scenario: str) -> str:
    if scenario == "benign":
        return "benign_task_passed"
    return CHECK_IDS.get((variant, scenario), "vulnerable_effect_observed")


def _under(child: str, root: str) -> bool:
    """True when the absolute container path ``child`` lives under ``root``."""
    child = child.rstrip("/")
    root = root.rstrip("/")
    return child == root or child.startswith(root + "/")


def _out_of_root(paths, roots) -> list[str]:
    return [p for p in paths if not any(_under(p, r) for r in roots)]


def _decode_payloads(text: str) -> tuple[list[str], list[str], str | None]:
    """Return (raw base64 lines, decoded line contents, error) for the effect file."""
    payloads = [line.strip() for line in text.splitlines() if line.strip()]
    decoded: list[str] = []
    for index, payload in enumerate(payloads):
        try:
            raw = base64.b64decode(payload, validate=True)
        except (binascii.Error, ValueError) as error:
            return [], [], "payload %d is not valid base64: %s" % (index, error)
        decoded.append(raw.decode("utf-8", errors="replace"))
    return payloads, decoded, None


def _gather(observation, paths):
    """Return a normalised evidence view, or ``(None, reason)`` when unusable."""
    for name in ("media_blocks.json", "embedded_audio_base64.txt"):
        if name not in paths:
            return None, "declared effect file missing from hash-checked evidence: " + name
    try:
        document = json.loads(paths["media_blocks.json"].read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return None, "media_blocks.json is not readable JSON: %s" % error
    if not isinstance(document, dict):
        return None, "media_blocks.json is not a JSON object"
    blocks = document.get("blocks")
    denied = document.get("denied_local_audio_access")
    if not isinstance(blocks, list) or not isinstance(denied, list):
        return None, "media_blocks.json lacks blocks / denied_local_audio_access lists"

    block_payloads: list[str] = []
    block_media_types: list[str] = []
    for index, block in enumerate(blocks):
        source = block.get("source") if isinstance(block, dict) else None
        if not isinstance(source, dict) or not isinstance(source.get("data"), str):
            return None, "block %d has no base64 source.data" % index
        block_payloads.append(source["data"])
        block_media_types.append(source.get("media_type"))

    text = paths["embedded_audio_base64.txt"].read_text(encoding="utf-8")
    file_payloads, file_text, decode_error = _decode_payloads(text)
    if decode_error:
        return None, decode_error

    decoded_blocks: list[str] = []
    for index, payload in enumerate(block_payloads):
        try:
            decoded_blocks.append(
                base64.b64decode(payload, validate=True).decode("utf-8", errors="replace")
            )
        except (binascii.Error, ValueError) as error:
            return None, "block %d payload cannot be decoded as text: %s" % (index, error)

    return {
        "blocks": blocks,
        "denied": [str(item) for item in denied],
        "block_payloads": block_payloads,
        "block_media_types": block_media_types,
        "block_text": decoded_blocks,
        "file_payloads": file_payloads,
        "file_text": file_text,
    }, None


def _find_markers(texts) -> set[str]:
    joined = "\n".join(texts)
    return {marker for marker in OUT_OF_ROOT_MARKERS if marker in joined}


def _summary(observation, view) -> dict:
    return {
        "variant": observation.get("variant"),
        "scenario": observation.get("scenario"),
        "audio_content_blocks": observation.get("audio_content_blocks"),
        "media_types": observation.get("media_types"),
        "denied_local_audio_access": observation.get("denied_local_audio_access"),
        "upstream_calls_containment_check": observation.get("upstream_calls_containment_check"),
        "upstream_module_sha256": observation.get("upstream_module_sha256"),
        "expected_module_sha256": MODULE_SHA256.get(str(observation.get("variant"))),
        "evidence_block_count": len(view["blocks"]),
        "evidence_payload_count": len(view["file_payloads"]),
        "evidence_markers": sorted(_find_markers(view["file_text"])),
        "evidence_is_exact_fixture_bytes": (
            sorted(view["file_text"]) == sorted(OUT_OF_ROOT_AUDIO)
            if observation.get("scenario") == "attack"
            else view["file_text"] == [IN_ROOT_AUDIO]
        ),
        "allowed_local_roots": observation.get("allowed_local_roots"),
        "materialized_paths": observation.get("materialized_paths"),
    }


def check(context, observation, paths):
    check_id = _check_id(context["variant"], context["scenario"])
    variant = context["variant"]
    scenario = context["scenario"]

    view, reason = _gather(observation, paths)
    if view is None:
        return (check_id, False, "readable hash-checked effect evidence", reason)

    actual = json.dumps(_summary(observation, view), ensure_ascii=False, sort_keys=True)

    base_problems = []
    if observation.get("variant") != variant:
        base_problems.append("observation variant %r != context variant %r"
                             % (observation.get("variant"), variant))
    if observation.get("scenario") != scenario:
        base_problems.append("observation scenario %r != context scenario %r"
                             % (observation.get("scenario"), scenario))
    if observation.get("target_ready") is not True:
        base_problems.append("target_ready is not true")
    if observation.get("execution_status") != "completed":
        base_problems.append("execution_status is not completed")
    if base_problems:
        return (check_id, False, "PoC recorded completed execution of the pinned mechanism",
                "; ".join(base_problems))

    roots = [str(r) for r in (observation.get("allowed_local_roots") or [])]
    materialized = [str(p) for p in (observation.get("materialized_paths") or [])]
    outside = _out_of_root(materialized, roots)

    problems = []

    # The evidence must come from the pinned revision this variant claims: the
    # digest is that of the module inside the hash-pinned source archive.
    if observation.get("upstream_module_sha256") != MODULE_SHA256[variant]:
        problems.append(
            "upstream module sha256 %r does not match the pinned %s revision %s"
            % (observation.get("upstream_module_sha256"), variant, MODULE_SHA256[variant])
        )

    # Both effect files must describe the same call result.
    if view["block_payloads"] != view["file_payloads"]:
        problems.append("media_blocks.json payloads disagree with embedded_audio_base64.txt")
    if view["block_text"] != view["file_text"]:
        problems.append("decoded block bytes disagree with embedded_audio_base64.txt")
    if observation.get("denied_local_audio_access") != view["denied"]:
        problems.append("observation denials disagree with media_blocks.json denials")

    leaked = _find_markers(view["file_text"])

    if scenario == "attack" and variant == "vulnerable":
        if observation.get("upstream_calls_containment_check") is not False:
            problems.append("pinned module unexpectedly calls assertLocalMediaAllowed")
        if not outside:
            problems.append("no materialized target lies outside the allowed roots")
        if len(view["blocks"]) != len(outside):
            problems.append("expected %d audio block(s), observed %d"
                            % (len(outside), len(view["blocks"])))
        if len(view["file_payloads"]) != len(outside):
            problems.append("expected %d embedded payload(s), observed %d"
                            % (len(outside), len(view["file_payloads"])))
        if leaked != set(OUT_OF_ROOT_MARKERS) or sorted(view["file_text"]) != sorted(OUT_OF_ROOT_AUDIO):
            problems.append("decoded audio bytes are not exactly the two out-of-root fixture "
                            "files (markers %s): %r"
                            % (sorted(leaked), view["file_text"]))
        if view["denied"]:
            problems.append("vulnerable build reported a local media denial")
        if observation.get("audio_content_blocks") != len(view["blocks"]):
            problems.append("observation block count disagrees with media_blocks.json")
        if any(item != "audio/mpeg" for item in view["block_media_types"]):
            problems.append("unexpected media types: %s" % view["block_media_types"])
        expected_text = ("vulnerable attack embeds the bytes of every out-of-root audio "
                         "target (%d blocks, markers %s) and denies nothing"
                         % (len(outside), list(OUT_OF_ROOT_MARKERS)))

    elif scenario == "attack" and variant == "patched":
        if observation.get("upstream_calls_containment_check") is not True:
            problems.append("pinned module does not call assertLocalMediaAllowed")
        if not outside:
            problems.append("no materialized target lies outside the allowed roots")
        if view["blocks"]:
            problems.append("patched build still returned %d audio block(s)" % len(view["blocks"]))
        if view["file_payloads"]:
            problems.append("patched build still embedded %d payload(s)" % len(view["file_payloads"]))
        if leaked:
            problems.append("patched build leaked out-of-root markers: %s" % sorted(leaked))
        if len(view["denied"]) != len(outside):
            problems.append("expected %d denial callback(s) for %d out-of-root target(s), observed %d"
                            % (len(outside), len(outside), len(view["denied"])))
        if any(not item for item in view["denied"]):
            problems.append("denial callback reported an empty error code")
        if observation.get("audio_content_blocks") != 0:
            problems.append("observation reports audio_content_blocks=%r"
                            % observation.get("audio_content_blocks"))
        expected_text = ("patched attack returns no audio block, embeds no out-of-root bytes "
                         "and reports one denial per rejected target (%d)" % len(outside))

    elif scenario == "benign":
        if not materialized or _out_of_root(materialized, roots):
            problems.append("benign target is not inside the allowed roots")
        if len(view["blocks"]) != 1:
            problems.append("expected exactly 1 audio block, observed %d" % len(view["blocks"]))
        if len(view["file_payloads"]) != 1:
            problems.append("expected exactly 1 embedded payload, observed %d"
                            % len(view["file_payloads"]))
        if view["file_text"] != [IN_ROOT_AUDIO]:
            problems.append("decoded audio bytes are not exactly the in-root greeting "
                            "fixture file: %r" % view["file_text"])
        if leaked:
            problems.append("benign run leaked out-of-root markers: %s" % sorted(leaked))
        if view["denied"]:
            problems.append("benign run reported a local media denial: %s" % view["denied"])
        if observation.get("audio_content_blocks") != 1:
            problems.append("observation reports audio_content_blocks=%r"
                            % observation.get("audio_content_blocks"))
        if any(item != "audio/mpeg" for item in view["block_media_types"]):
            problems.append("unexpected media types: %s" % view["block_media_types"])
        expected_text = ("benign reply still embeds the single in-root audio file "
                         "(marker %r) with no denial" % IN_ROOT_MARKER)

    else:  # pragma: no cover - read_context rejects other combinations
        return (check_id, False, "a known (variant, scenario) pair",
                "unsupported combination %r/%r" % (variant, scenario))

    if problems:
        return (check_id, False, expected_text, "; ".join(problems) + " | " + actual)
    return (check_id, True, expected_text, actual)


def main() -> int:
    args = parser(__doc__).parse_args()
    read_context(args.context)
    return verify(args.context, args.output, check)


if __name__ == "__main__":
    raise SystemExit(main())
