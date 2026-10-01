"""Independent effect checks for the Flowise MCP security bypass.

GHSA-M99R-2HXC-CP3Q: the Custom MCP node hands attacker-controlled server
parameters to the real upstream chain

    validateMCPServerConfig(serverParams)   # the only gate
      -> new MCPToolkit(serverParams, 'stdio')
      -> toolkit.initialize()               # opens StdioClientTransport
      -> StdioClientTransport(params)       # spawn(command, args)

The vulnerable build's local-file rule is ``/^\\/[^/]/``, so a ``//``-prefixed
path escapes it and an arbitrary local script is executed by a real child
process.  Only ``facts.json``, ``observation.json`` and the hash-checked effect
files produced by ``reproduce.py`` are read here; the pinned upstream code is
never invoked again.

The three checks map to the cases the runner exercises:

* ``attack`` on the vulnerable build: the double-slash config passes the gate and
  the pre-staged JavaScript is executed by a spawned child, which writes the
  fixed marker; the ordinary absolute-path control is still rejected and the
  other two documented bypasses are still accepted.
* ``attack`` on the patched build: the same config is rejected before any
  transport exists, no child and no marker file are produced, and all three
  bypasses are denied.
* ``benign`` on either build: the legitimate relative-path stdio server passes
  the gate and completes a real MCP handshake and tool round trip without
  writing any marker.
"""

from __future__ import annotations

import json

from lab_support import parser, read_context, verify

CHILD_EFFECT = ".ghsa-mcp-child-effect.txt"
HARNESS_RESULT = "harness_result.json"
RESOLVED_CONFIG = "resolved_mcp_config.json"

MARKER_PREFIX = "ghsa-mcp-stdio-child-executed"
PAYLOAD_NAME = "mcp_payload.js"
ATTACK_PATH = "//lab/fixtures/mcp_payload.js"
# node normalises the script operand with path.resolve(), so the spawned child
# reports the payload as an ordinary absolute path with a single leading slash.
# Requiring the *whole* marker line pins the effect to the exact staged script
# instead of accepting any text that merely mentions the file name.
CHILD_MARKER_LINE = f"{MARKER_PREFIX} /lab/fixtures/mcp_payload.js"
# The legitimate stdio server the benign scenario is supposed to drive.
BENIGN_PATH = "mcp_server.js"

# Every config the advisory documents as a bypass of the same gate.  The runner
# evaluates all three against the loaded build; the patched build must deny all.
BYPASS_IDS = (
    "rce_local_file_via_double_slash",
    "docker_build_remote_context",
    "npx_yes_remote_package",
)

BENIGN_TOOL = "ghsa_echo"
BENIGN_TEXT = "ghsa-benign-round-trip"


def _read_json(effects: dict, name: str):
    path = effects.get(name)
    if path is None:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _read_text(effects: dict, name: str):
    path = effects.get(name)
    if path is None:
        return None
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _bypasses(harness) -> dict:
    allowed = {}
    for item in (harness or {}).get("bypass_assertions") or []:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            allowed[item["id"]] = item.get("allowed") is True
    return allowed


def _marker_line(marker) -> str | None:
    return marker.strip() if isinstance(marker, str) else None


def _attack_actual(harness, config, marker, observation) -> str:
    return (
        f"validation={(harness or {}).get('validation')!r} "
        f"negative_control={(harness or {}).get('negative_control')!r} "
        f"bypasses={_bypasses(harness)!r} "
        f"command={(config or {}).get('command')!r} "
        f"args={(config or {}).get('args')!r} "
        f"child_process_executed={observation.get('child_process_executed')!r} "
        f"marker={marker!r}"
    )


def check(context: dict, observation: dict, effects: dict) -> tuple[str, bool, str, str]:
    harness = _read_json(effects, HARNESS_RESULT)
    config = _read_json(effects, RESOLVED_CONFIG)
    marker = _read_text(effects, CHILD_EFFECT)
    allowed = _bypasses(harness)
    scenario = context["scenario"]
    variant = context["variant"]

    if scenario == "attack" and variant == "vulnerable":
        passed = (
            isinstance(harness, dict)
            and harness.get("validation") == "accepted"
            and harness.get("negative_control") == "rejected"
            and set(allowed) == set(BYPASS_IDS)
            and all(allowed.get(name) is True for name in BYPASS_IDS)
            and isinstance(config, dict)
            and config.get("command") == "node"
            and list(config.get("args") or []) == [ATTACK_PATH]
            and isinstance(marker, str)
            and _marker_line(marker) == CHILD_MARKER_LINE
            and PAYLOAD_NAME in marker
            and observation.get("validation") == "accepted"
            and observation.get("resolved_command") == "node"
            and list(observation.get("resolved_args") or []) == [ATTACK_PATH]
            and observation.get("child_effect") == marker
            and observation.get("child_process_executed") is True
        )
        return (
            "vulnerable_effect_observed",
            passed,
            "The double-slash stdio config passes validateMCPServerConfig and a real "
            "spawned child writes the fixed marker, while a normal absolute path is "
            "still rejected and the docker/npx bypasses are still accepted.",
            _attack_actual(harness, config, marker, observation),
        )

    if scenario == "attack" and variant == "patched":
        rejection = harness.get("validation_error") if isinstance(harness, dict) else None
        passed = (
            isinstance(harness, dict)
            and harness.get("validation") == "rejected"
            and isinstance(rejection, str)
            and rejection.strip() != ""
            and ATTACK_PATH in rejection
            and harness.get("negative_control") == "rejected"
            and set(allowed) == set(BYPASS_IDS)
            and all(value is False for value in allowed.values())
            and harness.get("tools") is None
            and harness.get("tool_call_result") is None
            and marker is None
            and isinstance(config, dict)
            and config.get("command") == "node"
            and list(config.get("args") or []) == [ATTACK_PATH]
            and observation.get("validation") == "rejected"
            and list(observation.get("resolved_args") or []) == [ATTACK_PATH]
            and observation.get("child_process_executed") is not True
        )
        return (
            "patched_effect_blocked",
            passed,
            "The double-slash config and the docker/npx bypasses are rejected before any "
            "transport is created, so no child process runs and no marker file exists.",
            f"{_attack_actual(harness, config, marker, observation)} "
            f"validation_error={str(rejection)[:160]!r} "
            f"tools={(harness or {}).get('tools')!r}",
        )

    tools = harness.get("tools") if isinstance(harness, dict) else None
    round_trip = harness.get("tool_call_result") if isinstance(harness, dict) else None
    passed = (
        isinstance(harness, dict)
        and harness.get("validation") == "accepted"
        and harness.get("validation_error") is None
        and harness.get("negative_control") == "rejected"
        and harness.get("toolkit_error") is None
        and isinstance(tools, list)
        and BENIGN_TOOL in tools
        and round_trip is not None
        and BENIGN_TEXT in str(round_trip)
        and isinstance(config, dict)
        and config.get("command") == "node"
        and list(config.get("args") or []) == [BENIGN_PATH]
        and observation.get("resolved_command") == "node"
        and list(observation.get("resolved_args") or []) == [BENIGN_PATH]
        and marker is None
        and observation.get("benign_task_ok") is True
        and observation.get("child_process_executed") is not True
    )
    return (
        "benign_task_passed",
        passed,
        "The legitimate relative-path stdio server passes the gate and completes a real "
        "MCP handshake and ghsa_echo round trip without writing any marker.",
        f"validation={(harness or {}).get('validation')!r} "
        f"negative_control={(harness or {}).get('negative_control')!r} "
        f"tools={tools!r} toolkit_error={(harness or {}).get('toolkit_error')!r} "
        f"round_trip={str(round_trip)[:120]!r} "
        f"benign_task_ok={observation.get('benign_task_ok')!r} marker={marker!r}",
    )


def main() -> int:
    args = parser(__doc__).parse_args()
    return verify(args.context, args.output, check)


if __name__ == "__main__":
    raise SystemExit(main())
