"""Mechanism reproduction: n8n agent node tool executed for a Project Viewer.

Drives the pinned n8n source tree inside the image. The vulnerable and patched
images carry the same entrypoint and differ only in the checked-out revision, so
the release that runs decides the outcome:

  * ``npm/n8n`` 2.29.7 (vulnerable) rebuilds the agent runtime without consulting
    the caller, so a Project Viewer's node tool ref survives reconstruction and
    its handler reaches ``EphemeralNodeExecutor.executeInline`` with the baked
    credential details and node parameters.
  * ``npm/n8n`` 2.29.8 (patched) filters node tool refs through ``filterToolsForUser``
    (``workflow:execute`` plus ``credential:read``) before the runtime is built,
    so the same ref never produces a tool and the executor is never called.

The Node harness loads the real ``AgentRuntimeReconstructionService`` and
``resolveNodeTool`` from the image's source tree through a small ESM loader. It
supplies storage/DI doubles only; no authorization logic is reimplemented here.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from lab_support import parser, read_context, record

SOURCE_ROOT = Path(os.environ.get("N8N_SOURCE_ROOT", "/lab/app"))
FIXTURE_ROOT = Path(os.environ.get("N8N_FIXTURE_ROOT", "/lab/fixtures"))
HARNESS = FIXTURE_ROOT / "n8n_harness.mjs"
LOADER = FIXTURE_ROOT / "n8n_loader.mjs"
DOUBLES = FIXTURE_ROOT / "n8n_doubles.mjs"
NODE_CANDIDATES = ("/opt/node/bin/node", "/usr/local/bin/node", "/usr/bin/node", "node")


def node_binary() -> str:
    """Return the interpreter that ships with the image, or fail loudly."""
    for candidate in NODE_CANDIDATES:
        found = candidate if os.path.isabs(candidate) else shutil.which(candidate)
        if found and os.path.exists(found):
            return found
    raise FileNotFoundError("no node interpreter in the image")


def fixture_name(scenario: str, variant: str) -> str:
    """Pick the fixture, keeping the release's own call shape for attacks."""
    if scenario == "attack":
        return f"attack-{variant}.json"
    return "benign.json"


def run_harness(context: dict, output: Path) -> dict:
    fixture = FIXTURE_ROOT / fixture_name(context["scenario"], context["variant"])
    raw = output / "harness-observation.json"
    environment = {
        **os.environ,
        "N8N_SOURCE_ROOT": str(SOURCE_ROOT),
        "N8N_DOUBLES": str(DOUBLES),
        "N8N_FIXTURE": str(fixture),
        "N8N_OUTPUT": str(raw),
        "N8N_VARIANT": context["variant"],
        "N8N_SCENARIO": context["scenario"],
    }
    completed = subprocess.run(
        [node_binary(), "--experimental-transform-types", "--import", str(LOADER), str(HARNESS)],
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
    )
    sys.stderr.write(completed.stdout[-4000:])
    sys.stderr.write(completed.stderr[-4000:])
    if not raw.is_file():
        return {
            "mechanism_loaded": False,
            "execution_status": "failed",
            "detail": f"harness exited {completed.returncode}",
        }
    observation = json.loads(raw.read_text(encoding="utf-8"))
    observation["harness_exit_code"] = completed.returncode
    return observation


def summarize(scenario: str, observation: dict) -> dict:
    """Reduce the harness record to the facts the effect is judged on."""
    calls = observation.get("executor_calls", [])
    return {
        "mechanism_loaded": bool(observation.get("mechanism_loaded")),
        "scenario": scenario,
        "filter_tools_for_user_present": observation.get("filter_tools_for_user_present"),
        "resolved_tool_names": [tool["name"] for tool in observation.get("resolved_tools", [])],
        "resolved_tool_kinds": [tool["kind"] for tool in observation.get("resolved_tools", [])],
        "executor_node_types": [call["nodeType"] for call in calls],
        "executor_credential_ids": sorted(
            detail["id"]
            for call in calls
            for detail in (call.get("credentialDetails") or {}).values()
            if isinstance(detail, dict) and detail.get("id")
        ),
        "executor_node_parameters": [call.get("nodeParameters") for call in calls],
        "node_tool_invoked": bool(observation.get("node_tool_invocations")),
        "node_tool_results": [entry.get("result") for entry in observation.get("node_tool_invocations", [])],
    }


def main() -> int:
    args = parser(__doc__).parse_args()
    context = read_context(args.context)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    try:
        loaded = SOURCE_ROOT / "packages/cli/src/modules/agents/agent-runtime-reconstruction.service.ts"
        target_ready = loaded.is_file() and HARNESS.is_file() and DOUBLES.is_file()
        if not target_ready:
            detail = f"pinned source or harness missing under {SOURCE_ROOT}"
            effect = {"mechanism_loaded": False, "detail": detail}
            observation = {
                "target_ready": False,
                "execution_status": "failed",
                "detail": detail,
                "scenario": context["scenario"],
                "variant": context["variant"],
            }
            return record(context, args.output, observation, {"effect.json": json.dumps(effect, indent=2) + "\n"})

        harness_observation = run_harness(context, output)
        effect = summarize(context["scenario"], harness_observation)
        status = "completed" if harness_observation.get("mechanism_loaded") else "failed"
        observation = {
            "target_ready": target_ready,
            "execution_status": status,
            "scenario": context["scenario"],
            "variant": context["variant"],
            "source_revision_root": str(SOURCE_ROOT),
            **effect,
        }
        effects = {
            "effect.json": json.dumps(effect, ensure_ascii=False, indent=2) + "\n",
            "harness-observation.json": json.dumps(harness_observation, ensure_ascii=False, indent=2) + "\n",
        }
        return record(context, args.output, observation, effects)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        observation = {
            "target_ready": False,
            "execution_status": "failed",
            "scenario": context["scenario"],
            "variant": context["variant"],
            "error": str(error),
        }
        return record(context, args.output, observation, {"effect.json": "{}\n"})


if __name__ == "__main__":
    raise SystemExit(main())
