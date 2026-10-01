"""Mechanism PoC for grackle/GHSA-F9FF-5X35-7GFW (MCP tool-layer fail-open authorization).

The pinned upstream package @grackle-ai/mcp is loaded from the image and driven
through the same steps the real dispatcher performs for a `tools/call`:

  1. the caller presents its own scoped token, minted and verified by the
     package's own `createScopedToken` / `authenticateMcpRequest`;
  2. the tool is resolved with the package's own `resolveToolForAuth` against the
     persona's allowed tool set;
  3. if the revision ships the central gate, `enforceReadMembership` and
     `enforceToolScope` run before Zod validation and the handler, exactly as in
     the dispatcher (`mcp-server.js`);
  4. the tool's own Zod schema validates the arguments;
  5. the tool's own `handler` is invoked with the package's own client objects.

Step 3 is the only glue: `createMcpServerInstance` (the function that owns the
dispatcher order) is not exported by the package, so the two central checks are
called directly, in the upstream order, instead of over MCP-over-HTTP. The
dispatcher also injects `rawArgs.workspaceId` from the scoped token before the
gate; that step is omitted here because every probed tool's Zod schema has no
`workspaceId` field and strips unknown keys, and the gate reads
`authContext.workspaceId` rather than the argument, so it cannot change the
authorization decision. No upstream authorization logic is copied or
reimplemented: on the vulnerable revision the package exports neither
`enforceToolScope` nor `enforceReadMembership`, so the gate is a no-op there and
the tool handler executes unchecked — which is the bug.

The gRPC backend is an in-memory double. It plays the backend's real role on the
chain (it receives the RPC and applies the mutation) without replacing the
upstream code under test; every RPC it receives is recorded as the observable
effect.

Everything here uses synthetic data only.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from lab_support import parser, read_context, record

FIXTURES = Path(os.environ.get("GRACKLE_FIXTURES", "/lab/fixtures"))
NODE = os.environ.get("GRACKLE_NODE", "node")
TIMEOUT_SECONDS = int(os.environ.get("GRACKLE_POC_TIMEOUT", "300"))

DRIVER = r'''
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const inputPath = process.argv[2];
const outputPath = process.argv[3];
const input = JSON.parse(readFileSync(inputPath, "utf8"));

const report = {
  ok: false,
  target_ready: false,
  package: null,
  scope_enforcement_module_present: false,
  central_scope_gate_present: false,
  probes: [],
  fatal: null,
};

function persist() {
  writeFileSync(outputPath, JSON.stringify(report, null, 2) + "\n", "utf8");
}

function stop(message) {
  report.fatal = String(message).slice(0, 1000);
  persist();
  process.exit(0);
}

function looksLikePackage(dir) {
  if (!dir || !existsSync(path.join(dir, "package.json"))) return false;
  if (!existsSync(path.join(dir, "dist", "index.js"))) return false;
  try {
    return JSON.parse(readFileSync(path.join(dir, "package.json"), "utf8")).name === "@grackle-ai/mcp";
  } catch {
    return false;
  }
}

function findPackageDir() {
  const direct = [];
  if (process.env.GRACKLE_MCP_DIR) direct.push(process.env.GRACKLE_MCP_DIR);
  for (const root of ["/lab/app", "/lab", "/opt/grackle", "/srv/grackle", "/app", "/workspace"]) {
    direct.push(path.join(root, "node_modules", "@grackle-ai", "mcp"));
    direct.push(path.join(root, "packages", "mcp"));
  }
  for (const dir of direct) {
    if (looksLikePackage(dir)) return dir;
  }

  const found = [];
  const queue = ["/lab", "/opt", "/app", "/workspace", "/usr/local/lib"];
  const seen = new Set();
  let budget = 5000;
  while (queue.length > 0 && budget > 0) {
    const dir = queue.shift();
    if (seen.has(dir)) continue;
    seen.add(dir);
    budget -= 1;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name === ".git" || entry.name === ".cache") continue;
      const full = path.join(dir, entry.name);
      if (entry.name === "mcp" && path.basename(dir) === "@grackle-ai") found.push(full);
      queue.push(full);
    }
  }
  for (const dir of found) {
    if (looksLikePackage(dir)) return dir;
  }
  return null;
}

const CODE_NAMES = {
  3: "INVALID_ARGUMENT",
  5: "NOT_FOUND",
  7: "PERMISSION_DENIED",
  16: "UNAUTHENTICATED",
};

function describeError(error) {
  if (error === null || error === undefined) return null;
  const code = typeof error.code === "number" ? error.code : null;
  return {
    name: error.name ? String(error.name) : null,
    code,
    code_name: code !== null ? (CODE_NAMES[code] ?? "CODE_" + code) : null,
    message: String(error.message ?? error).slice(0, 600),
  };
}

function firstText(result) {
  const content = result && Array.isArray(result.content) ? result.content : [];
  return content
    .filter((item) => item && typeof item.text === "string")
    .map((item) => item.text)
    .join("\n")
    .slice(0, 2000);
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function createBackend(environment) {
  const tasks = new Map(environment.tasks.map((task) => [task.id, clone(task)]));
  const sessions = new Map(environment.sessions.map((session) => [session.id, clone(session)]));
  const effects = [];
  const note = (method, request) => effects.push({ method, request: clone(request) });
  const missing = (kind, id) => new Error(kind + " not found: " + id);
  return {
    effects,
    clients: {
      core: {
        async getSession(request) {
          note("core.getSession", request);
          const session = sessions.get(request.id);
          if (!session) throw missing("session", request.id);
          return clone(session);
        },
        async killAgent(request) {
          note("core.killAgent", request);
          const session = sessions.get(request.id);
          if (!session) throw missing("session", request.id);
          session.status = "killed";
          return {};
        },
        async resumeAgent(request) {
          note("core.resumeAgent", request);
          return {};
        },
      },
      orchestration: {
        async getTask(request) {
          note("orchestration.getTask", request);
          const task = tasks.get(request.id);
          if (!task) throw missing("task", request.id);
          return clone(task);
        },
        async listTasks(request) {
          note("orchestration.listTasks", request);
          return { tasks: Array.from(tasks.values()).map(clone) };
        },
        async updateTask(request) {
          note("orchestration.updateTask", request);
          const task = tasks.get(request.id);
          if (!task) throw missing("task", request.id);
          if (typeof request.title === "string" && request.title) task.title = request.title;
          if (typeof request.description === "string" && request.description) task.description = request.description;
          if (typeof request.status === "number" && request.status !== 0) task.status = request.status;
          if (Array.isArray(request.dependsOn) && request.dependsOn.length > 0) task.dependsOn = clone(request.dependsOn);
          if (typeof request.sessionId === "string" && request.sessionId) task.sessionId = request.sessionId;
          return clone(task);
        },
        async deleteTask(request) {
          note("orchestration.deleteTask", request);
          if (!tasks.has(request.id)) throw missing("task", request.id);
          tasks.delete(request.id);
          return {};
        },
        async resumeTask(request) {
          note("orchestration.resumeTask", request);
          return {};
        },
        async getPersona(request) {
          note("orchestration.getPersona", request);
          return { id: request.id, allowedMcpTools: environment.persona.allowed_mcp_tools };
        },
      },
      scheduling: {},
      knowledge: {},
    },
    snapshot() {
      return {
        tasks: Object.fromEntries(Array.from(tasks.entries()).map(([id, task]) => [id, clone(task)])),
        sessions: Object.fromEntries(Array.from(sessions.entries()).map(([id, session]) => [id, clone(session)])),
      };
    },
  };
}

const packageDir = findPackageDir();
if (!packageDir) {
  stop("pinned @grackle-ai/mcp package not found (searched /lab, /opt, /app, /workspace, /usr/local/lib and GRACKLE_MCP_DIR)");
}

report.package = { dir: packageDir, version: null };
try {
  report.package.version = JSON.parse(readFileSync(path.join(packageDir, "package.json"), "utf8")).version ?? null;
} catch {
  /* version is informational only */
}

let upstream;
try {
  upstream = { index: await import(pathToFileURL(path.join(packageDir, "dist", "index.js")).href) };
  try {
    upstream.scoping = await import(pathToFileURL(path.join(packageDir, "dist", "tool-scoping.js")).href);
  } catch {
    upstream.scoping = null;
  }
  try {
    upstream.enforcement = await import(pathToFileURL(path.join(packageDir, "dist", "scope-enforcement.js")).href);
  } catch {
    upstream.enforcement = null;
  }
} catch (error) {
  stop("cannot import the pinned package: " + describeError(error).message);
}

report.scope_enforcement_module_present = Boolean(upstream.enforcement);
report.central_scope_gate_present = typeof upstream.enforcement?.enforceToolScope === "function";

const registry = upstream.index.createToolRegistry();
const allowedTools = new Set(input.environment.persona.allowed_mcp_tools);

function buildAuth(actor) {
  const claims = input.environment.scoped_token_claims;
  const apiKey = input.environment.api_key;
  if (actor === "api_key") {
    return upstream.index.authenticateMcpRequest({ headers: { authorization: "Bearer " + apiKey } }, apiKey);
  }
  const token = upstream.index.createScopedToken(
    { sub: claims.sub, pid: claims.pid, per: claims.per, sid: claims.sid },
    apiKey,
  );
  return upstream.index.authenticateMcpRequest({ headers: { authorization: "Bearer " + token } }, apiKey);
}

for (const probe of input.probes) {
  const backend = createBackend(input.environment);
  const entry = {
    id: probe.id,
    tool: probe.tool,
    actor: probe.actor,
    args: clone(probe.args),
    target: probe.target ?? null,
    auth: null,
    tool_permitted: null,
    tool_scope: null,
    arguments_valid: null,
    central_gate_present: report.central_scope_gate_present,
    gate_denied: null,
    gate_error: null,
    handler_invoked: false,
    handler_is_error: null,
    handler_text: null,
    handler_error: null,
    backend_effects: [],
    backend_state: null,
    error: null,
  };
  try {
    const auth = buildAuth(probe.actor);
    entry.auth = auth
      ? {
          type: auth.type,
          taskId: auth.taskId ?? null,
          workspaceId: auth.workspaceId ?? null,
          personaId: auth.personaId ?? null,
        }
      : null;
    if (!auth) throw new Error("the pinned package rejected the probe identity");

    let tool = null;
    if (typeof upstream.scoping?.resolveToolForAuth === "function") {
      tool = upstream.scoping.resolveToolForAuth(registry, probe.tool, auth, allowedTools) ?? null;
    } else {
      const candidate = registry.get(probe.tool);
      tool = candidate && (auth.type !== "scoped" || allowedTools.has(candidate.name)) ? candidate : null;
    }
    entry.tool_permitted = Boolean(tool);

    if (tool) {
      entry.tool_scope = tool.scope ? clone(tool.scope) : null;
      // Dispatcher order (mcp-server.js): the central, fail-closed gate runs
      // BEFORE Zod validation and the handler. On the vulnerable revision neither
      // export exists, so this block is a no-op and the handler below executes
      // unchecked — which is the bug.
      try {
        if (typeof upstream.enforcement?.enforceReadMembership === "function") {
          await upstream.enforcement.enforceReadMembership(backend.clients, tool.name, auth, probe.args);
        }
        if (typeof upstream.enforcement?.enforceToolScope === "function") {
          await upstream.enforcement.enforceToolScope(backend.clients, tool, auth, probe.args);
        }
        entry.gate_denied = false;
      } catch (error) {
        entry.gate_denied = true;
        entry.gate_error = describeError(error);
      }
      if (entry.gate_denied === false) {
        const parsed = tool.inputSchema.safeParse(probe.args);
        entry.arguments_valid = parsed.success === true;
        if (!parsed.success) {
          entry.error = "arguments rejected by the tool's own zod schema";
        } else {
          try {
            const result = await tool.handler(parsed.data, backend.clients, auth);
            entry.handler_invoked = true;
            entry.handler_is_error = result && result.isError === true;
            entry.handler_text = firstText(result);
          } catch (error) {
            entry.handler_invoked = true;
            entry.handler_error = describeError(error);
          }
        }
      }
    }
  } catch (error) {
    entry.error = describeError(error)?.message ?? String(error);
  }
  entry.backend_effects = backend.effects;
  entry.backend_state = backend.snapshot();
  report.probes.push(entry);
}

report.ok =
  report.probes.length > 0 &&
  report.probes.every((entry) => entry.handler_invoked === true || entry.gate_denied === true);
report.target_ready = report.ok;
persist();
'''


def _read_json(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def main() -> int:
    args = parser(__doc__).parse_args()
    context = read_context(args.context)
    scenario = context["scenario"]
    variant = context["variant"]

    observation = {
        "target_ready": False,
        "execution_status": "not_run",
        "scenario": scenario,
        "variant": variant,
        "driver_sha256": hashlib.sha256(DRIVER.encode("utf-8")).hexdigest(),
        "upstream": None,
        "node": {"returncode": None, "stderr_tail": "", "stdout_tail": ""},
        "probes": [],
        "error": None,
    }

    try:
        environment = _read_json("environment.json")
        probes = _read_json("attack.json" if scenario == "attack" else "benign.json")
    except (OSError, ValueError) as error:
        observation["error"] = "fixed inputs unavailable: %s" % error
        return record(context, args.output, observation, {})

    driver_input = {
        "scenario": scenario,
        "variant": variant,
        "environment": environment,
        "probes": probes.get("probes", []),
    }

    workdir = Path(tempfile.mkdtemp(prefix="grackle-ghsa-f9ff-"))
    driver_path = workdir / "driver.mjs"
    input_path = workdir / "input.json"
    result_path = workdir / "result.json"
    driver_path.write_text(DRIVER, encoding="utf-8")
    input_path.write_text(json.dumps(driver_input, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    try:
        completed = subprocess.run(
            [NODE, str(driver_path), str(input_path), str(result_path)],
            cwd=str(workdir),
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )
        observation["node"]["returncode"] = completed.returncode
        observation["node"]["stderr_tail"] = (completed.stderr or "")[-4000:]
        observation["node"]["stdout_tail"] = (completed.stdout or "")[-2000:]
    except FileNotFoundError:
        observation["error"] = "node interpreter is not available in this image (looked for %r)" % NODE
        return record(context, args.output, observation, {})
    except subprocess.TimeoutExpired:
        observation["execution_status"] = "failed"
        observation["error"] = "the upstream driver did not finish within %ds" % TIMEOUT_SECONDS
        return record(context, args.output, observation, {})

    if not result_path.is_file():
        observation["execution_status"] = "failed"
        observation["error"] = "the driver produced no result document"
        return record(context, args.output, observation, {})

    try:
        report = json.loads(result_path.read_text(encoding="utf-8"))
    except ValueError as error:
        observation["execution_status"] = "failed"
        observation["error"] = "the driver result is not valid JSON: %s" % error
        return record(context, args.output, observation, {})

    observation["upstream"] = {
        "package_dir": (report.get("package") or {}).get("dir"),
        "package_version": (report.get("package") or {}).get("version"),
        "scope_enforcement_module_present": bool(report.get("scope_enforcement_module_present")),
        "central_scope_gate_present": bool(report.get("central_scope_gate_present")),
    }
    observation["probes"] = report.get("probes", [])
    observation["error"] = report.get("fatal")

    if report.get("ok"):
        observation["target_ready"] = True
        observation["execution_status"] = "completed"
    elif report.get("fatal"):
        # The pinned package is absent or unimportable: the precondition is missing,
        # which is "not_run" (exit 2), not a failed attempt.
        observation["target_ready"] = False
        observation["execution_status"] = "not_run"
    else:
        observation["target_ready"] = False
        observation["execution_status"] = "failed"
        if not observation["error"]:
            unfinished = [entry.get("id") for entry in observation["probes"]
                          if not entry.get("handler_invoked") and not entry.get("gate_denied")]
            observation["error"] = "the pinned mechanism did not run for: %s" % ", ".join(unfinished or ["<no probes>"])

    effects = {
        "tool-calls.json": json.dumps(observation["probes"], ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        "scenario-input.json": json.dumps(driver_input, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    }
    return record(context, args.output, observation, effects)


if __name__ == "__main__":
    raise SystemExit(main())
