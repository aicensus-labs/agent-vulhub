"""Exercise the pinned Dynatrace MCP server and observe the notebook write.

The vulnerable and patched ``@dynatrace-oss/dynatrace-mcp-server`` bundles are
executed unchanged over MCP stdio.  The scenario fixture fixes the ``tools/call``
request and the caller's approval behaviour, and a controlled HTTPS receiver
stands in for the Dynatrace document store, so the observable effect is the
document write request the upstream code itself emits.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import shutil
import socket
import socketserver
import ssl
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.parse

from lab_support import parser, read_context, record

LAB = Path(__file__).resolve().parent
FIXTURES = LAB / "fixtures"

# The upstream server only accepts DT_ENVIRONMENT values that start with https://
# and end in .apps.dynatrace.com, and it skips its startup connection test when
# the value contains abc12345.  One synthetic host satisfies all three.
SINK_HOST = "abc12345.apps.dynatrace.com"
DT_ENVIRONMENT = "https://" + SINK_HOST
DOCUMENT_PATH = "/platform/document/v1/documents"

# The fix commit adds this message to the create_dynatrace_notebook callback; it is
# absent from 1.8.6 and present in 1.8.7, which makes the bundle self-identifying.
FIX_MARKER = b'Create Dynatrace notebook: "'
TOOL_MARKER = b"create_dynatrace_notebook"

SYNTHETIC_TOKEN = "dt0s16.SYNTHETIC-NOT-A-REAL-TOKEN"
EXCHANGE_TIMEOUT = 90.0
RECEIVER_TIMEOUT = 30.0

FIXTURE_BY_SCENARIO = {
    "attack": "attack_tool_call.json",
    "benign": "benign_tool_call.json",
}


# --------------------------------------------------------------------------- #
# Controlled receiver
# --------------------------------------------------------------------------- #
def _recv(sock):
    try:
        chunk = sock.recv(65536)
    except (OSError, socket.timeout):
        return None
    return chunk or None


def _ensure(sock, buffer, count):
    while len(buffer) < count:
        chunk = _recv(sock)
        if chunk is None:
            return False
        buffer += chunk
    return True


def _read_head(sock, limit=65536):
    """Read one HTTP head byte by byte so a CONNECT request cannot over-read.

    Reading a block would consume the first bytes of the TLS ClientHello that the
    client sends immediately after the 200 response.
    """
    buffer = bytearray()
    while b"\r\n\r\n" not in buffer:
        if len(buffer) >= limit:
            return None
        chunk = _recv(sock)
        if chunk is None:
            return None
        buffer += chunk
    return bytes(buffer)


def _read_chunked(sock, initial):
    buffer = bytearray(initial)
    body = bytearray()
    while True:
        while b"\r\n" not in buffer:
            if not _ensure(sock, buffer, len(buffer) + 1):
                return bytes(body)
        index = buffer.index(b"\r\n")
        line = bytes(buffer[:index])
        del buffer[:index + 2]
        try:
            size = int(line.split(b";", 1)[0].strip() or b"0", 16)
        except ValueError:
            return bytes(body)
        if size == 0:
            return bytes(body)
        if not _ensure(sock, buffer, size + 2):
            body += buffer
            return bytes(body)
        body += buffer[:size]
        del buffer[:size + 2]


def _read_message(sock):
    """Return (method, target, headers, body) for one HTTP/1.1 request."""
    head = _read_head(sock)
    if head is None:
        return None
    head, _, body = head.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    request_line = lines[0].decode("latin-1", "replace")
    headers = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, value = line.split(b":", 1)
        headers[key.strip().decode("latin-1").lower()] = value.strip().decode("latin-1", "replace")
    if "100-continue" in headers.get("expect", "").lower():
        sock.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = _read_chunked(sock, body)
    elif "content-length" in headers:
        try:
            length = int(headers["content-length"])
        except ValueError:
            length = 0
        while len(body) < length:
            chunk = _recv(sock)
            if chunk is None:
                break
            body += chunk
    parts = request_line.split(" ")
    method = parts[0] if parts else ""
    target = parts[1] if len(parts) > 1 else ""
    return method, target, headers, body


def _respond(sock, status, body):
    reason = {200: "OK", 201: "Created"}.get(status, "OK")
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    sock.sendall(head + body)
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


class _Receiver:
    def __init__(self):
        self.records = []
        self.mode = "none"
        self.port = 0
        self._lock = threading.Lock()
        self._server = None
        self._thread = None

    def note(self, entry):
        with self._lock:
            self.records.append(entry)

    def snapshot(self):
        with self._lock:
            return list(self.records)

    def start(self, ssl_context, status, body):
        server = None
        try:
            server = _TlsServer(("127.0.0.1", 443), _DirectHandler, ssl_context, self, status, body)
        except OSError:
            server = None
        if server is not None and _ensure_hosts_entry(SINK_HOST):
            self.mode, self.port = "direct", 443
        else:
            if server is not None:
                server.server_close()
            server = _TlsServer(("127.0.0.1", 0), _ProxyHandler, ssl_context, self, status, body)
            self.mode, self.port = "proxy", server.server_address[1]
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self._thread.start()
        return self

    def stop(self):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None


class _TlsServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, handler, ssl_context, receiver, status, body):
        super().__init__(address, handler)
        self.ssl_context = ssl_context
        self.receiver = receiver
        self.status = status
        self.body = body


class _BaseHandler(socketserver.BaseRequestHandler):
    def setup(self):
        self.request.settimeout(RECEIVER_TIMEOUT)

    def _wrap(self):
        try:
            return self.server.ssl_context.wrap_socket(self.request, server_side=True)
        except (ssl.SSLError, OSError):
            return None

    def _serve(self, sock):
        message = _read_message(sock)
        if message is None:
            return
        method, target, headers, body = message
        self.server.receiver.note({
            "method": method,
            "target": target,
            "path": urllib.parse.urlsplit(target).path or "/",
            "headers": {
                key: ("<redacted>" if key == "authorization" else value)
                for key, value in headers.items()
            },
            "authorization_present": "authorization" in headers,
            "body": body.decode("utf-8", "replace"),
        })
        _respond(sock, self.server.status, self.server.body)


class _DirectHandler(_BaseHandler):
    """TLS terminates immediately: /etc/hosts points the synthetic host at loopback."""

    def handle(self):
        tls = self._wrap()
        if tls is not None:
            self._serve(tls)


class _ProxyHandler(_BaseHandler):
    """CONNECT tunnel used when binding port 443 is not permitted."""

    def handle(self):
        head = _read_head(self.request)
        if head is None:
            return
        request_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        if not request_line.upper().startswith("CONNECT "):
            self.request.sendall(
                b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            return
        self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        tls = self._wrap()
        if tls is not None:
            self._serve(tls)


def _ensure_hosts_entry(host):
    try:
        text = Path("/etc/hosts").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    for line in text.splitlines():
        parts = line.split()
        if len(parts) > 1 and host in parts[1:]:
            return True
    try:
        with open("/etc/hosts", "a", encoding="utf-8") as stream:
            stream.write(f"\n127.0.0.1 {host}\n")
    except OSError:
        return False
    return True


# --------------------------------------------------------------------------- #
# Pinned upstream discovery
# --------------------------------------------------------------------------- #
def _local_candidates(root):
    found = []
    for pattern in ("package/index.js", "index.js", "dist/index.js", "build/index.js",
                    "out/index.js", "lib/index.js", "*/index.js"):
        try:
            found.extend(sorted(root.glob(pattern)))
        except OSError:
            continue
    return found


def _unpack_inputs(workdir):
    roots = []
    inputs = Path("/inputs")
    if not inputs.is_dir():
        return roots
    for item in sorted(inputs.iterdir()):
        if not item.is_file() or not tarfile.is_tarfile(item):
            continue
        destination = workdir / ("input-" + item.name)
        try:
            with tarfile.open(item) as archive:
                try:
                    archive.extractall(destination, filter="data")
                except TypeError:
                    archive.extractall(destination)
        except (tarfile.TarError, OSError):
            continue
        roots.append(destination)
    return roots


def _walk_candidates(root, max_depth=5, limit=400):
    """Bounded search for a bundled entrypoint under an installed tree."""
    found = []
    stack = [(Path(root), 0)]
    visited = 0
    while stack and visited < limit:
        current, depth = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            visited += 1
            if visited >= limit or entry.is_symlink():
                continue
            if entry.is_dir():
                if depth >= max_depth or entry.name in {".git", "__pycache__", ".cache"}:
                    continue
                stack.append((entry, depth + 1))
            elif entry.name in {"index.js", "index.cjs", "index.mjs"}:
                found.append(entry)
    return found


def _classify(path):
    """Identify the upstream variant from the bundle's approval-gate marker."""
    try:
        with open(path, "rb") as stream:
            data = b""
            while len(data) < 16 * 1024 * 1024:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                data += chunk
                if TOOL_MARKER in data and FIX_MARKER in data:
                    return "patched"
    except OSError:
        return None
    if TOOL_MARKER not in data:
        return None
    return "patched" if FIX_MARKER in data else "vulnerable"


def find_upstream(variant, workdir):
    """Return (bundle path, classification) for the requested variant."""
    candidates = []
    for root in _unpack_inputs(workdir):
        candidates.extend(_local_candidates(root))
    for root in (
        Path("/lab/upstream"),
        Path("/lab"),
        Path("/opt/upstream"),
        Path("/opt/dynatrace-mcp"),
        Path("/usr/local/lib/node_modules/@dynatrace-oss/dynatrace-mcp-server"),
        Path("/usr/lib/node_modules/@dynatrace-oss/dynatrace-mcp-server"),
    ):
        if root.is_dir():
            candidates.extend(_local_candidates(root))
    for root in ("/lab", "/app", "/opt", "/srv"):
        if Path(root).is_dir():
            candidates.extend(_walk_candidates(root))
    seen = set()
    attempts = 0
    for candidate in candidates:
        if candidate in seen or attempts >= 32:
            continue
        seen.add(candidate)
        attempts += 1
        classification = _classify(candidate)
        if classification == variant:
            return candidate, classification
    return None, None


def _node_binary():
    found = shutil.which("node")
    if found:
        return found
    for candidate in ("/usr/local/bin/node", "/usr/bin/node", "/opt/node/bin/node"):
        if Path(candidate).is_file():
            return candidate
    return None


# --------------------------------------------------------------------------- #
# MCP stdio exchange
# --------------------------------------------------------------------------- #
def _pump(stream, sink):
    try:
        for line in iter(stream.readline, b""):
            sink.put(line)
    except (OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except OSError:
            pass


class _Session:
    def __init__(self, process, timeout):
        self.process = process
        self.deadline = time.monotonic() + timeout
        self.responses = []
        self.requests = []
        self.unparsed = []
        self._stdout = queue.Queue()
        self._stderr = queue.Queue()
        self._threads = [
            threading.Thread(target=_pump, args=(process.stdout, self._stdout), daemon=True),
            threading.Thread(target=_pump, args=(process.stderr, self._stderr), daemon=True),
        ]
        for thread in self._threads:
            thread.start()

    def send(self, message):
        try:
            self.process.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
            self.process.stdin.flush()
            return True
        except (OSError, ValueError):
            return False

    def receive(self):
        while True:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                raw = self._stdout.get(timeout=remaining)
            except queue.Empty:
                return None
            text = raw.decode("utf-8", "replace").strip()
            if not text:
                continue
            try:
                return json.loads(text)
            except ValueError:
                self.unparsed.append(text)

    def wait_for(self, target, on_request=None):
        while True:
            message = self.receive()
            if message is None:
                return None
            if "method" in message and "id" in message:
                self.requests.append(message)
                if on_request is not None:
                    reply = on_request(message)
                    if reply is not None:
                        self.send(reply)
                continue
            if message.get("id") == target:
                self.responses.append(message)
                return message

    def stderr_text(self):
        lines = []
        while True:
            try:
                lines.append(self._stderr.get_nowait().decode("utf-8", "replace"))
            except queue.Empty:
                break
        return "".join(lines)

    def shutdown(self):
        try:
            self.process.stdin.close()
        except (OSError, ValueError):
            pass
        for action in (None, "terminate", "kill"):
            if self.process.poll() is not None:
                break
            if action == "terminate":
                self.process.terminate()
            elif action == "kill":
                self.process.kill()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                continue
        for thread in self._threads:
            thread.join(timeout=2)


def _child_environment(receiver, workdir):
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(workdir),
        "TMPDIR": str(workdir / "tmp"),
        "DT_ENVIRONMENT": DT_ENVIRONMENT,
        "DT_PLATFORM_TOKEN": SYNTHETIC_TOKEN,
        "DT_MCP_DISABLE_TELEMETRY": "true",
        "NODE_EXTRA_CA_CERTS": str(FIXTURES / "tls" / "ca.crt"),
        "NO_COLOR": "1",
    }
    (workdir / "tmp").mkdir(exist_ok=True)
    if receiver.mode == "proxy":
        environment["HTTPS_PROXY"] = f"http://127.0.0.1:{receiver.port}"
        environment["NO_PROXY"] = ""
    return environment


def _exchange(node, bundle, payload, policy, environment, workdir):
    process = subprocess.Popen(
        [node, str(bundle)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        cwd=str(workdir),
    )
    session = _Session(process, EXCHANGE_TIMEOUT)
    result = {
        "initialized": False,
        "initialized_result": None,
        "approval_requests": 0,
        "tool_result": None,
        "tool_call_returned": False,
        "send_failed": False,
    }
    try:
        capabilities = (
            {"elicitation": {"form": {}}} if policy.get("declare_elicitation") else {}
        )
        if not session.send({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": policy["protocol_version"],
                "capabilities": capabilities,
                "clientInfo": policy["client_info"],
            },
        }):
            result["send_failed"] = True
            return result, session
        initialized = session.wait_for(1)
        if initialized is None or "result" not in initialized:
            return result, session
        result["initialized"] = True
        result["initialized_result"] = initialized.get("result")
        session.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        def on_request(message):
            if message.get("method") != "elicitation/create":
                return None
            result["approval_requests"] += 1
            return {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": policy.get("elicitation_response", {"action": "decline"}),
            }

        if not session.send({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": payload["tool"], "arguments": payload["arguments"]},
        }):
            result["send_failed"] = True
            return result, session
        call = session.wait_for(2, on_request=on_request)
        result["tool_call_returned"] = call is not None
        result["tool_result"] = call
        return result, session
    finally:
        session.shutdown()


def _tool_text(tool_result):
    if not isinstance(tool_result, dict):
        return ""
    content = (tool_result.get("result") or {}).get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                return item["text"]
    if "error" in tool_result:
        return json.dumps(tool_result["error"], ensure_ascii=False)
    return ""


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def main() -> int:
    args = parser(__doc__).parse_args()
    context = read_context(args.context)
    scenario = context["scenario"]
    variant = context["variant"]

    payload = json.loads((FIXTURES / FIXTURE_BY_SCENARIO[scenario]).read_text(encoding="utf-8"))
    client_policy = json.loads((FIXTURES / "client_policy.json").read_text(encoding="utf-8"))
    # client_policy.json keeps the client identity (protocol_version, client_info)
    # at the top level and the per-scenario approval behaviour under "scenarios".
    # Merge the two so _exchange() sees the full policy for this scenario; a
    # scenario-level key still overrides the global default.
    policy = {**client_policy, **client_policy["scenarios"][scenario]}
    response = json.loads((FIXTURES / "mock_document_response.json").read_text(encoding="utf-8"))

    observation = {
        "target_ready": False,
        "execution_status": "not_run",
        "scenario": scenario,
        "variant": variant,
        "payload_marker": payload["marker"],
        "expected_notebook_name": payload["arguments"]["name"],
        "upstream_bundle": "",
        "upstream_classification": "",
        "receiver_mode": "none",
        "mcp_initialized": False,
        "server_version": "",
        "tool_call_returned": False,
        "tool_result_text": "",
        "approval_requests": 0,
        "document_requests": 0,
        "document_request_paths": [],
        "marker_seen_in_document_request": False,
        "notebook_name_seen_in_document_request": False,
        "server_stderr_tail": "",
    }
    effects = {"mock_requests.json": "[]\n", "tool_exchange.json": "{}\n", "server_stderr.txt": ""}

    node = _node_binary()
    workdir = Path(tempfile.mkdtemp(prefix="notebook-poc-"))
    receiver = None
    session = None
    try:
        if node is None:
            observation["execution_status"] = "failed"
            return record(context, args.output, observation, effects)

        bundle, classification = find_upstream(variant, workdir)
        if bundle is None:
            observation["execution_status"] = "failed"
            return record(context, args.output, observation, effects)
        observation["upstream_bundle"] = str(bundle)
        observation["upstream_classification"] = classification

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(
            str(FIXTURES / "tls" / "server.crt"), str(FIXTURES / "tls" / "server.key")
        )
        ssl_context.set_alpn_protocols(["http/1.1"])
        receiver = _Receiver().start(
            ssl_context, int(response.get("status", 201)),
            json.dumps(response.get("body", {})).encode("utf-8"),
        )
        observation["receiver_mode"] = receiver.mode

        environment = _child_environment(receiver, workdir)
        exchange, session = _exchange(node, bundle, payload, policy, environment, workdir)

        observation["mcp_initialized"] = exchange["initialized"]
        observation["server_version"] = str(
            (exchange["initialized_result"] or {}).get("serverInfo", {}).get("version", "")
        )
        observation["approval_requests"] = exchange["approval_requests"]
        observation["tool_call_returned"] = exchange["tool_call_returned"]
        observation["tool_result_text"] = _tool_text(exchange["tool_result"])[:4000]

        records = receiver.snapshot()
        documents = [item for item in records if item["path"] == DOCUMENT_PATH]
        observation["document_requests"] = len(documents)
        observation["document_request_paths"] = sorted({item["path"] for item in records})
        marker = payload["marker"]
        name = payload["arguments"]["name"]
        observation["marker_seen_in_document_request"] = any(
            marker in item["body"] for item in documents
        )
        observation["notebook_name_seen_in_document_request"] = any(
            name in item["body"] for item in documents
        )

        stderr_text = session.stderr_text()
        observation["server_stderr_tail"] = stderr_text[-4000:]

        if exchange["initialized"] and exchange["tool_call_returned"]:
            observation["target_ready"] = True
            observation["execution_status"] = "completed"
        else:
            observation["execution_status"] = "failed"

        effects["mock_requests.json"] = json.dumps(records, ensure_ascii=False, indent=2) + "\n"
        effects["tool_exchange.json"] = json.dumps(
            {
                "initialize": exchange["initialized_result"],
                "approval_requests": exchange["approval_requests"],
                "tool_result": exchange["tool_result"],
                "unparsed_stdout": session.unparsed,
            },
            ensure_ascii=False,
            indent=2,
        ) + "\n"
        effects["server_stderr.txt"] = stderr_text[-262144:]
        return record(context, args.output, observation, effects)
    except (OSError, ValueError, KeyError, TypeError) as error:
        observation["execution_status"] = "failed"
        observation["error"] = f"{type(error).__name__}: {error}"
        return record(context, args.output, observation, effects)
    finally:
        if session is not None:
            session.shutdown()
        if receiver is not None:
            receiver.stop()
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
