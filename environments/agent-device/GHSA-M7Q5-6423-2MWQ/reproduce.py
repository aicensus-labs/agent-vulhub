"""Mechanism PoC for project-selected remote daemon endpoints."""

import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import threading


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    context = json.loads(Path(args.context).read_text())
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    home = output / "home"
    state = output / "state"
    project = output / "project"
    for directory in (home, state, project):
        directory.mkdir(parents=True, exist_ok=True)

    observations = []

    class Receiver(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.record_and_reply(b"")

        def do_POST(self):
            length = int(self.headers.get("content-length", "0"))
            self.record_and_reply(self.rfile.read(length))

        def record_and_reply(self, body):
            observations.append({
                "method": self.command,
                "url": self.path,
                "authorization": self.headers.get("authorization"),
                "x_agent_device_token": self.headers.get("x-agent-device-token"),
                "body": body.decode("utf-8", "replace"),
            })
            payload = {"service": "agent-device", "rpcProtocolVersion": 2} if self.command == "GET" else {"result": {"ok": True, "data": []}}
            encoded = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    configured = context["scenario"] == "attack"
    if configured:
        (project / "agent-device.json").write_text(json.dumps({
            "daemonBaseUrl": f"http://127.0.0.1:{port}/agent-device"
        }) + "\n")

    environment = os.environ.copy()
    environment.update({
        "HOME": str(home),
        "AGENT_DEVICE_STATE_DIR": str(state),
        "AGENT_DEVICE_DAEMON_AUTH_TOKEN": "poc-secret-token",
        "AGENT_DEVICE_NO_UPDATE_NOTIFIER": "1",
    })
    for key in ("AGENT_DEVICE_CONFIG", "AGENT_DEVICE_DAEMON_BASE_URL"):
        environment.pop(key, None)
    try:
        completed = subprocess.run(
            ["node", "/lab/app/bin/agent-device.mjs", "devices", "--json"],
            cwd=project, env=environment, text=True, capture_output=True, timeout=30,
        )
    except subprocess.TimeoutExpired as error:
        completed = None
        execution_status = "failed"
        stdout = str(error.stdout or "")
        stderr = str(error.stderr or "")
    else:
        execution_status = "completed"
        stdout = completed.stdout
        stderr = completed.stderr
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    observation = {
        "schema_version": 1,
        "context": {key: context[key] for key in ("schema_version", "run_id", "case_id", "variant", "scenario")},
        "target_ready": completed is not None,
        "configured_project": configured,
        "daemon_base_url": f"http://127.0.0.1:{port}/agent-device",
        "return_code": None if completed is None else completed.returncode,
        "stdout_tail": stdout[-4000:],
        "stderr_tail": stderr[-4000:],
        "observations": observations,
    }
    observation_path = output / "observation.json"
    observation_path.write_text(json.dumps(observation, indent=2) + "\n")
    (output / "facts.json").write_text(json.dumps({
        "schema_version": 1,
        "run_id": context["run_id"],
        "case_id": context["case_id"],
        "variant": context["variant"],
        "scenario": context["scenario"],
        "execution_status": execution_status,
        "evidence": [{"path": "observation.json", "sha256": digest(observation_path)}],
    }, indent=2) + "\n")
    return 0 if execution_status == "completed" else 1


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
