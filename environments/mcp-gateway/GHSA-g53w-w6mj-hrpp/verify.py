"""Independent verifier for GHSA-g53w-w6mj-hrpp.

This file never invokes the upstream handler. It reads the observation and facts
written by reproduce.py, checks their integrity, and then decides whether the
recorded behaviour matches the expectation for the (variant, scenario) pair.

The mechanism under test: a hair-pin initialize request carries a caller-chosen
`mcp-init-host` header. In 0.6.0 the router authenticates it with a shared
router key and rewrites `:authority` to that host, which is the bypass. In 0.7.0
the header must carry a backend-init JWT signed by the gateway HMAC key, so a
caller who only knows the shared key is rejected.
"""

import argparse
import hashlib
import json
import pathlib
import sys

ATTACKER_HOST = "attacker-chosen-backend.example.invalid"
BROKER_NAME = "mcpBroker"


def check(identifier, passed, expected, actual, reason, evidence):
    return {
        "id": identifier,
        "passed": passed,
        "expected": expected,
        "actual": actual,
        "reason": reason,
        "evidence": evidence,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--output", required=True)
    options = parser.parse_args()

    context = json.loads(pathlib.Path(options.context).read_text())
    output = pathlib.Path(options.output)
    facts = json.loads((output / "facts.json").read_text())
    observation = json.loads((output / "observation.json").read_text())

    for key in ("schema_version", "run_id", "case_id", "variant", "scenario"):
        if facts.get(key) != context.get(key):
            raise SystemExit(f"facts context mismatch: {key}")
        if observation.get("context", {}).get(key) != context.get(key):
            raise SystemExit(f"observation context mismatch: {key}")

    observation_path = output / "observation.json"
    observed_hash = hashlib.sha256(observation_path.read_bytes()).hexdigest()
    if facts.get("evidence", [{}])[0].get("sha256") != observed_hash:
        raise SystemExit("observation hash mismatch")

    evidence = ["observation.json"]
    response = observation.get("response", {})
    rewrite = observation.get("header_rewrite", {})
    authority = rewrite.get(":authority")
    immediate_code = response.get("immediate_code")
    server_name = rewrite.get("x-mcp-servername")

    checks = [
        check(
            "target_ready",
            observation.get("target_ready") is True,
            "upstream HandleNoneToolCall runs to completion",
            str(observation.get("target_ready")),
            "The real upstream router method was invoked in-process.",
            evidence,
        )
    ]

    if context["scenario"] == "benign":
        # A direct client initialize with no mcp-init-host must keep working in
        # both revisions: it is routed to the broker and rewrites no authority.
        checks.append(
            check(
                "benign_task_passed",
                server_name == BROKER_NAME and authority is None,
                "initialize without mcp-init-host routes to the broker and rewrites no :authority",
                f"x-mcp-servername={server_name!r}; :authority={authority!r}",
                "The ordinary initialize path is unaffected by the fix.",
                evidence,
            )
        )
    elif context["variant"] == "vulnerable":
        # The bypass: the attacker's host becomes the upstream authority while
        # the internal routing headers are stripped so the backend cannot tell.
        checks.append(
            check(
                "vulnerable_effect_observed",
                authority == ATTACKER_HOST,
                f":authority is rewritten to {ATTACKER_HOST} on a shared-key-only request",
                f":authority={authority!r}",
                "0.6.0 accepts the shared router key and re-targets the request to a caller-chosen backend.",
                evidence,
            )
        )
        checks.append(
            check(
                "vulnerable_strips_internal_routing_headers",
                "-mcp-init-host" in rewrite and "-router-key" in rewrite,
                "mcp-init-host and router-key are removed before forwarding",
                f"removed={sorted(k for k in rewrite if k.startswith('-'))}",
                "Stripping the routing headers hides the hair-pin origin from the backend.",
                evidence,
            )
        )
    else:
        # The fix: a caller who only knows the shared key cannot produce a valid
        # backend-init JWT, so the request is rejected before any rewrite.
        checks.append(
            check(
                "patched_effect_blocked",
                immediate_code == 400 and authority is None,
                "hair-pin initialize without a valid backend-init JWT returns HTTP 400 and no :authority rewrite",
                f"immediate_code={immediate_code!r}; :authority={authority!r}",
                "0.7.0 replaced the shared router key with an HMAC-signed backend-init token, so the rejection happens before the authority rewrite.",
                evidence,
            )
        )

    verdict = {
        "schema_version": context.get("schema_version"),
        "run_id": context["run_id"],
        "case_id": context["case_id"],
        "variant": context["variant"],
        "scenario": context["scenario"],
        "outcome": "passed" if all(item["passed"] for item in checks) else "failed",
        "checks": checks,
    }
    (output / "verdict.json").write_text(json.dumps(verdict, indent=2) + "\n")

    if verdict["outcome"] != "passed":
        for item in checks:
            if not item["passed"]:
                print(f"FAILED {item['id']}: {item['actual']}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
