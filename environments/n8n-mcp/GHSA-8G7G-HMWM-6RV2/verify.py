"""Independent effect checks for GHSA-8G7G-HMWM-6RV2 (n8n-mcp).

The verifier never reruns the attack. It reads the hash-checked
``observation.json``, ``facts.json`` and the raw ``probe-output.json`` that the
pinned upstream code produced, and decides from those bytes alone whether the
vulnerable revision exposed the three defects the advisory bundles, whether the
fixed revision blocked all three, and whether both revisions still serve the
legitimate operations.

Attribution comes from the ``X-Attack-Marker`` operation header that the driver
attaches to each call, so a captured request is matched to the exact call that
produced it instead of to whichever request happened to arrive first.
"""

import hashlib
import json
import os
from pathlib import Path

from lab_support import parser, read_context, verify

OPERATION_HEADER = "x-attack-marker"
TRAVERSAL_OPERATION = "traversal-get-workflow"
BENIGN_WORKFLOW_OPERATION = "benign-get-workflow"
REDIRECT_OPERATION = "redirect-trigger-webhook"
BENIGN_WEBHOOK_OPERATION = "benign-trigger-webhook"
TELEMETRY_OPERATION = "telemetry-process-mutation"
TELEMETRY_FIELDS = ("operations", "validationBefore", "validationAfter", "mutationError")
LAB_DEFAULT = "/lab"


def load_fixture():
    path = Path(os.environ.get("N8N_MCP_LAB_ROOT") or LAB_DEFAULT) / "fixtures" / "inputs.json"
    if not path.is_file():
        path = Path(__file__).resolve().parent / "fixtures" / "inputs.json"
    return json.loads(path.read_text(encoding="utf-8"))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def events(observation, listener):
    recorded = observation.get("recorded_events")
    if not isinstance(recorded, dict):
        return []
    items = recorded.get(listener)
    return items if isinstance(items, list) else []


def by_operation(observation, listener, operation):
    return [event for event in events(observation, listener)
            if isinstance(event, dict)
            and event.get("headers", {}).get(OPERATION_HEADER) == operation]


def observed(observation, name):
    value = observation.get("observed")
    return value.get(name, {}) if isinstance(value, dict) else {}


def node_result(entry):
    return entry.get("node_outcome") if isinstance(entry, dict) else None


def digest_matches(observation, name, expected):
    entry = observed(observation, name)
    return isinstance(entry, dict) and entry.get("response_digest") == digest(expected)


def raw_payload(paths):
    path = paths.get("probe-output.json")
    if path is None:
        return {}
    return json.loads(Path(path).read_text(encoding="utf-8"))


def raw_results(paths):
    payload = raw_payload(paths)
    results = payload.get("results") if isinstance(payload, dict) else None
    return results if isinstance(results, dict) else {}


def raw_entry(paths, operation):
    entry = raw_results(paths).get(operation)
    return entry if isinstance(entry, dict) else {}


def raw_telemetry(paths):
    value = raw_entry(paths, TELEMETRY_OPERATION).get("record")
    return value if isinstance(value, dict) else None


def raw_body_matches(paths, operation, expected):
    """The bytes the upstream module returned in the raw probe must equal the fixture's."""
    entry = raw_entry(paths, operation)
    return bool(entry) and digest(entry.get("body")) == digest(expected)


def summary_agrees_with_raw(observation, paths, name, operation):
    """The observation summary must be re-derivable from the raw product output.

    ``reproduce.py`` writes both the summary it derived and the untouched probe
    output; the verifier refuses to accept a summary that the raw bytes do not
    support, so a doctored or drifted summary cannot carry the verdict.
    """
    entry = observed(observation, name)
    raw = raw_entry(paths, operation)
    return {
        f"{name}_raw_outcome_agrees": bool(raw) and entry.get("node_outcome") == raw.get("outcome"),
        f"{name}_raw_digest_agrees": bool(raw)
        and entry.get("response_digest") == digest(raw.get("body")),
    }


def marker_values(fixture):
    return list(fixture["markers"].values())


def contains_marker(value, marker):
    return marker in json.dumps(value, sort_keys=True, default=str)


def benign_workflow_ok(observation, fixture):
    expected_body = {
        "data": {
            "id": fixture["benign"]["workflow_id"],
            "name": "normal workflow",
            "active": False,
        }
    }
    expected_path = f"/api/v1/workflows/{fixture['benign']['workflow_id']}"
    hits = by_operation(observation, "api", BENIGN_WORKFLOW_OPERATION)
    entry = observed(observation, "benign_workflow")
    return {
        "outcome_resolved": node_result(entry) == "resolved",
        "path_exact": [hit.get("path") for hit in hits] == [expected_path],
        "digest_matches": digest_matches(observation, "benign_workflow", expected_body),
        "api_key_attached": bool(hits) and all(
            hit.get("headers", {}).get("x-n8n-api-key") == fixture["traversal"]["api_key"]
            for hit in hits),
    }


def benign_webhook_ok(observation, fixture):
    hits = by_operation(observation, "webhook", BENIGN_WEBHOOK_OPERATION)
    entry = observed(observation, "benign_webhook")
    return {
        "outcome_resolved": node_result(entry) == "resolved",
        "path_exact": [hit.get("path") for hit in hits] == [fixture["benign"]["webhook_path"]],
        "digest_matches": digest_matches(observation, "benign_webhook", fixture["benign"]["webhook_response"]),
    }


def benign_telemetry_ok(observation, paths, fixture):
    record = raw_telemetry(paths)
    entry = observed(observation, "telemetry")
    return {
        "record_present": record is not None and bool(entry.get("record_present")),
        "operations_unchanged": record is not None
        and record.get("operations") == fixture["telemetry"]["benign_operations"],
        "validation_before_unchanged": record is not None
        and record.get("validationBefore") == fixture["telemetry"]["benign_validation_before"],
        "no_synthetic_marker": record is not None
        and not any(contains_marker(record, marker) for marker in marker_values(fixture)),
    }


def no_cross_talk(observation, fixture):
    """A legitimate call must never reach the credential endpoint or carry a marker."""
    benign_markers = {BENIGN_WORKFLOW_OPERATION, BENIGN_WEBHOOK_OPERATION}
    for listener in ("api", "redirect", "target", "webhook"):
        for event in events(observation, listener):
            marker = event.get("headers", {}).get(OPERATION_HEADER)
            path = event.get("path") or ""
            body = event.get("body") or ""
            if marker in benign_markers and "/credentials" in path:
                return False
            if marker in benign_markers and any(marker_value in body for marker_value in marker_values(fixture)):
                return False
    return True


def attack_case(context, observation, paths, fixture):
    """Require the vulnerable side to land all three defects and the fixed side to stop them."""
    payload = raw_payload(paths)
    upstream = payload.get("upstream") if isinstance(payload, dict) else {}
    expected_version = fixture["archives"][context["variant"]]["version"]
    traversal_entry = observed(observation, "traversal")
    traversal_hits = by_operation(observation, "api", TRAVERSAL_OPERATION)
    redirect_first_hop = by_operation(observation, "redirect", REDIRECT_OPERATION)
    redirect_second_hop = by_operation(observation, "target", REDIRECT_OPERATION)
    redirect_entry = observed(observation, "redirect")
    telemetry_entry = observed(observation, "telemetry")
    record = raw_telemetry(paths)
    markers = fixture["markers"]
    workflow = benign_workflow_ok(observation, fixture)
    webhook = benign_webhook_ok(observation, fixture)
    common = {
        "pinned_version_matches": bool(upstream) and upstream.get("version") == expected_version,
        "benign_workflow_intact": all(workflow.values()),
        "benign_webhook_intact": all(webhook.values()),
    }
    if context["variant"] == "vulnerable":
        effect = {
            **common,
            **summary_agrees_with_raw(observation, paths, "traversal", TRAVERSAL_OPERATION),
            **summary_agrees_with_raw(observation, paths, "redirect", REDIRECT_OPERATION),
            "traversal_node_resolved": node_result(traversal_entry) == "resolved",
            "traversal_reached_credentials_endpoint": [
                hit.get("path") for hit in traversal_hits] == [fixture["traversal"]["reached_path"]],
            "traversal_carried_api_key": bool(traversal_hits) and all(
                hit.get("headers", {}).get("x-n8n-api-key") == fixture["traversal"]["api_key"]
                for hit in traversal_hits),
            "traversal_returned_protected_listing": digest_matches(
                observation, "traversal", fixture["traversal"]["credential_response"]),
            "traversal_raw_returns_protected_listing": raw_body_matches(
                paths, TRAVERSAL_OPERATION, fixture["traversal"]["credential_response"]),
            "traversal_listing_holds_synthetic_credential": contains_marker(
                fixture["traversal"]["credential_response"], markers["credential"]) and digest_matches(
                observation, "traversal", fixture["traversal"]["credential_response"]),
            "traversal_raw_listing_holds_synthetic_credential": contains_marker(
                raw_entry(paths, TRAVERSAL_OPERATION).get("body"), markers["credential"]),
            "redirect_first_hop_validated_url": [hit.get("path") for hit in redirect_first_hop] == [
                fixture["redirect"]["webhook_path"]],
            "redirect_second_hop_unvalidated_host": [hit.get("path") for hit in redirect_second_hop] == [
                fixture["redirect"]["redirect_target_path"]],
            "redirect_returned_target_body": digest_matches(
                observation, "redirect", fixture["redirect"]["target_response"]),
            "redirect_raw_returns_target_body": raw_body_matches(
                paths, REDIRECT_OPERATION, fixture["redirect"]["target_response"]),
            "telemetry_record_present": record is not None and bool(telemetry_entry.get("record_present")),
            "telemetry_secret_in_every_diff_field": record is not None and all(
                contains_marker(record.get(field), markers["telemetry"]) for field in TELEMETRY_FIELDS),
            "telemetry_secret_absent_from_workflow_body": record is not None and not contains_marker(
                record.get("workflowAfter"), markers["telemetry"]),
            "no_cross_talk": no_cross_talk(observation, fixture),
        }
        return (
            "vulnerable_effect_observed",
            all(effect.values()),
            "the crafted workflow identifier reaches the protected same-origin endpoint with the configured API key, "
            "the validated webhook URL is followed onto the unvalidated host, the telemetry record keeps the "
            "synthetic bearer token in every diff field, and the legitimate calls still succeed",
            json.dumps(effect, sort_keys=True),
        )

    effect = {
        **common,
        **summary_agrees_with_raw(observation, paths, "traversal", TRAVERSAL_OPERATION),
        **summary_agrees_with_raw(observation, paths, "redirect", REDIRECT_OPERATION),
        "traversal_node_rejected": node_result(traversal_entry) == "rejected",
        "traversal_rejection_names_identifier": "workflowId" in str(
            traversal_entry.get("node_error") or ""),
        "traversal_raw_rejection_names_identifier": "workflowId" in str(
            raw_entry(paths, TRAVERSAL_OPERATION).get("error") or ""),
        "traversal_no_request_emitted": traversal_hits == [],
        "traversal_never_reached_credentials": not [
            hit for hit in events(observation, "api") if "/credentials" in (hit.get("path") or "")],
        "redirect_first_hop_validated_url": [hit.get("path") for hit in redirect_first_hop] == [
            fixture["redirect"]["webhook_path"]],
        "redirect_second_hop_absent": redirect_second_hop == [],
        "redirect_stopped_at_redirect_status": redirect_entry.get("node_status") == 302,
        "redirect_raw_stopped_at_redirect_status": raw_entry(
            paths, REDIRECT_OPERATION).get("status") == 302,
        "redirect_raw_target_body_absent": raw_body_matches(
            paths, REDIRECT_OPERATION, fixture["redirect"]["target_response"]) is False,
        "telemetry_record_present": record is not None and bool(telemetry_entry.get("record_present")),
        "telemetry_secret_absent_everywhere": record is not None and not any(
            contains_marker(record, marker) for marker in marker_values(fixture)),
        "telemetry_diff_still_recorded": record is not None and bool(record.get("operations")),
    }
    return (
        "patched_effect_blocked",
        all(effect.values()),
        "the same crafted identifier is rejected before any request leaves the client, the redirect is not followed "
        "onto the unvalidated host, the telemetry record keeps the diff structure without the synthetic token, and "
        "the legitimate calls still succeed",
        json.dumps(effect, sort_keys=True),
    )


def benign_case(context, observation, paths, fixture):
    workflow = benign_workflow_ok(observation, fixture)
    webhook = benign_webhook_ok(observation, fixture)
    telemetry = benign_telemetry_ok(observation, paths, fixture)
    payload = raw_payload(paths)
    upstream = payload.get("upstream") if isinstance(payload, dict) else {}
    effect = {
        "pinned_version_matches": bool(upstream)
        and upstream.get("version") == fixture["archives"][context["variant"]]["version"],
        **summary_agrees_with_raw(observation, paths, "benign_workflow", BENIGN_WORKFLOW_OPERATION),
        **summary_agrees_with_raw(observation, paths, "benign_webhook", BENIGN_WEBHOOK_OPERATION),
        "workflow_read_resolved": workflow["outcome_resolved"],
        "workflow_path_exact": workflow["path_exact"],
        "workflow_digest_matches": workflow["digest_matches"],
        "workflow_raw_digest_matches": raw_body_matches(
            paths, BENIGN_WORKFLOW_OPERATION,
            {"data": {"id": fixture["benign"]["workflow_id"], "name": "normal workflow", "active": False}}),
        "workflow_api_key_attached": workflow["api_key_attached"],
        "webhook_post_resolved": webhook["outcome_resolved"],
        "webhook_path_exact": webhook["path_exact"],
        "webhook_digest_matches": webhook["digest_matches"],
        "webhook_raw_digest_matches": raw_body_matches(
            paths, BENIGN_WEBHOOK_OPERATION, fixture["benign"]["webhook_response"]),
        "telemetry_record_present": telemetry["record_present"],
        "telemetry_operations_unchanged": telemetry["operations_unchanged"],
        "telemetry_validation_unchanged": telemetry["validation_before_unchanged"],
        "telemetry_has_no_synthetic_marker": telemetry["no_synthetic_marker"],
        "credential_endpoint_never_reached": not [
            hit for hit in events(observation, "api") if "/credentials" in (hit.get("path") or "")],
        "no_synthetic_marker_in_any_request": not any(
            marker_value in (hit.get("body") or "")
            for listener in ("api", "redirect", "target", "webhook")
            for hit in events(observation, listener)
            for marker_value in marker_values(fixture)),
        "no_attack_operation_emitted": not [
            hit for listener in ("api", "redirect", "target")
            for hit in by_operation(observation, listener, TRAVERSAL_OPERATION)
            + by_operation(observation, listener, REDIRECT_OPERATION)],
        "observation_has_no_marker_leak": not observation.get("credential_markers_in_observation"),
    }
    return (
        "benign_task_passed",
        all(effect.values()),
        "both revisions still read a normal workflow, post a webhook directly and build the same credential-free "
        "telemetry record, while no crafted identifier or synthetic marker reaches any endpoint",
        json.dumps(effect, sort_keys=True),
    )


def upstream_loaded(observation):
    upstream = observation.get("upstream") or {}
    return {
        "target_ready": observation.get("target_ready"),
        "collection_error": observation.get("collection_error"),
        "package": upstream.get("package"),
        "version": upstream.get("version"),
        "module": upstream.get("module"),
        "dependencies": observation.get("dependencies"),
    }


def main():
    args = parser(__doc__).parse_args()
    context = read_context(args.context)
    fixture = load_fixture()

    def check(_context, observation, paths):
        if context["scenario"] == "attack":
            identifier, passed, expected, actual = attack_case(context, observation, paths, fixture)
        else:
            identifier, passed, expected, actual = benign_case(context, observation, paths, fixture)
        upstream = upstream_loaded(observation)
        if not upstream["version"] or upstream["target_ready"] is not True:
            passed = False
        return identifier, passed, expected, json.dumps(
            {"mechanism": json.loads(actual), "pinned_upstream": upstream}, sort_keys=True)

    return verify(args.context, args.output, check)


if __name__ == "__main__":
    raise SystemExit(main())
