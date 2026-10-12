"""Local review attestations; Git branch protection supplies reviewer authorization."""

from datetime import datetime, timezone
from pathlib import Path
import shutil

from .protocol import (contained, digest, fingerprint, read_json, validate_report,
                       revision_identity, validate_verdict, write_json, write_metadata)


def ready_check(root, directory, metadata):
    if metadata.get("lifecycle") != "ready":
        return
    review = metadata.get("review", {})
    if review.get("fingerprint") != fingerprint(root, directory, metadata):
        raise ValueError("ready evidence is stale; run runner refresh to downgrade")
    reviewers = review.get("reviewers", [])
    minimum = 2 if metadata.get("runtime", {}).get("exceptions") else 1
    if not isinstance(reviewers, list) or len(set(reviewers)) < minimum or any(not x.strip() for x in reviewers):
        raise ValueError(f"ready requires {minimum} distinct reviewer(s)")
    if metadata.get("verification", {}).get("mechanism", {}).get("status") != "passed":
        raise ValueError("ready requires passed mechanism evidence")
    summary = contained(directory, review.get("report", ""))
    if digest(summary) != review.get("report_sha256"):
        raise ValueError("Reviewed report hash mismatch")
    report = read_json(summary)
    if report.get("layer") != "mechanism":
        raise ValueError("ready report must be a mechanism report")
    validate_report(report, review["fingerprint"])
    if report.get("environment_id") != metadata["id"]:
        raise ValueError("Reviewed report belongs to another environment")
    manifest = read_json(summary.parent / "manifest.json")
    actual_files = {p.relative_to(summary.parent).as_posix() for p in summary.parent.rglob("*")
                    if p.is_file() and p != summary.parent / "manifest.json"}
    if set(manifest) != actual_files:
        raise ValueError("Evidence manifest does not cover retained files exactly")
    for name, sha in manifest.items():
        if digest(contained(summary.parent, name)) != sha:
            raise ValueError(f"Retained evidence changed: {name}")
    for case in report["cases"]:
        revision_kind, revision = revision_identity(metadata, case["variant"])
        if case.get("revision_kind") != revision_kind or case.get("target_revision") != revision:
            raise ValueError("Case target revision differs from reviewed metadata")
        path = contained(summary.parent, case["case_id"])
        actual = read_json(path / "result.json")
        if actual != case:
            raise ValueError("Case summary differs from retained result")
        verdict = validate_verdict(path / "evidence", case)
        if verdict["outcome"] != "passed" or verdict["checks"] != case.get("checks"):
            raise ValueError("Retained verdict disagrees with passing report")


def _mechanism_evidence_current(root, directory, metadata):
    mechanism = metadata.get("verification", {}).get("mechanism", {})
    if mechanism.get("status") != "passed":
        return
    evidence = mechanism.get("evidence") or []
    if not evidence:
        raise ValueError("passed mechanism needs evidence")
    expected = fingerprint(root, directory, metadata)
    for relative in evidence:
        path = contained(directory, relative)
        if not path.is_file():
            path = contained(root, relative)
        report = read_json(path)
        if report.get("environment_id") != metadata.get("id"):
            raise ValueError(f"Mechanism evidence belongs to another environment: {relative}")
        if report.get("fingerprint") != expected:
            raise ValueError(f"Mechanism evidence {relative} is stale for the current inputs")


def _invalidate(directory, metadata, reason, layers, downgrade_lifecycle=True):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    write_json(directory / "evidence" / "history" / f"{stamp}.json", {
        "action": "invalidate", "reason": str(reason),
        "previous_review": metadata.get("review"),
        "previous_verification": metadata.get("verification"),
    })
    if downgrade_lifecycle:
        metadata["lifecycle"] = "draft"
    verification = metadata.get("verification", {})
    for layer in layers:
        value = verification.get(layer)
        if not isinstance(value, dict):
            continue
        if layer == "agent_poc":
            value.update(adapter_status="not_run", verified_at="", evidence=[],
                         notes="Previous evidence retained after invalidation")
        elif value.get("status") in {"passed", "failed"}:
            value.update(status="not_run", verified_at="", evidence=[],
                         notes="Previous evidence retained after invalidation")
    if downgrade_lifecycle:
        metadata.pop("review", None)
    write_metadata(directory / "metadata.toml", metadata)
    return True


def refresh(root, directory, metadata):
    if metadata.get("lifecycle") == "ready":
        try:
            ready_check(root, directory, metadata)
        except (ValueError, OSError, KeyError, TypeError) as error:
            return _invalidate(directory, metadata, error, metadata.get("verification", {}).keys())
        adapter = metadata.get("verification", {}).get("agent_poc", {})
        if adapter.get("adapter_status") == "accepted":
            try:
                from .agent_poc import validate_adapter_admission
                validate_adapter_admission(root, directory, metadata)
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _invalidate(directory, metadata, error, ("agent_poc",),
                                   downgrade_lifecycle=False)
        return False

    try:
        _mechanism_evidence_current(root, directory, metadata)
    except (ValueError, OSError, KeyError, TypeError) as error:
        return _invalidate(directory, metadata, error,
                           ("mechanism", "end_to_end", "agent_poc"))

    adapter = metadata.get("verification", {}).get("agent_poc", {})
    if adapter.get("adapter_status") == "accepted":
        try:
            from .agent_poc import validate_adapter_admission
            validate_adapter_admission(root, directory, metadata)
        except (ValueError, OSError, KeyError, TypeError) as error:
            return _invalidate(directory, metadata, error, ("agent_poc",))
    return False


def archive_report(root, directory, metadata, report_path):
    report_path = Path(report_path).resolve()
    raw_report = read_json(report_path)
    if raw_report.get("layer") != "mechanism":
        raise ValueError("Only mechanism reports can be archived")
    report = validate_report(raw_report, fingerprint(root, directory, metadata))
    if report.get("environment_id") != metadata["id"]:
        raise ValueError("Report belongs to another environment")
    archive = directory / "evidence" / report["run_id"]
    if not report["run_id"] or "/" in report["run_id"] or ".." in report["run_id"]:
        raise ValueError("Invalid run ID")
    # Check every retained result before copying or changing metadata.
    for case in report["cases"]:
        revision_kind, revision = revision_identity(metadata, case["variant"])
        if case.get("revision_kind") != revision_kind or case.get("target_revision") != revision:
            raise ValueError("Case target revision differs from metadata")
        folder = contained(report_path.parent, case["case_id"])
        if read_json(folder / "result.json") != case:
            raise ValueError("Report case differs from on-disk result")
        verdict = validate_verdict(folder / "evidence", case)
        if verdict["outcome"] != "passed" or verdict["checks"] != case.get("checks"):
            raise ValueError("Report disagrees with independent verifier")
    if archive.exists():
        raise ValueError("Evidence archive already exists; do not overwrite historical evidence")
    archive.mkdir(parents=True)
    shutil.copyfile(report_path, archive / "report.json")
    manifest = {"report.json": digest(archive / "report.json")}
    for case in report["cases"]:
        source = report_path.parent / case["case_id"]
        dest = archive / case["case_id"]
        dest.mkdir()
        shutil.copyfile(source / "result.json", dest / "result.json")
        evidence = source / "evidence"
        names = ["facts.json", "verdict.json", "context.json"]
        names += [entry["path"] for entry in read_json(evidence / "facts.json")["evidence"]]
        for name in names:
            path = contained(evidence, name)
            if path.stat().st_size > 8 * 1024 * 1024:
                raise ValueError("Retained evidence file exceeds 8 MiB; use reviewed compact evidence")
            target = dest / "evidence" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    for path in archive.rglob("*"):
        if path.is_file():
            manifest[path.relative_to(archive).as_posix()] = digest(path)
    write_json(archive / "manifest.json", manifest)
    return archive


def archive_draft(root, directory, metadata, report_path):
    """Retain a verified mechanism report while leaving lifecycle at draft."""
    if metadata.get("lifecycle") != "draft":
        raise ValueError("Evidence can only be archived without review while lifecycle is draft")
    archive = archive_report(root, directory, metadata, report_path)
    report = read_json(archive / "report.json")
    metadata["verification"]["mechanism"].update(
        status="passed",
        verified_at=report["finished_at"],
        evidence=[(archive / "report.json").relative_to(directory).as_posix()],
    )
    write_metadata(directory / "metadata.toml", metadata)
    return archive


def promote(root, directory, metadata, report_path, reviewers):
    minimum = 2 if metadata.get("runtime", {}).get("exceptions") else 1
    if len(set(reviewers)) < minimum or any(not x.strip() for x in reviewers):
        raise ValueError(f"Need {minimum} distinct reviewers")
    archive = archive_report(root, directory, metadata, report_path)
    report = read_json(archive / "report.json")
    metadata["lifecycle"] = "ready"
    metadata["verification"]["mechanism"].update(status="passed", verified_at=report["finished_at"],
        evidence=[(archive / "report.json").relative_to(directory).as_posix()])
    metadata["review"] = {"reviewers": sorted(set(reviewers)), "fingerprint": report["fingerprint"],
                          "report": (archive / "report.json").relative_to(directory).as_posix(),
                          "report_sha256": digest(archive / "report.json")}
    ready_check(root, directory, metadata)
    write_metadata(directory / "metadata.toml", metadata)
    return archive
