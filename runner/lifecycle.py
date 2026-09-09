"""Local review attestations; Git branch protection supplies reviewer authorization."""

from datetime import datetime, timezone
from pathlib import Path
import shutil

from .protocol import (contained, digest, fingerprint, read_json, validate_report,
                       validate_verdict, write_json, write_metadata)


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
        if case["source_commit"] != metadata[case["variant"]]["commit"]:
            raise ValueError("Case source revision differs from reviewed metadata")
        path = contained(summary.parent, case["case_id"])
        actual = read_json(path / "result.json")
        if actual != case:
            raise ValueError("Case summary differs from retained result")
        verdict = validate_verdict(path / "evidence", case)
        if verdict["outcome"] != "passed" or verdict["checks"] != case.get("checks"):
            raise ValueError("Retained verdict disagrees with passing report")


def refresh(root, directory, metadata):
    if metadata.get("lifecycle") != "ready":
        return False
    try:
        ready_check(root, directory, metadata)
        return False
    except (ValueError, OSError, KeyError, TypeError) as error:
        history = directory / "evidence" / "history"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        write_json(history / f"{stamp}.json", {"action": "invalidate", "reason": str(error),
                   "previous_review": metadata.get("review"), "previous_verification": metadata.get("verification")})
        metadata["lifecycle"] = "draft"
        for value in metadata.get("verification", {}).values():
            value.update(status="not_run", verified_at="", evidence=[], notes="Previous evidence retained after invalidation")
        metadata.pop("review", None)
        write_metadata(directory / "metadata.toml", metadata)
        return True


def promote(root, directory, metadata, report_path, reviewers):
    minimum = 2 if metadata.get("runtime", {}).get("exceptions") else 1
    if len(set(reviewers)) < minimum or any(not x.strip() for x in reviewers):
        raise ValueError(f"Need {minimum} distinct reviewers")
    report_path = Path(report_path).resolve()
    report = validate_report(read_json(report_path), fingerprint(root, directory, metadata))
    if report.get("environment_id") != metadata["id"]:
        raise ValueError("Report belongs to another environment")
    archive = directory / "evidence" / report["run_id"]
    if not report["run_id"] or "/" in report["run_id"] or ".." in report["run_id"]:
        raise ValueError("Invalid run ID")
    # Check every retained result before copying or changing metadata.
    for case in report["cases"]:
        if case["source_commit"] != metadata[case["variant"]]["commit"]:
            raise ValueError("Case source revision differs from metadata")
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
    metadata["lifecycle"] = "ready"
    metadata["verification"]["mechanism"].update(status="passed", verified_at=report["finished_at"],
        evidence=[(archive / "report.json").relative_to(directory).as_posix()])
    metadata["review"] = {"reviewers": sorted(set(reviewers)), "fingerprint": report["fingerprint"],
                          "report": (archive / "report.json").relative_to(directory).as_posix(),
                          "report_sha256": digest(archive / "report.json")}
    ready_check(root, directory, metadata)
    write_metadata(directory / "metadata.toml", metadata)
    return archive
