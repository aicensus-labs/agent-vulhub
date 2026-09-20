"""Versioned evidence, input fingerprints, and reviewable readiness records."""

import hashlib
import json
from pathlib import Path
import re
import tomllib

SCHEMA = 1
CASES = (("vulnerable", "attack"), ("patched", "attack"),
         ("vulnerable", "benign"), ("patched", "benign"))
HASH = re.compile(r"[0-9a-f]{64}")
IMAGE = re.compile(r"[^\s]+@sha256:[0-9a-f]{64}")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def contained(base, relative):
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"Unsafe relative path: {relative}")
    result = base / path
    if any(p.is_symlink() for p in [result, *result.parents] if p != base.parent):
        raise ValueError(f"Symlink is not evidence/build input: {relative}")
    if not result.resolve().is_relative_to(base.resolve()):
        raise ValueError(f"Path escapes directory: {relative}")
    return result


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def read_json(path):
    if Path(path).stat().st_size > 8 * 1024 * 1024:
        raise ValueError(f"JSON exceeds 8 MiB: {path}")
    return json.loads(Path(path).read_text(encoding="utf-8"))


def toml_value(value):
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{json.dumps(k)} = {toml_value(v)}" for k, v in value.items()) + " }"
    raise ValueError(f"Unsupported metadata value: {type(value).__name__}")


def write_metadata(path, data):
    # Inline tables keep this writer small and round-trip through the stdlib parser.
    content = "\n".join(f"{json.dumps(k)} = {toml_value(v)}" for k, v in data.items()) + "\n"
    if tomllib.loads(content) != data:
        raise ValueError("Metadata serialization did not round-trip")
    backup = path.with_suffix(".toml.before-update")
    if not backup.exists():
        backup.write_bytes(path.read_bytes())
    temporary = path.with_suffix(".toml.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def fingerprint(root, directory, metadata):
    inputs = {}
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory)
        if relative.parts[0] in {"evidence", "results", "__pycache__", ".cache", ".git"}:
            continue
        if relative.parts[0] == "diagram":
            # Rendered diagrams are documentation, like README prose.
            continue
        if relative.parts[0] == ".env" or (relative.parts[0].startswith(".env.") and relative.parts[0] != ".env.example"):
            continue
        if path.name.startswith("metadata.toml") or path.name == "diagram.toml" or path.suffix == ".pyc":
            continue
        if path.suffix == ".md" and relative.parts[0] != "fixtures":
            continue
        if path.is_symlink():
            raise ValueError(f"Symlink build input: {relative}")
        if path.is_file():
            inputs[str(relative)] = digest(path)
    for path in sorted((root / "runner").glob("*.py")):
        inputs[f"@runner/{path.name}"] = digest(path)
    contract = root / "docs/environment-contract.md"
    if contract.exists():
        inputs["@contract"] = digest(contract)
    material = {k: v for k, v in metadata.items()
                if k not in {"lifecycle", "verification", "review", "title", "description", "advisories"}}
    payload = json.dumps({"files": inputs, "metadata": material}, sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


def runner_fingerprint(root):
    """Return a digest for the runner implementation and its execution contract."""
    files = {}
    for path in sorted((root / "runner").glob("*.py")):
        files[path.name] = digest(path)
    contract = root / "docs/environment-contract.md"
    if contract.exists():
        files["@contract"] = digest(contract)
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()


def check_fixtures(directory):
    manifest = tomllib.loads((directory / "fixtures/manifest.toml").read_text())
    entries = manifest.get("files", {})
    if not isinstance(entries, dict):
        raise ValueError("Fixture manifest files must be a table")
    actual = set()
    for path in (directory / "fixtures").rglob("*"):
        if path.is_symlink():
            raise ValueError("Fixture symlinks are forbidden")
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        if path.is_file() and path.name not in {"manifest.toml", "README.md"}:
            actual.add(path.relative_to(directory / "fixtures").as_posix())
    if set(entries) != actual:
        raise ValueError("Fixture manifest does not cover exactly the fixture files")
    for name, sha in entries.items():
        if not isinstance(sha, str) or not HASH.fullmatch(sha) or digest(contained(directory / "fixtures", name)) != sha:
            raise ValueError(f"Fixture hash mismatch: {name}")


def validate_verdict(directory, context):
    facts = read_json(directory / "facts.json")
    verdict = read_json(directory / "verdict.json")
    for document in (facts, verdict):
        for key in ("schema_version", "run_id", "case_id", "variant", "scenario"):
            if document.get(key) != context[key]:
                raise ValueError(f"Evidence context mismatch: {key}")
    if facts.get("execution_status") != "completed":
        raise ValueError("PoC did not record completed execution")
    evidence = facts.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("Missing independently checkable evidence")
    names = set()
    for item in evidence:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ValueError("Evidence requires path and sha256")
        name = item["path"]
        if name in names or name in {"facts.json", "verdict.json", "context.json"}:
            raise ValueError("Duplicate or self-referential evidence")
        names.add(name)
        if digest(contained(directory, name)) != item["sha256"]:
            raise ValueError(f"Evidence hash mismatch: {name}")
    checks = verdict.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ValueError("Verifier returned no checks")
    required = "benign_task_passed" if context["scenario"] == "benign" else (
        "vulnerable_effect_observed" if context["variant"] == "vulnerable" else "patched_effect_blocked")
    ids = set()
    for check in checks:
        if not isinstance(check, dict) or not isinstance(check.get("passed"), bool):
            raise ValueError("Check passed must be a boolean")
        if not check.get("id") or check["id"] in ids or not check.get("reason"):
            raise ValueError("Check requires unique id and reason")
        ids.add(check["id"])
        for field in ("expected", "actual"):
            if field not in check:
                raise ValueError(f"Check requires {field}")
        if not check.get("evidence") or not set(check["evidence"]).issubset(names):
            raise ValueError("Check must reference collected evidence")
    if required not in ids or "target_ready" not in ids:
        raise ValueError(f"Missing required checks: target_ready, {required}")
    passed = all(c["passed"] for c in checks)
    if verdict.get("outcome") != ("passed" if passed else "failed"):
        raise ValueError("Verdict outcome disagrees with check results")
    return verdict


def validate_report(report, expected_fingerprint):
    if report.get("schema_version") != SCHEMA or report.get("fingerprint") != expected_fingerprint:
        raise ValueError("Evidence is stale or uses an unsupported schema")
    if report.get("outcome") != "passed" or report.get("exit_code") != 0:
        raise ValueError("Only passing reports can be promoted")
    if report.get("platform") != "linux/amd64" or report.get("host_system") != "Linux":
        raise ValueError("Promotion requires native Linux amd64")
    if report.get("host_architecture") not in {"x86_64", "AMD64"}:
        raise ValueError("Promotion requires native amd64 host architecture")
    if report.get("docker_operating_system", "").lower().find("docker desktop") >= 0:
        raise ValueError("Docker Desktop is not the mandatory native platform")
    for key in ("docker_version", "compose_version", "runner_fingerprint"):
        if not report.get(key):
            raise ValueError(f"Missing toolchain field: {key}")
    cases = report.get("cases", [])
    rounds = report.get("rounds")
    if not isinstance(rounds, int) or rounds < 3 or len(cases) != rounds * 4:
        raise ValueError("Promotion needs at least three complete rounds")
    projects = set()
    images = {}
    for number in range(1, rounds + 1):
        batch = [c for c in cases if c.get("round") == number]
        if len(batch) != 4 or {(c.get("variant"), c.get("scenario")) for c in batch} != set(CASES):
            raise ValueError("Incomplete or duplicate round")
        for case in batch:
            if case.get("run_id") != report.get("run_id"):
                raise ValueError("Case run_id does not match report")
            if case.get("environment_id") != report.get("environment_id"):
                raise ValueError("Case environment_id does not match report")
            if case.get("outcome") != "passed" or case.get("exit_code") != 0 or not case.get("cleaned"):
                raise ValueError("A case failed or left resources behind")
            if not re.fullmatch(r"[0-9a-f]{40}", case.get("source_commit", "")):
                raise ValueError("Case source revision must be pinned")
            project = case.get("project")
            if not project or project in projects:
                raise ValueError("Cases must have independent Compose projects")
            projects.add(project)
            image = case.get("image")
            if not isinstance(image, str) or not (IMAGE.fullmatch(image) or IMAGE_ID.fullmatch(image)):
                raise ValueError("Case image is not immutable")
            if images.setdefault(case["variant"], image) != image:
                raise ValueError("Images changed between rounds")
    return report
