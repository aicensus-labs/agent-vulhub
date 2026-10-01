"""Register, build, reproduce, and review isolated CVE environments."""

import argparse
import json
import os
from pathlib import Path
import re
import sys
import tomllib

# The checkout that owns this package. `AVH_ROOT` points the same CLI at a
# separate registry root (for example a staging tree produced by `runner
# harvest`) so drafts can be checked, linted and diagrammed without touching
# the public `environments.toml`.
CHECKOUT = Path(__file__).resolve().parents[1]
ROOT = Path(os.environ.get("AVH_ROOT") or CHECKOUT).resolve()
PRODUCT = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
IDENTIFIER = re.compile(r"(?:CVE-[0-9]{4}-[0-9]{4,}|GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4,})", re.I)
COMMIT = re.compile(r"[0-9a-f]{40}")
IMAGE = re.compile(r"[^\s]+@sha256:[0-9a-f]{64}")
REQUIRED_FILES = (
    "metadata.toml", "README.zh-cn.md", "compose.yaml", "Dockerfile",
    "reproduce.py", "end_to_end.py", "verify.py", "fixtures/README.md",
    "fixtures/manifest.toml",
)
STATUSES = {"not_run", "passed", "failed", "not_applicable"}
# Advisory severity, normalized to the vocabulary the harvest provenance uses.
# ``UNKNOWN`` is a declared value, not a placeholder: it records that no
# authoritative source published a severity for this identifier.
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"}


class RegistryError(ValueError):
    pass


def read_toml(path: Path) -> dict:
    with path.open("rb") as stream:
        return tomllib.load(stream)


def split_id(value: str) -> tuple[str, str]:
    parts = value.split("/")
    if len(parts) != 2 or not PRODUCT.fullmatch(parts[0]) or not IDENTIFIER.fullmatch(parts[1]):
        raise RegistryError(f"Invalid environment id: {value!r}")
    return parts[0], parts[1]


def load_registry(root: Path) -> list[dict]:
    registry = read_toml(root / "environments.toml")
    if registry.get("schema_version") != 1 or not isinstance(registry.get("environments"), list):
        raise RegistryError("Expected schema_version = 1 and an environments array")
    entries = registry["environments"]
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"id", "path"}:
            raise RegistryError("Each index entry must contain only id and path")
        if not isinstance(entry["id"], str):
            raise RegistryError("Environment id must be a string")
        split_id(entry["id"])
        if entry["id"] in seen:
            raise RegistryError(f"Duplicate id: {entry['id']}")
        seen.add(entry["id"])
        if entry["path"] != f"environments/{entry['id']}":
            raise RegistryError(f"Invalid path for {entry['id']}")
        target = root / entry["path"]
        if not target.resolve().is_relative_to((root / "environments").resolve()):
            raise RegistryError(f"Environment path escapes root: {entry['path']}")
    return entries


def validate_metadata(data: dict, environment_id: str) -> None:
    product, identifier = split_id(environment_id)
    metadata_key = "cve" if identifier.startswith("CVE-") else "ghsa"
    for key, expected in {"schema_version": 1, "id": environment_id, "product": product, metadata_key: identifier}.items():
        if data.get(key) != expected:
            raise RegistryError(f"{environment_id}: metadata {key} must equal {expected!r}")
    if data.get("lifecycle") not in {"draft", "ready"}:
        raise RegistryError(f"{environment_id}: lifecycle must be draft or ready")
    if data.get("agent_specificity") not in {"unclassified", "agent_related", "agent_unique"}:
        raise RegistryError(f"{environment_id}: invalid agent_specificity")
    if data.get("severity") not in SEVERITIES:
        raise RegistryError(
            f"{environment_id}: severity must be one of {sorted(SEVERITIES)}"
        )
    runtime = data.get("runtime", {})
    if not isinstance(runtime, dict) or runtime.get("harness", "python3") not in {"python3", "node"}:
        raise RegistryError(f"{environment_id}: runtime.harness must be python3 or node")
    verification = data.get("verification", {})
    if not isinstance(verification, dict):
        raise RegistryError(f"{environment_id}: verification must be a table")
    for layer in ("mechanism", "end_to_end"):
        result = verification.get(layer, {})
        if not isinstance(result, dict) or result.get("status") not in STATUSES:
            raise RegistryError(f"{environment_id}: invalid verification.{layer}.status")
        if result["status"] in {"passed", "failed"} and not (result.get("verified_at") and result.get("evidence")):
            raise RegistryError(f"{environment_id}: {layer} result needs date and evidence")
        if result["status"] == "not_applicable" and not result.get("notes"):
            raise RegistryError(f"{environment_id}: {layer} not_applicable needs a reason")
    adapter = verification.get("agent_poc", {})
    if not isinstance(adapter, dict) or adapter.get("status", "not_run") not in STATUSES:
        raise RegistryError(f"{environment_id}: invalid verification.agent_poc.status")
    if adapter.get("adapter_status", "not_run") not in {"not_run", "accepted"}:
        raise RegistryError(f"{environment_id}: invalid verification.agent_poc.adapter_status")
    if adapter.get("adapter_status") == "accepted" and not (adapter.get("verified_at") and adapter.get("evidence") and adapter.get("notes")):
        raise RegistryError(f"{environment_id}: accepted Agent-PoC Adapter needs date, evidence and notes")
    if data["lifecycle"] == "ready":
        if not data.get("advisories") or not data.get("title") or str(data["title"]).startswith("TODO"):
            raise RegistryError(f"{environment_id}: ready environment needs title and advisories")
        if data["agent_specificity"] == "unclassified":
            raise RegistryError(f"{environment_id}: ready environment needs classification")
        # Publishing is optional (ADR-0004): a ready environment's reproducibility comes
        # from pinned build inputs. When images *are* published, both variants must pin a
        # digest -- a half-published environment is not reproducible either way.
        published = [variant for variant in ("vulnerable", "patched")
                     if str(data.get(variant, {}).get("image", "")).strip()]
        if published and len(published) != 2:
            raise RegistryError(
                f"{environment_id}: {published[0]} has an image digest but the other variant does not")
        for variant in ("vulnerable", "patched"):
            version = data.get(variant, {})
            if not isinstance(version, dict) or not version.get("version") or not version.get("source_url"):
                raise RegistryError(f"{environment_id}: {variant} needs version and source_url")
            if not COMMIT.fullmatch(str(version.get("commit", ""))):
                raise RegistryError(f"{environment_id}: {variant} needs a pinned commit")
            image = str(version.get("image", "")).strip()
            if image and not IMAGE.fullmatch(image):
                raise RegistryError(f"{environment_id}: {variant} image must be an immutable digest reference")


def check_evidence(root: Path, directory: Path, data: dict) -> None:
    """Confirm claimed mechanism evidence still describes this tree.

    ``ready_check`` only inspects environments that are already ``ready``, so a draft can
    claim ``passed`` while pointing at a report whose input fingerprint no longer matches.
    Promotion would reject it later; surfacing it at ``check`` time keeps the registry
    honest without running anything. This is a static comparison of recorded JSON.
    """
    layer = data.get("verification", {}).get("mechanism", {})
    if layer.get("status") != "passed":
        return
    evidence = layer.get("evidence") or []
    if not evidence:
        raise RegistryError(f"{data['id']}: passed mechanism needs evidence")
    from .protocol import contained, fingerprint, read_json
    expected = fingerprint(root, directory, data)
    for relative in evidence:
        # ``verification.mechanism.evidence`` is resolved against the environment
        # directory, matching ``promote`` (which writes ``review.report``) and
        # ``ready_check`` (which reads it). A pre-promotion draft recorded the path
        # from the repository root instead, so that form is accepted as a fallback.
        # Resolving against the root unconditionally broke ``runner check`` on the
        # first promoted environment, because the two conventions disagree.
        path = contained(directory, relative)
        if not path.is_file():
            fallback = contained(root, relative)
            if not fallback.is_file():
                raise RegistryError(f"{data['id']}: missing evidence {relative}")
            path = fallback
        report = read_json(path)
        if report.get("environment_id") != data["id"]:
            raise RegistryError(f"{data['id']}: evidence {relative} belongs to another environment")
        if report.get("fingerprint") != expected:
            raise RegistryError(
                f"{data['id']}: evidence {relative} is stale for the current inputs"
            )


def _check_research_results(root: Path, environment_id: str) -> None:
    """Reject malformed stage-result files instead of silently ignoring them.

    ``result_status`` reads ``status`` with a regex and returns ``not_run`` when the
    pattern is absent, so an unparsable ``*-res.toml`` degrades to "this stage never
    ran" and the batch driver never notices. Three such files existed in the registry
    -- an unescaped ``\\s`` in a reason string, and two double quotes nested in a
    single-quoted string -- so a stage that genuinely passed was reported as unaudited
    and one environment disappeared from the tracked set entirely. Parse them here.
    """
    product, identifier = environment_id.split("/", 1)
    research = Path(root) / "research" / product / identifier
    if not research.is_dir():
        return
    for path in sorted(research.glob("*-res.toml")):
        match = re.match(r"^(analyze|generate|build|validate|solve)-res\.toml$", path.name)
        if not match:
            continue
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as error:
            raise RegistryError(
                f"{environment_id}: research/{path.name} is not valid TOML ({error}); "
                f"a malformed result file is ignored by result_status and silently "
                f"downgrades a real stage to not_run") from error
        status = data.get("status")
        if status not in ("continue", "error"):
            raise RegistryError(
                f"{environment_id}: research/{path.name} status is {status!r}, "
                f"expected 'continue' or 'error'")
        if data.get("stage") not in (None, match.group(1)):
            raise RegistryError(
                f"{environment_id}: research/{path.name} declares stage "
                f"{data.get('stage')!r}, expected {match.group(1)!r}")
        if status == "continue":
            missing = [key for key in ("environment_id", "reason", "evidence", "updated_at")
                       if key not in data]
            if missing:
                raise RegistryError(
                    f"{environment_id}: research/{path.name} claims status=continue but "
                    f"is missing {missing}")
            if not isinstance(data.get("evidence"), list) or not data["evidence"]:
                raise RegistryError(
                    f"{environment_id}: research/{path.name} claims status=continue "
                    f"without non-empty evidence")


def check(root: Path) -> list[dict]:
    entries = load_registry(root)
    indexed = {entry["path"] for entry in entries}
    for entry in entries:
        directory = root / entry["path"]
        for name in REQUIRED_FILES:
            path = directory / name
            if not path.is_file() or not path.resolve().is_relative_to(directory.resolve()):
                raise RegistryError(f"{entry['id']}: missing or external file {name}")
        validate_metadata(read_toml(directory / "metadata.toml"), entry["id"])
        from .protocol import check_fixtures
        from .lifecycle import ready_check
        from . import diagram
        data = read_toml(directory / "metadata.toml")
        # Name the environment: this is the only check in the loop that used to raise
        # without one, so a batch run reported a bare "manifest does not cover exactly
        # the fixture files" with no way to tell which of 300+ environments was at fault.
        try:
            check_fixtures(directory)
        except ValueError as error:
            raise RegistryError(f"{entry['id']}: {error}") from error
        try:
            rendered = diagram.load(directory)
            if rendered is not None:
                diagram.check(directory, rendered)
        except ValueError as error:
            raise RegistryError(f"{entry['id']}: {error}") from error
        ready_check(root, directory, data)
        check_evidence(root, directory, data)
        _check_research_results(root, entry["id"])
    for path in (root / "environments").glob("*/*/metadata.toml"):
        if path.parent.relative_to(root).as_posix() not in indexed:
            raise RegistryError(f"Unregistered environment: {path.parent.relative_to(root)}")
    return entries


def scaffold(root: Path, product: str, identifier: str, verify: bool = True) -> Path:
    """Create and register a draft from the template.

    ``verify`` runs the full registry check first, which catches a duplicate id or a
    broken sibling. Batch callers pass ``verify=False``: one pre-existing invalid
    draft must not stop a harvest from scaffolding the rest, since every draft in a
    staging root is unverified by design.
    """
    environment_id = f"{product}/{identifier}"
    _, normalized = split_id(environment_id)
    metadata_key = "cve" if normalized.startswith("CVE-") else "ghsa"
    entries = check(root) if verify else load_registry(root)
    target = root / "environments" / product / identifier
    if target.exists() or any(entry["id"] == environment_id for entry in entries):
        raise RegistryError(f"Environment already exists: {environment_id}")
    if not target.resolve().is_relative_to((root / "environments").resolve()):
        raise RegistryError("Destination escapes environments directory")
    template = root / "templates" / "environment"
    files = list(template.rglob("*"))
    if not (template / "metadata.toml").is_file():
        raise RegistryError("Environment template is missing")
    rendered = {}
    for path in files:
        if path.is_file():
            rendered[path.relative_to(template)] = path.read_text(encoding="utf-8").replace(
                "{{PRODUCT}}", product).replace("{{CVE_KEY}}", metadata_key).replace("{{CVE}}", normalized)
    for name, content in rendered.items():
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
    from . import diagram
    scaffolded = diagram.load(target)
    if scaffolded is not None:
        diagram.validate(target, scaffolded)
        diagram.write_all(target, scaffolded)
    entries.append({"id": environment_id, "path": target.relative_to(root).as_posix()})
    lines = ["schema_version = 1", ""]
    for entry in sorted(entries, key=lambda entry: entry["id"]):
        lines.extend(["[[environments]]", f"id = {json.dumps(entry['id'])}", f"path = {json.dumps(entry['path'])}", ""])
    registry = root / "environments.toml"
    temporary = root / "environments.toml.tmp"
    temporary.write_text("\n".join(lines), encoding="utf-8")
    temporary.replace(registry)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="List registered environments")
    commands.add_parser("check", help="Validate metadata and required files without executing code")
    agent_task = commands.add_parser("agent-task", help="Package a visible Agent-PoC task")
    agent_task.add_argument("environment")
    agent_task.add_argument("--level", choices=("0", "1"), default="1")
    agent_task.add_argument("--out-dir", required=True)
    agent_task.add_argument("--offline", action="store_true")
    new = commands.add_parser("new", help="Create and register a draft from the template")
    new.add_argument("product")
    new.add_argument("identifier", help="CVE or GHSA identifier")
    harvest_command = commands.add_parser(
        "harvest", help="Select agent_unique AgentSec candidates and scaffold staging drafts")
    harvest_command.add_argument("--db", required=True, help="Path to the AgentSec SQLite database")
    harvest_command.add_argument("--out", required=True, help="Staging registry root to write")
    harvest_command.add_argument("--registry-root", help="Registry compared for coverage (default: this checkout)")
    harvest_command.add_argument("--min-research-value", type=positive_int, default=4)
    harvest_command.add_argument("--limit", type=positive_int, help="Select at most N candidates")
    harvest_command.add_argument("--product", help="Force a product slug (requires --limit 1)")
    harvest_command.add_argument("--identifier", action="append",
                                 help="Only these CVE/GHSA identifiers (repeatable)")
    harvest_command.add_argument("--include-covered", action="store_true",
                                 help="Keep candidates that already have an environment")
    harvest_command.add_argument("--scaffold", action="store_true",
                                 help="Also scaffold a draft environment per candidate")
    harvest_command.add_argument("--json", action="store_true", dest="as_json",
                                 help="Print the harvest index as JSON")
    factory_command = commands.add_parser(
        "factory", help="Drive the six-stage reproduction factory for a staged draft")
    factory_command.add_argument("action", choices=("brief", "gate", "status"))
    factory_command.add_argument("environment", nargs="?")
    factory_command.add_argument("--stage", help="Stage id: analyze, generate, build, validate, solve, check")
    factory_command.add_argument("--execute", action="store_true",
                                 help="Actually run Docker/lint gates instead of reporting only")
    factory_command.add_argument("--timeout", type=positive_int, default=1200)
    batch_command = commands.add_parser(
        "batch", help="Queue harvested drafts and advance their factory gates in bulk")
    batch_command.add_argument("action", choices=("queue", "run", "progress"))
    batch_command.add_argument("--batch-id", required=True, help="Batch identifier, e.g. wave-001")
    batch_command.add_argument("--environment", action="append", dest="environments",
                               help="Environment id to include; repeatable")
    batch_command.add_argument("--stage", action="append", dest="stages",
                               help="Restrict to these stage ids; repeatable")
    batch_command.add_argument("--execute", action="store_true",
                               help="Run Docker gates; without it they are reported as awaiting-execute")
    batch_command.add_argument("--limit", type=positive_int, help="Advance at most this many environments")
    batch_command.add_argument("--timeout", type=positive_int, default=1200)
    batch_command.add_argument("--json", action="store_true", dest="as_json",
                               help="Print the batch report as JSON")
    commands.add_parser("refresh", help="Downgrade stale ready environments; preserve historical evidence")
    prune_command = commands.add_parser(
        "prune", help="Delete untagged GHCR package versions left by publication")
    prune_command.add_argument("--repository", required=True, help="ghcr.io/owner/package")
    prune_command.add_argument("--apply", action="store_true",
                               help="Actually delete; without it only report what would go")
    prune_command.add_argument("--timeout", type=positive_int, default=120)
    lint = commands.add_parser("lint", help="Parse Compose via Docker CLI without starting containers")
    lint.add_argument("environment", nargs="?")
    diagram_command = commands.add_parser("diagram", help="Render Mermaid mechanism diagrams from diagram.toml")
    diagram_command.add_argument("environment", nargs="?")
    diagram_command.add_argument("--all", action="store_true", dest="every", help="Render every environment that has diagram.toml")
    diagram_command.add_argument("--check", action="store_true", help="Report drift without writing")
    diagram_command.add_argument("--missing", action="store_true", help="List environments without diagram.toml")
    for name in ("fetch", "build", "reproduce", "agent-evaluate", "promote", "publish"):
        command = commands.add_parser(name)
        command.add_argument("environment")
        if name in {"fetch", "build", "reproduce", "agent-evaluate"}:
            command.add_argument("--offline", action="store_true")
        if name in {"build", "reproduce", "agent-evaluate", "publish"}:
            command.add_argument("--timeout", type=positive_int, default=300)
        if name in {"reproduce", "agent-evaluate"}:
            source = command.add_mutually_exclusive_group()
            source.add_argument("--build", action="store_true", help="Build pinned source locally before execution")
            source.add_argument("--images", help="Use a local build.json manifest")
            command.add_argument("--rounds", type=positive_int, default=1)
            command.add_argument("--keep-on-failure", action="store_true")
            command.add_argument("--allow-exceptions", action="store_true", help="Apply only explicitly documented isolation exceptions")
            if name == "reproduce":
                command.add_argument("--scenario", choices=("all", "vulnerable", "patched", "benign"), default="all")
        if name == "agent-evaluate":
            command.add_argument("--task-dir", required=True)
            command.add_argument("--candidate", required=True)
            command.add_argument("--agent-meta", help="JSON provenance for the Agent/model/toolchain (no secrets)")
        if name == "promote":
            command.add_argument("--report", required=True)
            command.add_argument("--reviewer", action="append", required=True)
            command.add_argument("--reviewed", action="store_true", required=True,
                                 help="Attest that evidence, source, safety and redaction were reviewed")
        if name == "publish":
            command.add_argument("--images", required=True)
            command.add_argument("--repository", required=True, help="ghcr.io/owner/package")
    args = parser.parse_args(argv)
    try:
        if args.command == "batch":
            from . import batch as batch_module
            if args.action == "queue":
                if not args.environments:
                    raise RegistryError("batch queue needs at least one --environment")
                queued = batch_module.queue(ROOT, args.environments, batch_id=args.batch_id)
                for entry in queued["entries"]:
                    print(f"{entry['environment_id']}\tnext={entry['next_stage']}\t{entry['brief'] or ''}")
                print(f"batch {args.batch_id}: {len(queued['entries'])} environment(s)")
                return 0
            if args.action == "run":
                report = batch_module.run_batch(
                    ROOT, args.batch_id, stages=args.stages, execute=args.execute,
                    timeout=args.timeout, limit=args.limit)
                if args.as_json:
                    print(json.dumps(report, ensure_ascii=False, indent=2))
                    return 0
                for outcome in report["outcomes"]:
                    detail = outcome.get("reason") or outcome.get("brief") or ""
                    problems = outcome.get("problems") or []
                    print(f"{outcome['environment_id']}\t{outcome['stage']}\t{outcome['outcome']}\t{detail}")
                    for problem in problems:
                        print(f"    BLOCKED: {problem}", file=sys.stderr)
                print(f"batch {args.batch_id}: attempted {report['attempted']}")
                failed = [item for item in report["outcomes"] if item["outcome"] in {"failed", "error"}]
                return 0 if not failed else 1
            report = batch_module.progress(ROOT, args.batch_id)
            if args.as_json:
                print(json.dumps(report, ensure_ascii=False, indent=2))
                return 0
            print(f"batch {report['batch_id']}: {report['environments']} environment(s), "
                  f"{report['complete']} complete")
            for stage_id, count in sorted(report["awaiting_stage"].items()):
                print(f"  awaiting {stage_id}: {count}")
            for item in report["blocked"]:
                print(f"  BLOCKED {item['environment_id']} at {item['stage']}: {item['problems'][:2]}",
                      file=sys.stderr)
            return 0
        if args.command == "factory":
            from . import factory as factory_module
            if args.action == "brief":
                if not args.environment or not args.stage:
                    raise RegistryError("factory brief needs an environment and --stage")
                path = factory_module.write_brief(ROOT, args.environment, args.stage)
                print(path.read_text(encoding="utf-8"), end="")
                print(f"\n<!-- written to {path} -->")
                return 0
            if args.action == "gate":
                if not args.environment or not args.stage:
                    raise RegistryError("factory gate needs an environment and --stage")
                result = factory_module.gate(
                    ROOT, args.environment, args.stage, execute=args.execute, timeout=args.timeout)
                for run in result["runs"]:
                    print(f"$ {' '.join(run['command'])} -> {run['returncode']}")
                    if run["stdout"].strip():
                        print(run["stdout"].strip())
                    if run["stderr"].strip():
                        print(run["stderr"].strip(), file=sys.stderr)
                for problem in result["problems"]:
                    print(f"BLOCKED: {problem}", file=sys.stderr)
                print(f"{result['stage']}: {'passed' if result['passed'] else 'failed'}")
                return 0 if result["passed"] else 1
            if args.environment:
                state = factory_module.read_state(ROOT, args.environment)
                for stage in factory_module.STAGES:
                    print(f"{stage.id}\t{state['stages'].get(stage.id, 'not_run')}")
            else:
                for entry in load_registry(ROOT):
                    state = factory_module.read_state(ROOT, entry["id"])
                    done = sum(1 for value in state["stages"].values() if value == "passed")
                    print(f"{entry['id']}\t{done}/{len(factory_module.STAGES)}")
            return 0
        if args.command == "harvest":
            from .harvest import harvest
            index = harvest(
                Path(args.db),
                Path(args.out),
                checkout=CHECKOUT,
                registry_root=Path(args.registry_root) if args.registry_root else CHECKOUT,
                min_research_value=args.min_research_value,
                limit=args.limit,
                include_covered=args.include_covered,
                scaffold=args.scaffold,
                product=args.product,
                identifiers=tuple(args.identifier) if args.identifier else None,
            )
            if args.as_json:
                print(json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True))
            else:
                totals = index["totals"]
                print(f"Qualifying: {totals['qualifying']}, already covered: {totals['covered']}, "
                      f"selected: {totals['selected']}")
                for entry in index["candidates"]:
                    state = "draft" if entry["scaffolded"] else "candidate"
                    print(f"  [{state}] {entry['environment_id']}\t{entry['title'][:70]}")
                for failure in index["failures"]:
                    print(f"  ERROR {failure}", file=sys.stderr)
                print(f"Index: {Path(args.out) / 'candidates' / 'index.json'}")
            return 0
        if args.command == "agent-task":
            from .agent_poc import create_task
            split_id(args.environment)
            entries = load_registry(ROOT)
            if args.environment not in {entry["id"] for entry in entries}:
                raise RegistryError(f"Unknown environment: {args.environment}")
            directory = ROOT / "environments" / args.environment
            metadata = read_toml(directory / "metadata.toml")
            validate_metadata(metadata, args.environment)
            output = create_task(ROOT, directory, metadata, int(args.level), Path(args.out_dir), args.offline)
            print(output)
            return 0
        if args.command == "diagram":
            from . import diagram as diagrams
            entries = load_registry(ROOT)
            if args.missing:
                for entry in entries:
                    if diagrams.load(ROOT / entry["path"]) is None:
                        print(entry["id"])
                return 0
            if args.every:
                targets = list(entries)
            elif args.environment:
                if args.environment not in {entry["id"] for entry in entries}:
                    raise RegistryError(f"Unknown environment: {args.environment}")
                targets = [entry for entry in entries if entry["id"] == args.environment]
            else:
                raise RegistryError("diagram needs an environment, --all, or --missing")
            problems = []
            missing = []
            rendered = 0
            for entry in targets:
                directory = ROOT / entry["path"]
                data = diagrams.load(directory)
                if data is None:
                    if args.check:
                        missing.append(entry["id"])
                    elif not args.every:
                        raise RegistryError(f"{entry['id']}: diagram.toml is missing")
                    continue
                diagrams.validate(directory, data)
                if args.check:
                    problems.extend(f"{entry['id']}: {item}" for item in diagrams.drift(directory, data))
                    continue
                changed = diagrams.write_all(directory, data)
                rendered += 1
                print(f"{entry['id']}: {', '.join(changed) if changed else 'already up to date'}")
            for identifier in missing:
                print(f"MISSING: {identifier}: no diagram.toml yet")
            for problem in problems:
                print(f"DRIFT: {problem}", file=sys.stderr)
            if problems:
                print("Fix with: python3 -m runner diagram <environment>", file=sys.stderr)
                return 1
            if not args.check:
                print(f"Rendered {rendered} diagram(s)")
            return 0
        if args.command == "refresh":
            from .lifecycle import refresh
            for entry in load_registry(ROOT):
                directory = ROOT / entry["path"]
                if refresh(ROOT, directory, read_toml(directory / "metadata.toml")):
                    print(f"Downgraded: {entry['id']}")
            return 0
        if args.command == "lint":
            from .runtime import Commands, inspect_config
            from .build import validate_sources
            import tempfile
            entries = check(ROOT)
            if args.environment and args.environment not in {e['id'] for e in entries}:
                raise RegistryError("Unknown environment")
            with tempfile.TemporaryDirectory(prefix="avh-lint-") as temp:
                if not args.environment:
                    template = ROOT / "templates/environment"
                    placeholders = {v: "placeholder@sha256:" + "0" * 64 for v in ("vulnerable", "patched")}
                    template_metadata = tomllib.loads(
                        (template / "metadata.toml").read_text(encoding="utf-8")
                        .replace("{{PRODUCT}}", "template")
                        .replace("{{CVE_KEY}}", "cve")
                        .replace("{{CVE}}", "CVE-0000-0000")
                    )
                    inspect_config(Commands(Path(temp)), template, placeholders, "avh-template-lint",
                                   template_metadata, False)
                    print("Static Compose check: template")
                for entry in entries:
                    if args.environment and entry["id"] != args.environment:
                        continue
                    directory = ROOT / entry["path"]
                    data = read_toml(directory / "metadata.toml")
                    images = {v: data[v].get("image") or "placeholder@sha256:" + "0" * 64 for v in ("vulnerable", "patched")}
                    inspect_config(Commands(Path(temp)), directory, images, "avh-lint", data, True)
                    if data["lifecycle"] == "ready":
                        validate_sources(directory, data)
                    print(f"Static Compose check: {entry['id']}")
            return 0
        if args.command == "prune":
            from .prune import prune
            outcome = prune(args.repository, apply_changes=args.apply, timeout=args.timeout)
            print(json.dumps(outcome, indent=2))
            return 0
        if args.command in {"fetch", "build", "reproduce", "agent-evaluate", "promote", "publish"}:
            from .runtime import Commands, agent_evaluate, preflight, reproduce, utc
            from .build import build_images, fetch_inputs
            from .lifecycle import promote, refresh
            from .protocol import write_json
            import uuid
            split_id(args.environment)
            entries = load_registry(ROOT)
            if args.environment not in {e["id"] for e in entries}:
                raise RegistryError(f"Unknown environment: {args.environment}")
            directory = ROOT / "environments" / args.environment
            data = read_toml(directory / "metadata.toml")
            refresh(ROOT, directory, data)
            validate_metadata(data, args.environment)
            if args.command == "agent-evaluate":
                return agent_evaluate(ROOT, directory, data, args)
            if args.command == "reproduce":
                return reproduce(ROOT, directory, data, args)
            if args.command == "fetch":
                files = fetch_inputs(ROOT, directory, data, args.offline)
                print(f"Verified {len(files)} cached build input(s)")
            elif args.command == "build":
                output = ROOT / "results" / args.environment / ("build-" + uuid.uuid4().hex[:12])
                output.mkdir(parents=True)
                commands_io = Commands(output, args.timeout)
                try:
                    preflight(commands_io)
                    build_images(ROOT, directory, data, commands_io, args.offline)
                except Exception as error:
                    write_json(output / "failure.json", {"phase": "build", "actual": str(error), "time": utc()})
                    raise
                print(output / "build.json")
            elif args.command == "publish":
                from .publish import publish
                output = ROOT / "results" / args.environment / ("publish-" + uuid.uuid4().hex[:12])
                output.mkdir(parents=True)
                publish(ROOT, directory, data, args.images, args.repository, Commands(output, args.timeout))
                print(output / "publication.json")
            else:
                from .build import validate_sources
                validate_sources(directory, data)
                candidate = dict(data, lifecycle="ready")
                validate_metadata(candidate, args.environment)
                print(f"Reviewed evidence retained: {promote(ROOT, directory, data, args.report, args.reviewer)}")
            return 0
        if args.command == "new":
            print(f"Created draft: {scaffold(ROOT, args.product, args.identifier)}")
        else:
            entries = check(ROOT)
            if args.command == "check":
                from . import diagram as diagrams
                covered = sum(1 for entry in entries if diagrams.load(ROOT / entry["path"]) is not None)
                print(f"OK: {len(entries)} environment(s), {covered} with diagrams; "
                      "static checks only, no reproductions executed")
            elif not entries:
                print("No environments registered. Use 'python3 -m runner new --help' to add a draft.")
            else:
                for entry in entries:
                    metadata = read_toml(ROOT / entry["path"] / "metadata.toml")
                    print(f"{entry['id']}\t{metadata['lifecycle']}\t{metadata['agent_specificity']}")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2 if args.command in {"fetch", "build", "reproduce", "agent-task", "agent-evaluate", "promote", "publish"} else 1
    except Exception as error:
        from .runtime import RunError
        if not isinstance(error, RunError):
            raise
        print(f"ERROR ({error.phase}): {error}", file=sys.stderr)
        return error.code


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number
