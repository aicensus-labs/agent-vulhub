"""Register, build, reproduce, and review isolated CVE environments."""

import argparse
import json
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
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
    if data["lifecycle"] == "ready":
        if not data.get("advisories") or not data.get("title") or str(data["title"]).startswith("TODO"):
            raise RegistryError(f"{environment_id}: ready environment needs title and advisories")
        if data["agent_specificity"] == "unclassified":
            raise RegistryError(f"{environment_id}: ready environment needs classification")
        for variant in ("vulnerable", "patched"):
            version = data.get(variant, {})
            if not isinstance(version, dict) or not version.get("version") or not version.get("source_url"):
                raise RegistryError(f"{environment_id}: {variant} needs version and source_url")
            if not COMMIT.fullmatch(str(version.get("commit", ""))) or not IMAGE.fullmatch(str(version.get("image", ""))):
                raise RegistryError(f"{environment_id}: {variant} needs pinned commit and image digest")


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
        data = read_toml(directory / "metadata.toml")
        check_fixtures(directory)
        ready_check(root, directory, data)
    for path in (root / "environments").glob("*/*/metadata.toml"):
        if path.parent.relative_to(root).as_posix() not in indexed:
            raise RegistryError(f"Unregistered environment: {path.parent.relative_to(root)}")
    return entries


def scaffold(root: Path, product: str, identifier: str) -> Path:
    environment_id = f"{product}/{identifier}"
    _, normalized = split_id(environment_id)
    metadata_key = "cve" if normalized.startswith("CVE-") else "ghsa"
    entries = check(root)
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
    new = commands.add_parser("new", help="Create and register a draft from the template")
    new.add_argument("product")
    new.add_argument("identifier", help="CVE or GHSA identifier")
    commands.add_parser("refresh", help="Downgrade stale ready environments; preserve historical evidence")
    lint = commands.add_parser("lint", help="Parse Compose via Docker CLI without starting containers")
    lint.add_argument("environment", nargs="?")
    for name in ("fetch", "build", "reproduce", "promote", "publish"):
        command = commands.add_parser(name)
        command.add_argument("environment")
        if name in {"fetch", "build", "reproduce"}:
            command.add_argument("--offline", action="store_true")
        if name in {"build", "reproduce", "publish"}:
            command.add_argument("--timeout", type=positive_int, default=300)
        if name == "reproduce":
            source = command.add_mutually_exclusive_group()
            source.add_argument("--build", action="store_true", help="Build pinned source locally before execution")
            source.add_argument("--images", help="Use a local build.json manifest")
            command.add_argument("--rounds", type=positive_int, default=1)
            command.add_argument("--scenario", choices=("all", "vulnerable", "patched", "benign"), default="all")
            command.add_argument("--keep-on-failure", action="store_true")
            command.add_argument("--allow-exceptions", action="store_true", help="Apply only explicitly documented isolation exceptions")
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
                    inspect_config(Commands(Path(temp)), template, placeholders, "avh-template-lint",
                                   read_toml(template / "metadata.toml"), False)
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
        if args.command in {"fetch", "build", "reproduce", "promote", "publish"}:
            from .runtime import Commands, preflight, reproduce, utc
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
                print(f"OK: {len(entries)} environment(s); static checks only, no reproductions executed")
            elif not entries:
                print("No environments registered. Use 'python3 -m runner new --help' to add a draft.")
            else:
                for entry in entries:
                    metadata = read_toml(ROOT / entry["path"] / "metadata.toml")
                    print(f"{entry['id']}\t{metadata['lifecycle']}\t{metadata['agent_specificity']}")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2 if args.command in {"fetch", "build", "reproduce", "promote", "publish"} else 1
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
