"""List, validate and scaffold environments without executing their code."""

import argparse
import json
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PRODUCT = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
COMMIT = re.compile(r"[0-9a-f]{40}")
IMAGE = re.compile(r"[^\s]+@sha256:[0-9a-f]{64}")
REQUIRED_FILES = (
    "metadata.toml", "README.zh-cn.md", "compose.yaml", "Dockerfile",
    "reproduce.py", "end_to_end.py", "verify.py", "fixtures/README.md",
)
STATUSES = {"not_run", "passed", "failed", "not_applicable"}


class RegistryError(ValueError):
    pass


def read_toml(path: Path) -> dict:
    with path.open("rb") as stream:
        return tomllib.load(stream)


def split_id(value: str) -> tuple[str, str]:
    parts = value.split("/")
    if len(parts) != 2 or not PRODUCT.fullmatch(parts[0]) or not CVE.fullmatch(parts[1]):
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
    product, cve = split_id(environment_id)
    for key, expected in {"schema_version": 1, "id": environment_id, "product": product, "cve": cve}.items():
        if data.get(key) != expected:
            raise RegistryError(f"{environment_id}: metadata {key} must equal {expected!r}")
    if data.get("lifecycle") not in {"draft", "ready"}:
        raise RegistryError(f"{environment_id}: lifecycle must be draft or ready")
    if data.get("agent_specificity") not in {"unclassified", "agent_related", "agent_unique"}:
        raise RegistryError(f"{environment_id}: invalid agent_specificity")
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
    for path in (root / "environments").glob("*/*/metadata.toml"):
        if path.parent.relative_to(root).as_posix() not in indexed:
            raise RegistryError(f"Unregistered environment: {path.parent.relative_to(root)}")
    return entries


def scaffold(root: Path, product: str, cve: str) -> Path:
    environment_id = f"{product}/{cve}"
    split_id(environment_id)
    entries = check(root)
    target = root / "environments" / product / cve
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
            rendered[path.relative_to(template)] = path.read_text(encoding="utf-8").replace("{{PRODUCT}}", product).replace("{{CVE}}", cve)
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
    new.add_argument("cve")
    args = parser.parse_args(argv)
    try:
        if args.command == "new":
            print(f"Created draft: {scaffold(ROOT, args.product, args.cve)}")
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
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
