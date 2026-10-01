"""Harvest agent-unique candidates from an AgentSec database into staging drafts.

This is stage 0 of the reproduction factory. It only *reads* the external
AgentSec SQLite database with ``immutable=1`` and ``query_only=ON``; it never
imports upstream project code, runs a PoC, or starts a container.

Selected candidates become two things:

* ``candidates/<IDENTIFIER>.toml`` — an auditable provenance record naming the
  database, its hash, the selection filters and the raw AgentSec rows;
* optionally, a draft environment scaffolded under ``<out>/environments/`` with
  the repository template, so ``AVH_ROOT=<out> python3 -m runner check`` and
  ``... diagram`` work on it without touching the public registry.

A generated draft is *not* a verified reproduction. It stays ``draft`` and
``not_run`` until the later factory stages build it and reproduce the mechanism.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import tomllib
from urllib.parse import quote

SCHEMA = 1
DEFAULT_MIN_RESEARCH_VALUE = 4
SPECIFICITY = "agent_unique"
RECOMMENDATION = "push"
# The database mixes cases and stores the KEV flag in the same column as the rating,
# so a raw value cannot be written to metadata.toml verbatim: `runner check` only
# accepts the declared vocabulary.
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"}
SEVERITY_ALIASES = {"MODERATE": "MEDIUM", "KNOWN_EXPLOITED": "HIGH"}


def normalize_severity(raw: str) -> str:
    """Map a raw advisory severity onto the vocabulary `runner check` accepts."""
    value = (raw or "").strip().upper()
    if value in SEVERITIES:
        return value
    return SEVERITY_ALIASES.get(value, "UNKNOWN")

# Reviewer metadata wins; the LLM analysis row is only a fallback. Ranking lets
# duplicate analysis rows collapse to the most specific / most valuable one.
SPECIFICITY_RANK = {"agent_unique": 3, "agent_related": 2, "generic": 1, "": 0}
RECOMMENDATION_RANK = {"push": 3, "watch": 2, "drop": 1, "": 0}

IDENTIFIER = re.compile(
    r"(?:CVE-[0-9]{4}-[0-9]{4,}|GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4,})",
    re.I,
)
REPOSITORY = re.compile(r"github\.com/([^/\s]+)/([^/\s#?]+)", re.I)
SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


class HarvestError(ValueError):
    """The database or the requested selection cannot be harvested."""


@dataclass(frozen=True)
class Candidate:
    """One deduplicated agent-unique vulnerability, ready to be scaffolded."""

    identifier: str
    aliases: tuple[str, ...]
    title: str
    advisory_url: str
    summary: str
    ecosystem: str
    package: str
    project: str
    severity: str
    owasp_agentic_category: str
    status: str
    published_at: str
    research_value: int
    specificity_source: str
    recommendation_source: str
    raw_item_ids: tuple[str, ...] = field(default_factory=tuple)
    references: tuple[str, ...] = field(default_factory=tuple)

    def repositories(self) -> list[str]:
        """Project repositories named by the advisory URL or its references.

        ``github.com/advisories/GHSA-...`` is the aggregator, not a project, so
        it is skipped in favour of a real ``owner/repo`` reference.
        """
        found: list[str] = []
        for url in (self.advisory_url, *self.references):
            match = REPOSITORY.search(url or "")
            if not match:
                continue
            owner, repository = match.group(1).lower(), match.group(2)
            if owner == "advisories" or repository.lower() in {"advisories", "security"}:
                continue
            if IDENTIFIER.fullmatch(repository):
                continue
            if repository not in found:
                found.append(repository)
        return found

    def resolve_product(self, known: dict[str, str] | None = None) -> tuple[str, str]:
        """Return ``(product_slug, source)`` for the environment id.

        The slug is provisional when it comes from the title: the analyzer stage
        confirms the real upstream project before anything is promoted.
        """
        for repository in self.repositories():
            if known and repository.lower() in known:
                return known[repository.lower()], "known_environment"
            slug = slugify(repository)
            if slug:
                return slug, "advisory_reference"
        for value in (self.package, self.project):
            if value:
                slug = slugify(str(value).split("/")[-1])
                if slug:
                    return slug, "package_metadata"
        return title_product(self.title), "title_heuristic"

    def product(self, known: dict[str, str] | None = None) -> str:
        return self.resolve_product(known)[0]


# Leading product names in titles such as "CVE-2026-73498: MCP Atlassian is a ...".
_LEAD = re.compile(r"^(?:CVE-\d{4}-\d+|GHSA-[\w-]+)\s*:\s*", re.I)
_STOP = (
    " is ", " are ", " was ", " were ", " has ", " have ", " allows ", " allow ",
    " before ", " prior ", " through ", " contains ", " lets ", " enables ",
    " executes ", " execute ", " permits ", " exposes ", " leaks ", " renders ",
    " accepts ", " provides ", " fails ", " does ", " in ", " via ", " when ",
    " where ", ":", ",", " - ",
)


def title_product(title: str) -> str:
    """Best-effort provisional product name taken from the advisory title."""
    text = _LEAD.sub("", (title or "").strip())
    text = re.sub(r"^(?:The|A|An)\s+", "", text, flags=re.I)
    lowered = text.lower()
    cut = len(text)
    for token in _STOP:
        index = lowered.find(token)
        if index != -1:
            cut = min(cut, index)
    return slugify(text[:cut].strip(" .,-")) or "agent-project"



def slugify(text: str) -> str:
    """Lowercase a name into a product slug matching ``[a-z0-9]+(-[a-z0-9]+)*``."""
    lowered = re.sub(r"[^a-z0-9]+", "-", str(text).strip().lower()).strip("-")
    return re.sub(r"-{2,}", "-", lowered)[:48].strip("-")


def identifiers_in(text: str) -> set[str]:
    return {match.group(0).upper() for match in IDENTIFIER.finditer(text or "")}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect_readonly(database: Path) -> sqlite3.Connection:
    """Open the AgentSec database without ever writing to it."""
    path = Path(database).expanduser()
    if not path.is_file():
        raise HarvestError(f"AgentSec database not found: {path}")
    connection = sqlite3.connect(f"file:{quote(str(path.resolve()))}?immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    return connection


def _best(values, rank: dict[str, int], default: str = "") -> str:
    candidates = [value for value in values if value]
    if not candidates:
        return default
    return max(candidates, key=lambda value: rank.get(value, 0))


def _int(value, default: int = 0) -> int:
    """SQLite is dynamically typed; never let a text score crash the harvest."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def query_candidates(connection: sqlite3.Connection, min_research_value: int) -> list[Candidate]:
    """Select effective ``agent_unique`` + ``push`` candidates and deduplicate them.

    Effective specificity/recommendation prefer ``vulnerability_metadata``
    (reviewer metadata) and only fall back to ``analysis_results``. Several raw
    items can describe the same advisory, so rows collapse by canonical
    identifier and the union of their raw item ids is retained for audit.
    """
    metadata = {row["raw_item_id"]: row for row in connection.execute("SELECT * FROM vulnerability_metadata")}
    analysis: dict[str, list[sqlite3.Row]] = {}
    for row in connection.execute("SELECT * FROM analysis_results"):
        analysis.setdefault(row["raw_item_id"], []).append(row)

    grouped: dict[str, dict] = {}
    rows = connection.execute(
        """
        SELECT v.vuln_id, v.aliases_json, v.references_json, v.raw_item_id, v.severity, v.published_at,
               r.title, r.url, r.canonical_url, r.content
        FROM vuln_items v
        JOIN raw_items r ON r.id = v.raw_item_id
        """
    )
    for row in rows:
        raw_item_id = row["raw_item_id"]
        reviewer = metadata.get(raw_item_id)
        reviews = analysis.get(raw_item_id, [])

        specificity = (reviewer["agent_specificity"] if reviewer else "") or _best(
            [item["agent_specificity"] for item in reviews], SPECIFICITY_RANK
        )
        recommendation = (reviewer["recommendation"] if reviewer else "") or _best(
            [item["push_recommendation"] for item in reviews], RECOMMENDATION_RANK
        )
        reviewer_value = reviewer["research_value"] if reviewer else None
        if reviewer_value in (None, ""):
            research_value = max((_int(item["research_value"]) for item in reviews), default=0)
        else:
            research_value = _int(reviewer_value)
        if specificity != SPECIFICITY or recommendation != RECOMMENDATION:
            continue
        if (research_value or 0) < min_research_value:
            continue

        identifier = str(row["vuln_id"] or "").upper()
        if not IDENTIFIER.fullmatch(identifier):
            continue
        references = tuple(
            sorted({str(item) for item in json.loads(row["references_json"] or "[]") if isinstance(item, str)})
        )
        aliases = {str(item).upper() for item in json.loads(row["aliases_json"] or "[]")}
        # References often name the project's own GHSA even when the row is
        # NVD-sourced; they count for coverage and dedup too.
        for reference in references:
            aliases |= identifiers_in(reference)
        aliases.discard(identifier)
        entry = grouped.get(identifier)
        if entry is None:
            grouped[identifier] = {
                "identifier": identifier,
                "aliases": set(aliases),
                "references": set(references),
                "title": row["title"] or "",
                "advisory_url": row["url"] or row["canonical_url"] or "",
                "summary": "",
                "ecosystem": (reviewer["ecosystem"] if reviewer else "") or "",
                "package": (reviewer["package_name"] if reviewer else "") or "",
                "project": (reviewer["project_name"] if reviewer else "") or "",
                "severity": row["severity"] or "",
                "owasp_agentic_category": (reviewer["owasp_agentic_category"] if reviewer else "") or "",
                "status": (reviewer["status"] if reviewer else "") or "",
                "published_at": row["published_at"] or "",
                "research_value": research_value or 0,
                "specificity_source": "vulnerability_metadata" if reviewer and reviewer["agent_specificity"] else "analysis_results",
                "recommendation_source": "vulnerability_metadata" if reviewer and reviewer["recommendation"] else "analysis_results",
                "raw_item_ids": {raw_item_id},
            }
            continue
        entry["aliases"] |= set(aliases)
        entry["references"] |= set(references)
        entry["raw_item_ids"].add(raw_item_id)
        entry["research_value"] = max(entry["research_value"], research_value or 0)
        if not entry["advisory_url"] and row["url"]:
            entry["advisory_url"] = row["url"]
        if not entry["title"] and row["title"]:
            entry["title"] = row["title"]

    candidates = []
    for entry in grouped.values():
        candidates.append(
            Candidate(
                identifier=entry["identifier"],
                aliases=tuple(sorted(entry["aliases"])),
                title=entry["title"].strip(),
                advisory_url=entry["advisory_url"].strip(),
                summary=entry["summary"].strip(),
                ecosystem=entry["ecosystem"],
                package=entry["package"],
                project=entry["project"],
                severity=entry["severity"],
                owasp_agentic_category=entry["owasp_agentic_category"],
                status=entry["status"],
                published_at=entry["published_at"],
                research_value=entry["research_value"],
                specificity_source=entry["specificity_source"],
                recommendation_source=entry["recommendation_source"],
                raw_item_ids=tuple(sorted(entry["raw_item_ids"])),
                references=tuple(sorted(entry["references"])),
            )
        )
    candidates.sort(key=lambda item: (-item.research_value, item.published_at or "", item.identifier))
    return candidates


def known_products(root: Path) -> dict[str, str]:
    """Map ``github.com`` repository names of registered environments to products."""
    registry = Path(root) / "environments.toml"
    if not registry.is_file():
        return {}
    try:
        entries = tomllib.loads(registry.read_text(encoding="utf-8")).get("environments", [])
    except tomllib.TOMLDecodeError:
        return {}
    products: dict[str, str] = {}
    for entry in entries:
        metadata_path = Path(root) / entry["path"] / "metadata.toml"
        if not metadata_path.is_file():
            continue
        try:
            metadata = tomllib.loads(metadata_path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError:
            continue
        product = entry["id"].split("/")[0]
        for variant in ("vulnerable", "patched"):
            match = REPOSITORY.search(str((metadata.get(variant) or {}).get("source_url", "")))
            if match:
                products.setdefault(match.group(2).lower(), product)
    return products


def covered_identifiers(root: Path) -> set[str]:
    """Identifiers and advisory aliases already published by a registry root."""
    registry = Path(root) / "environments.toml"
    if not registry.is_file():
        return set()
    try:
        entries = tomllib.loads(registry.read_text(encoding="utf-8")).get("environments", [])
    except tomllib.TOMLDecodeError:
        return set()
    found: set[str] = set()
    for entry in entries:
        metadata_path = Path(root) / entry["path"] / "metadata.toml"
        if not metadata_path.is_file():
            continue
        try:
            metadata = tomllib.loads(metadata_path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError:
            continue
        for key in ("cve", "ghsa"):
            if metadata.get(key):
                found.add(str(metadata[key]).upper())
        for advisory in metadata.get("advisories", []) or []:
            found |= identifiers_in(str(advisory))
    return found


def _toml(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml(item) for item in value) + "]"
    raise HarvestError(f"Cannot serialize {type(value).__name__} to TOML")


def candidate_toml(candidate: Candidate, product: str, product_source: str, database: Path,
                   digest: str, size: int, min_research_value: int) -> str:
    lines = [
        "# Generated by `python3 -m runner harvest`. Do not edit by hand.",
        "# Provenance for one AgentSec candidate; not evidence of reproduction.",
        f"schema_version = {SCHEMA}",
        f"identifier = {_toml(candidate.identifier)}",
        f"aliases = {_toml(list(candidate.aliases))}",
        f"environment_id = {_toml(f'{product}/{candidate.identifier}')}",
        f"product = {_toml(product)}",
        f"product_source = {_toml(product_source)}",
        f"title = {_toml(candidate.title)}",
        f"advisory_url = {_toml(candidate.advisory_url)}",
        f"severity = {_toml(normalize_severity(candidate.severity))}",
        f"ecosystem = {_toml(candidate.ecosystem)}",
        f"package = {_toml(candidate.package)}",
        f"project = {_toml(candidate.project)}",
        f"owasp_agentic_category = {_toml(candidate.owasp_agentic_category)}",
        f"status = {_toml(candidate.status)}",
        f"published_at = {_toml(candidate.published_at)}",
        f"research_value = {candidate.research_value}",
        f"specificity = {_toml(SPECIFICITY)}",
        f"specificity_source = {_toml(candidate.specificity_source)}",
        f"recommendation = {_toml(RECOMMENDATION)}",
        f"recommendation_source = {_toml(candidate.recommendation_source)}",
        f"raw_item_ids = {_toml(list(candidate.raw_item_ids))}",
        f"references = {_toml(list(candidate.references))}",
        "",
        "[selection]",
        f"database = {_toml(str(database))}",
        f"database_sha256 = {_toml(digest)}",
        f"database_bytes = {size}",
        f"min_research_value = {min_research_value}",
        f"harvested_at = {_toml(now())}",
        "",
    ]
    return "\n".join(lines)


def file_digest(path: Path) -> str:
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def apply_candidate_metadata(directory: Path, candidate: Candidate) -> None:
    """Fill the scaffolded metadata with facts the database actually knows.

    Only fields with a first-hand source are replaced. Root cause, versions,
    commits, build inputs and verification status stay as TODO/not_run: those
    require reading the advisory and the pinned source, which is the job of the
    later factory stages, not of the harvester.
    """
    path = Path(directory) / "metadata.toml"
    text = path.read_text(encoding="utf-8")
    advisories = [candidate.advisory_url] if candidate.advisory_url else []
    replacements = {
        'title = "TODO: verified vulnerability title"': f"title = {_toml(candidate.title)}",
        'agent_specificity = "unclassified"': f'agent_specificity = {_toml(SPECIFICITY)}',
        'severity = "UNKNOWN"': f"severity = {_toml(normalize_severity(candidate.severity))}",
        "advisories = []": f"advisories = {_toml(advisories)}",
    }
    for old, new in replacements.items():
        if old not in text:
            raise HarvestError(f"metadata.toml template changed; cannot replace {old!r}")
        text = text.replace(old, new, 1)
    path.write_text(text, encoding="utf-8")


def prepare_root(out: Path, checkout: Path) -> None:
    """Create a self-contained registry root that ``AVH_ROOT`` can point at."""
    out = Path(out)
    (out / "environments").mkdir(parents=True, exist_ok=True)
    (out / "candidates").mkdir(parents=True, exist_ok=True)
    (out / "research").mkdir(parents=True, exist_ok=True)
    registry = out / "environments.toml"
    if not registry.is_file():
        registry.write_text("schema_version = 1\nenvironments = []\n", encoding="utf-8")
    templates = out / "templates"
    if not templates.exists():
        # Scaffolding reads root/templates; reuse the checkout's copy so drafts
        # cannot drift from the maintained template.
        templates.symlink_to(checkout / "templates", target_is_directory=True)
    readme = out / "README.md"
    if not readme.is_file():
        readme.write_text(
            "# Staging registry\n\n"
            "Generated by `python3 -m runner harvest`. Every environment here is an\n"
            "unverified `draft`: TODO placeholders are expected and none of it is\n"
            "evidence of reproduction. Review, then copy an environment directory into\n"
            "the checkout and register it in the real `environments.toml`.\n\n"
            "```sh\n"
            f"AVH_ROOT={out} python3 -m runner check\n"
            f"AVH_ROOT={out} python3 -m runner diagram --all --check\n"
            "```\n",
            encoding="utf-8",
        )


def harvest(
    database: Path,
    out: Path,
    *,
    checkout: Path,
    registry_root: Path | None = None,
    min_research_value: int = DEFAULT_MIN_RESEARCH_VALUE,
    limit: int | None = None,
    include_covered: bool = False,
    scaffold: bool = False,
    product: str | None = None,
    identifiers: tuple[str, ...] | None = None,
) -> dict:
    """Select candidates and write provenance records plus optional drafts."""
    database = Path(database).expanduser()
    connection = connect_readonly(database)
    try:
        candidates = query_candidates(connection, min_research_value)
    finally:
        connection.close()
    if identifiers:
        wanted = {value.upper() for value in identifiers}
        candidates = [item for item in candidates if item.identifier in wanted]
        missing = wanted - {item.identifier for item in candidates}
        if missing:
            raise HarvestError(f"Not a qualifying agent_unique candidate: {', '.join(sorted(missing))}")
    if not candidates:
        raise HarvestError("No candidate matched the selection filters")

    coverage_root = Path(registry_root) if registry_root else Path(checkout)
    covered = covered_identifiers(coverage_root) | covered_identifiers(Path(out))
    products = {**known_products(coverage_root), **known_products(Path(out))}

    if product and limit != 1 and not (identifiers and len(identifiers) == 1):
        raise HarvestError("--product requires --limit 1 or a single --identifier")

    selected = []
    for candidate in candidates:
        if not include_covered and (candidate.identifier in covered or set(candidate.aliases) & covered):
            continue
        selected.append(candidate)
    if limit is not None:
        selected = selected[:limit]

    prepare_root(Path(out), Path(checkout))
    digest = file_digest(database)
    size = database.stat().st_size
    records = []
    failures = []
    for candidate in selected:
        if product:
            slug, product_source = slugify(product), "command_line"
        else:
            slug, product_source = candidate.resolve_product(products)
        if not SLUG.fullmatch(slug):
            raise HarvestError(f"Invalid product slug for {candidate.identifier}: {slug!r}")
        record = Path(out) / "candidates" / f"{candidate.identifier}.toml"
        record.write_text(
            candidate_toml(candidate, slug, product_source, database.resolve(), digest, size, min_research_value),
            encoding="utf-8",
        )
        entry = {
            "identifier": candidate.identifier,
            "environment_id": f"{slug}/{candidate.identifier}",
            "product": slug,
            "product_source": product_source,
            "title": candidate.title,
            "advisory_url": candidate.advisory_url,
            "research_value": candidate.research_value,
            "aliases": list(candidate.aliases),
            "candidate": str(record.relative_to(out)),
            "scaffolded": False,
        }
        if scaffold:
            from .cli import RegistryError, scaffold as scaffold_environment
            try:
                # verify=False: a staging root is unverified by design, so one broken
                # sibling draft must not stop the rest of the batch from scaffolding.
                directory = scaffold_environment(Path(out), slug, candidate.identifier, verify=False)
                apply_candidate_metadata(directory, candidate)
                entry["scaffolded"] = True
                entry["environment_path"] = str(directory.relative_to(out))
            except (RegistryError, HarvestError) as error:
                entry["error"] = str(error)
                failures.append(f"{candidate.identifier}: {error}")
        records.append(entry)

    index = {
        "schema_version": SCHEMA,
        "harvested_at": now(),
        "database": str(database.resolve()),
        "database_sha256": digest,
        "database_bytes": size,
        "filters": {
            "specificity": SPECIFICITY,
            "recommendation": RECOMMENDATION,
            "min_research_value": min_research_value,
            "include_covered": include_covered,
        },
        "totals": {
            "qualifying": len(candidates),
            "covered": sum(
                1 for item in candidates
                if item.identifier in covered or set(item.aliases) & covered
            ),
            "selected": len(selected),
        },
        "candidates": records,
    }
    (Path(out) / "candidates" / "index.json").write_text(
        json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    index["failures"] = failures
    return index
