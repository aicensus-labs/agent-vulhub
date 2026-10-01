"""Harvest tests use a synthetic AgentSec database; they never touch the network."""

from pathlib import Path
import sqlite3
import tempfile
import unittest

from runner.cli import ROOT, check, read_toml
from runner.harvest import (
    Candidate,
    HarvestError,
    connect_readonly,
    covered_identifiers,
    harvest,
    identifiers_in,
    normalize_severity,
    query_candidates,
    slugify,
    title_product,
)

METADATA_COLUMNS = (
    "raw_item_id", "agent_specificity", "research_value", "recommendation", "status",
    "ecosystem", "package_name", "project_name", "owasp_agentic_category",
)
ANALYSIS_COLUMNS = ("raw_item_id", "agent_specificity", "research_value", "push_recommendation")
VULN_COLUMNS = ("raw_item_id", "vuln_id", "aliases_json", "references_json", "severity", "published_at")
RAW_COLUMNS = ("id", "title", "url", "canonical_url", "content")


def _insert(connection, table, columns, values):
    placeholders = ", ".join("?" for _ in columns)
    connection.execute(f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})", values)


def build_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.execute(f"CREATE TABLE vulnerability_metadata ({', '.join(c + ' TEXT' for c in METADATA_COLUMNS)})")
    connection.execute(f"CREATE TABLE analysis_results ({', '.join(c + ' TEXT' for c in ANALYSIS_COLUMNS)})")
    connection.execute(f"CREATE TABLE vuln_items ({', '.join(c + ' TEXT' for c in VULN_COLUMNS)})")
    connection.execute(f"CREATE TABLE raw_items ({', '.join(c + ' TEXT' for c in RAW_COLUMNS)})")

    # Qualifying: reviewer metadata marks it agent_unique + push with value 5.
    _insert(connection, "vulnerability_metadata", METADATA_COLUMNS,
            ("raw-1", "agent_unique", "5", "push", "published", "npm", "@acme/mcp-demo", "acme", ""))
    _insert(connection, "analysis_results", ANALYSIS_COLUMNS, ("raw-1", "agent_unique", "5", "push"))
    _insert(connection, "vuln_items", VULN_COLUMNS,
            ("raw-1", "CVE-2099-00001", "[]",
             '["https://github.com/acme/mcp-demo/security/advisories/GHSA-aaaa-bbbb-cccc"]', "HIGH",
             "2099-01-02T00:00:00Z"))
    _insert(connection, "raw_items", RAW_COLUMNS,
            ("raw-1", "Acme MCP Demo is a tool. Prior to 1.2.3 it escapes its sandbox.", "https://nvd.nist.gov/x",
             "https://nvd.nist.gov/x", ""))

    # Same advisory from a second raw item: must deduplicate and union the alias.
    _insert(connection, "vulnerability_metadata", METADATA_COLUMNS,
            ("raw-2", "agent_unique", "4", "push", "published", "npm", "@acme/mcp-demo", "acme", ""))
    _insert(connection, "analysis_results", ANALYSIS_COLUMNS, ("raw-2", "agent_unique", "4", "push"))
    _insert(connection, "vuln_items", VULN_COLUMNS,
            ("raw-2", "CVE-2099-00001", '["GHSA-aaaa-bbbb-cccc"]', "[]", "HIGH", "2099-01-01T00:00:00Z"))
    _insert(connection, "raw_items", RAW_COLUMNS,
            ("raw-2", "Acme MCP Demo sandbox escape", "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
             "", ""))

    # Excluded: reviewer metadata says agent_related.
    _insert(connection, "vulnerability_metadata", METADATA_COLUMNS,
            ("raw-3", "agent_related", "5", "push", "published", "", "", "", ""))
    _insert(connection, "analysis_results", ANALYSIS_COLUMNS, ("raw-3", "agent_unique", "5", "push"))
    _insert(connection, "vuln_items", VULN_COLUMNS, ("raw-3", "CVE-2099-00003", "[]", "[]", "LOW", ""))
    _insert(connection, "raw_items", RAW_COLUMNS, ("raw-3", "Excluded by reviewer metadata", "https://x", "", ""))

    # Excluded: below the research-value floor.
    _insert(connection, "vulnerability_metadata", METADATA_COLUMNS,
            ("raw-4", "agent_unique", "2", "push", "published", "", "", "", ""))
    _insert(connection, "analysis_results", ANALYSIS_COLUMNS, ("raw-4", "agent_unique", "2", "push"))
    _insert(connection, "vuln_items", VULN_COLUMNS, ("raw-4", "CVE-2099-00004", "[]", "[]", "LOW", ""))
    _insert(connection, "raw_items", RAW_COLUMNS, ("raw-4", "Too low value", "https://x", "", ""))

    # Included via the analysis fallback when reviewer metadata is silent.
    _insert(connection, "vulnerability_metadata", METADATA_COLUMNS,
            ("raw-5", "", "", "", "published", "pip", "agentlib", "agentlib", ""))
    _insert(connection, "analysis_results", ANALYSIS_COLUMNS, ("raw-5", "agent_unique", "4", "push"))
    _insert(connection, "vuln_items", VULN_COLUMNS,
            ("raw-5", "GHSA-dddd-eeee-ffff", "[]",
             '["https://github.com/agentlib/agentlib/security/advisories/GHSA-dddd-eeee-ffff"]', "MEDIUM", ""))
    _insert(connection, "raw_items", RAW_COLUMNS, ("raw-5", "Agentlib bypass", "https://github.com/advisories/GHSA-dddd-eeee-ffff", "", ""))

    # Excluded: not a real CVE/GHSA identifier.
    _insert(connection, "vulnerability_metadata", METADATA_COLUMNS,
            ("raw-6", "agent_unique", "5", "push", "published", "", "", "", ""))
    _insert(connection, "analysis_results", ANALYSIS_COLUMNS, ("raw-6", "agent_unique", "5", "push"))
    _insert(connection, "vuln_items", VULN_COLUMNS, ("raw-6", "NOT-AN-ID", "[]", "[]", "", ""))
    _insert(connection, "raw_items", RAW_COLUMNS, ("raw-6", "Not an advisory", "https://x", "", ""))
    connection.commit()
    connection.close()


class HarvestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / "agentsec.sqlite3"
        build_database(self.database)
        self.staging = self.root / "staging"

    def test_readonly_connection_rejects_missing_database(self):
        with self.assertRaises(HarvestError):
            connect_readonly(self.root / "absent.sqlite3")

    def test_query_selects_agent_unique_push_and_deduplicates(self):
        connection = connect_readonly(self.database)
        self.addCleanup(connection.close)
        candidates = query_candidates(connection, 4)
        self.assertEqual([candidate.identifier for candidate in candidates],
                         ["CVE-2099-00001", "GHSA-DDDD-EEEE-FFFF"])
        first = candidates[0]
        self.assertEqual(first.aliases, ("GHSA-AAAA-BBBB-CCCC",))
        self.assertEqual(len(first.raw_item_ids), 2)
        self.assertEqual(first.research_value, 5)
        self.assertEqual(first.recommendation_source, "vulnerability_metadata")
        self.assertIn("github.com/acme/mcp-demo/security/advisories", " ".join(first.references))

    def test_product_prefers_known_environment_then_repository(self):
        candidate = Candidate(
            identifier="CVE-2099-00001", aliases=(), title="Acme MCP Demo is a tool.",
            advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2099-00001", summary="", ecosystem="",
            package="", project="", severity="", owasp_agentic_category="", status="", published_at="",
            research_value=5, specificity_source="", recommendation_source="",
            references=("https://github.com/acme/mcp-demo/security/advisories/GHSA-aaaa-bbbb-cccc",),
        )
        self.assertEqual(candidate.resolve_product({}), ("mcp-demo", "advisory_reference"))
        self.assertEqual(candidate.resolve_product({"mcp-demo": "acme-mcp"}),
                         ("acme-mcp", "known_environment"))

    def test_title_and_slug_helpers(self):
        self.assertEqual(title_product("CVE-2099-00001: Roo Code is an agent."), "roo-code")
        self.assertEqual(title_product("The MCP inspector is a tool."), "mcp-inspector")
        self.assertEqual(title_product("n8n: Allowed HTTP Request Domains bypass"), "n8n")
        self.assertEqual(slugify("@Scope/Pkg Name!"), "scope-pkg-name")
        self.assertEqual(identifiers_in("see https://x/GHSA-aaaa-bbbb-cccc and CVE-2099-00001"),
                         {"GHSA-AAAA-BBBB-CCCC", "CVE-2099-00001"})

    def test_covered_identifiers_reads_registry_and_advisories(self):
        environment = self.root / "environments" / "demo" / "GHSA-AAAA-BBBB-CCCC"
        environment.mkdir(parents=True)
        (environment / "metadata.toml").write_text(
            'schema_version = 1\nid = "demo/GHSA-AAAA-BBBB-CCCC"\n'
            'ghsa = "GHSA-AAAA-BBBB-CCCC"\ncve = "CVE-2099-00001"\n'
            'advisories = ["https://github.com/advisories/GHSA-aaaa-bbbb-cccc"]\n',
            encoding="utf-8")
        (self.root / "environments.toml").write_text(
            'schema_version = 1\n[[environments]]\nid = "demo/GHSA-AAAA-BBBB-CCCC"\n'
            'path = "environments/demo/GHSA-AAAA-BBBB-CCCC"\n', encoding="utf-8")
        self.assertEqual(covered_identifiers(self.root), {"GHSA-AAAA-BBBB-CCCC", "CVE-2099-00001"})

    def test_harvest_writes_candidates_and_scaffolds_checkable_drafts(self):
        index = harvest(self.database, self.staging, checkout=ROOT, registry_root=self.root, scaffold=True)
        self.assertEqual(index["totals"]["qualifying"], 2)
        self.assertEqual(index["totals"]["selected"], 2)
        self.assertTrue(all(entry["scaffolded"] for entry in index["candidates"]))
        self.assertEqual(index["failures"], [])
        # The staging root is a valid registry: existing static checks apply.
        entries = check(self.staging)
        self.assertEqual(len(entries), 2)
        draft = self.staging / "environments" / "mcp-demo" / "CVE-2099-00001"
        metadata = read_toml(draft / "metadata.toml")
        self.assertEqual(metadata["lifecycle"], "draft")
        self.assertEqual(metadata["agent_specificity"], "agent_unique")
        self.assertEqual(metadata["verification"]["mechanism"]["status"], "not_run")
        self.assertNotIn("TODO: verified vulnerability title", (draft / "metadata.toml").read_text())
        self.assertTrue((draft / "diagram" / "mechanism.mmd").is_file())
        self.assertTrue((draft / "diagram.toml").is_file())

    def test_normalize_severity_maps_onto_the_declared_vocabulary(self):
        """The database mixes cases and stores the KEV flag beside the rating."""
        self.assertEqual(normalize_severity("HIGH"), "HIGH")
        self.assertEqual(normalize_severity("high"), "HIGH")
        self.assertEqual(normalize_severity(" critical "), "CRITICAL")
        self.assertEqual(normalize_severity("moderate"), "MEDIUM")
        self.assertEqual(normalize_severity("known_exploited"), "HIGH")
        self.assertEqual(normalize_severity("NONE"), "NONE")
        for empty in ("", "   ", "unknown", "weird", None):
            self.assertEqual(normalize_severity(empty), "UNKNOWN")

    def test_scaffolded_draft_records_the_candidate_severity(self):
        """A harvested draft must not lose the rating the database already knew."""
        harvest(self.database, self.staging, checkout=ROOT, registry_root=self.root, scaffold=True)
        draft = self.staging / "environments" / "mcp-demo" / "CVE-2099-00001"
        self.assertEqual(read_toml(draft / "metadata.toml")["severity"], "HIGH")

    def test_harvest_skips_covered_and_is_idempotent(self):
        index = harvest(self.database, self.staging, checkout=ROOT, registry_root=self.root, limit=1)
        self.assertEqual(index["totals"]["selected"], 1)
        self.assertFalse(index["candidates"][0]["scaffolded"])
        self.assertTrue((self.staging / "candidates" / "index.json").is_file())
        # Re-running without --scaffold re-emits the same records; it does not
        # treat its own candidate files as coverage.
        again = harvest(self.database, self.staging, checkout=ROOT, registry_root=self.root, limit=1)
        self.assertEqual(again["totals"]["selected"], 1)
        self.assertEqual(again["candidates"][0]["identifier"], index["candidates"][0]["identifier"])

    def test_harvest_marks_alias_matches_as_covered(self):
        environment = self.root / "environments" / "demo" / "GHSA-AAAA-BBBB-CCCC"
        environment.mkdir(parents=True)
        (environment / "metadata.toml").write_text(
            'schema_version = 1\nid = "demo/GHSA-AAAA-BBBB-CCCC"\n'
            'ghsa = "GHSA-AAAA-BBBB-CCCC"\n', encoding="utf-8")
        (self.root / "environments.toml").write_text(
            'schema_version = 1\n[[environments]]\nid = "demo/GHSA-AAAA-BBBB-CCCC"\n'
            'path = "environments/demo/GHSA-AAAA-BBBB-CCCC"\n', encoding="utf-8")
        index = harvest(self.database, self.staging, checkout=ROOT, registry_root=self.root)
        self.assertEqual([entry["identifier"] for entry in index["candidates"]],
                         ["GHSA-DDDD-EEEE-FFFF"])

    def test_product_override_requires_a_single_candidate(self):
        with self.assertRaises(HarvestError):
            harvest(self.database, self.staging, checkout=ROOT, registry_root=self.root, product="forced")

    def test_identifier_filter_selects_one_candidate(self):
        index = harvest(self.database, self.staging, checkout=ROOT, registry_root=self.root,
                        identifiers=("ghsa-dddd-eeee-ffff",), product="agentlib", scaffold=True)
        self.assertEqual([entry["environment_id"] for entry in index["candidates"]],
                         ["agentlib/GHSA-DDDD-EEEE-FFFF"])
        with self.assertRaises(HarvestError):
            harvest(self.database, self.staging, checkout=ROOT, registry_root=self.root,
                    identifiers=("CVE-2099-00003",))


if __name__ == "__main__":
    unittest.main()
