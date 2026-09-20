"""Diagram contract tests use synthetic environments in temporary directories only."""

from pathlib import Path
import re
import shutil
import tempfile
import unittest

from runner import diagram
from runner.cli import ROOT, RegistryError, check, scaffold


def base():
    return {
        "schema_version": 1,
        "title": "sample diagram",
        "summary": "sample summary",
        "entities": [
            {"id": "attacker", "label": "attacker", "kind": "actor",
             "trust": "attacker_controlled", "role": "sends the attack input"},
            {"id": "target", "label": "target", "kind": "service",
             "trust": "trusted", "role": "checks the input"},
            {"id": "effect", "label": "effect", "kind": "sink", "trust": "trusted",
             "role": "receives the controlled effect", "synthetic": True},
        ],
        "boundaries": [
            {"id": "attacker_side", "label": "attacker side", "members": ["attacker"], "note": "outside"},
            {"id": "product", "label": "product", "members": ["target", "effect"], "note": "isolated"},
        ],
        "steps": [
            {"n": 1, "phase": "setup", "from": "attacker", "to": "target",
             "action": "send input", "variant": "both"},
            {"n": 2, "phase": "trigger", "from": "target", "to": "target",
             "action": "escape the boundary", "variant": "vulnerable_only", "diverges": True},
            {"n": 3, "phase": "effect", "from": "target", "to": "effect",
             "action": "produce the controlled effect", "variant": "vulnerable_only"},
        ],
    }


class DiagramTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "environments").mkdir()
        (self.root / "environments.toml").write_text("schema_version = 1\nenvironments = []\n")
        shutil.copytree(ROOT / "templates", self.root / "templates")

    def reject(self, data, pattern):
        with self.assertRaisesRegex(ValueError, pattern):
            diagram.validate(self.root, data)

    def test_shipped_template_is_valid_and_renders(self):
        template = ROOT / "templates" / "environment"
        data = diagram.load(template)
        diagram.validate(template, data)
        artifacts = diagram.render(data)
        self.assertEqual(sorted(artifacts), ["diagram/entities.mmd", "diagram/mechanism.mmd"])
        self.assertIn("sequenceDiagram", artifacts["diagram/mechanism.mmd"])
        self.assertIn("flowchart LR", artifacts["diagram/entities.mmd"])

    def test_scaffold_renders_and_check_accepts(self):
        target = scaffold(self.root, "synthetic-agent", "CVE-2099-99999")
        self.assertTrue((target / "diagram/mechanism.mmd").is_file())
        self.assertTrue((target / "diagram/entities.mmd").is_file())
        self.assertIn(diagram.BEGIN, (target / "README.zh-cn.md").read_text())
        self.assertEqual(diagram.drift(target, diagram.load(target)), [])
        self.assertEqual(len(check(self.root)), 1)

    def test_rendering_is_idempotent(self):
        target = scaffold(self.root, "synthetic-agent", "CVE-2099-99999")
        data = diagram.load(target)
        self.assertEqual(diagram.write_all(target, data), [])
        self.assertEqual(diagram.embed((target / "README.zh-cn.md").read_text(), diagram.readme_block(data)),
                         (target / "README.zh-cn.md").read_text())

    def test_stale_diagram_is_rejected_by_check(self):
        target = scaffold(self.root, "synthetic-agent", "CVE-2099-99999")
        source = target / "diagram.toml"
        source.write_text(re.sub(r"^summary = .*$", 'summary = "edited without re-rendering"',
                                 source.read_text(encoding="utf-8"), count=1, flags=re.MULTILINE),
                          encoding="utf-8")
        with self.assertRaisesRegex(RegistryError, "out of date"):
            check(self.root)

    def test_unknown_entity_in_step_is_rejected(self):
        data = base()
        data["steps"][0]["to"] = "missing"
        self.reject(data, "unknown entity")

    def test_duplicate_entity_is_rejected(self):
        data = base()
        data["entities"].append(dict(data["entities"][0]))
        self.reject(data, "duplicate entity")

    def test_step_numbering_must_be_contiguous(self):
        data = base()
        data["steps"][1]["n"] = 4
        self.reject(data, "numbered 1..N")

    def test_missing_role_is_rejected(self):
        data = base()
        del data["entities"][0]["role"]
        self.reject(data, "role must be a non-empty string")

    def test_invalid_kind_and_trust_are_rejected(self):
        for field in ("kind", "trust"):
            data = base()
            data["entities"][0][field] = "nonsense"
            self.reject(data, f"{field} must be one of")

    def test_a_diverging_step_is_required(self):
        data = base()
        for step in data["steps"]:
            step.pop("diverges", None)
        self.reject(data, "diverges = true")

    def test_diverging_step_cannot_apply_to_both_variants(self):
        data = base()
        data["steps"][1]["variant"] = "both"
        self.reject(data, "not vulnerable_only or patched_only")

    def test_orphan_entity_is_rejected_unless_static(self):
        data = base()
        data["entities"].append({"id": "orphan", "label": "orphan", "kind": "store",
                                 "trust": "trusted", "role": "unused"})
        self.reject(data, "appears in no step")
        data["entities"][-1]["static"] = True
        diagram.validate(self.root, data)

    def test_boundary_members_must_exist_and_be_unique(self):
        data = base()
        data["boundaries"][0]["members"] = ["attacker", "missing"]
        self.reject(data, "unknown entity")
        data = base()
        data["boundaries"].append({"id": "second", "label": "second", "members": ["attacker"], "note": "again"})
        self.reject(data, "at most one boundary")

    def test_boundary_id_cannot_shadow_an_entity(self):
        data = base()
        data["boundaries"][0]["id"] = "attacker"
        self.reject(data, "collides with entity id")

    def test_fixture_references_must_exist_and_be_manifested(self):
        (self.root / "fixtures").mkdir()
        (self.root / "fixtures/attack.json").write_text("{}\n")
        (self.root / "fixtures/manifest.toml").write_text("schema_version = 1\n[files]\n")
        data = base()
        data["steps"][0]["evidence"] = "fixtures/attack.json"
        self.reject(data, "absent from fixtures/manifest.toml")
        (self.root / "fixtures/manifest.toml").write_text(
            'schema_version = 1\n[files]\n"attack.json" = "%s"\n' % ("0" * 64))
        diagram.validate(self.root, data)
        data["steps"][0]["evidence"] = "fixtures/missing.json"
        self.reject(data, "missing fixture")

    def test_mermaid_escaping_neutralises_syntax_characters(self):
        data = base()
        data["entities"][0]["label"] = 'bad "label" | with ; chars # and <b>tags</b>'
        flowchart = diagram.render(data)["diagram/entities.mmd"]
        node = next(line for line in flowchart.splitlines() if line.strip().startswith("attacker["))
        self.assertNotIn('"label"', node)
        self.assertNotIn(";", node)
        self.assertNotIn("#", node)
        self.assertNotIn("<b>", node)

    def test_reproduction_harness_is_not_expressible(self):
        for kind in ("verifier", "runtime"):
            data = base()
            data["entities"][0]["kind"] = kind
            self.reject(data, "kind must be one of")
        data = base()
        data["steps"][0]["phase"] = "verify"
        self.reject(data, "phase must be one of")

    def test_apparatus_vocabulary_is_rejected_from_diagram_text(self):
        # Diagram-visible text explains the vulnerability itself, so the words
        # that belong to this repository's reproduction apparatus must not reach
        # a node label, an arrow message, a subgraph title or the summary.
        for word in ("本仓库", "本实验", "本环境", "fixture", "synthetic", "替身", "本地假"):
            for field in ("entity label", "step action", "summary", "boundary label"):
                data = base()
                if field == "entity label":
                    data["entities"][0]["label"] = f"{word} attacker"
                elif field == "step action":
                    data["steps"][0]["action"] = f"send input ({word})"
                elif field == "summary":
                    data["summary"] = f"{word} summary"
                else:
                    data["boundaries"][0]["label"] = f"{word} side"
                with self.subTest(word=word, field=field):
                    self.reject(data, "reproduction apparatus")

    def test_prose_and_provenance_may_name_the_apparatus(self):
        # role, detail and note are rendered outside the diagram, and source and
        # evidence are provenance columns, so they may describe the reproduction.
        data = base()
        data["entities"][0]["role"] = "提交 fixtures/attack.json 里的固定输入"
        data["boundaries"][0]["note"] = "本实验用替身代替真实目标"
        data["steps"][0]["detail"] = "本环境不连接真实渠道"
        diagram.validate(self.root, data)

    def test_mermaid_keyword_ids_are_rejected(self):
        data = base()
        data["entities"][0]["id"] = "end"
        data["boundaries"][0]["members"][0] = "end"
        data["steps"][0]["from"] = "end"
        self.reject(data, "Mermaid keyword")

    def test_multi_class_nodes_use_separate_class_statements(self):
        flowchart = diagram.render(base())["diagram/entities.mmd"]
        statements = [line.split() for line in flowchart.splitlines() if line.strip().startswith("class ")]
        for parts in statements:
            self.assertEqual(len(parts), 3, f"invalid class statement: {parts}")
        assigned = {tuple(parts[1:]) for parts in statements}
        self.assertIn(("effect", "sink"), assigned)
        self.assertIn(("effect", "synthetic"), assigned)

    def test_boxes_are_rendered_without_fill(self):
        flowchart = diagram.render(base())["diagram/entities.mmd"]
        for line in flowchart.splitlines():
            stripped = line.strip()
            # Any fill that is declared at all must be transparent; the synthetic
            # class only adds a dashed border and inherits the kind's fill.
            if stripped.startswith("classDef ") and "fill:" in stripped:
                self.assertIn("fill:transparent", stripped)
            if stripped.startswith("style "):
                self.assertIn("fill:transparent", stripped)
        self.assertEqual(sum(line.strip().startswith("style ") for line in flowchart.splitlines()), 2)

    def test_flowchart_edges_carry_only_step_numbers(self):
        data = base()
        data["steps"][0]["action"] = "a very long action that would collide on an edge"
        flowchart = diagram.render(data)["diagram/entities.mmd"]
        edges = [line for line in flowchart.splitlines() if re.search(r'\|"\d+"\|', line)]
        self.assertEqual(len(edges), 3)
        for line, number in zip(edges, ("1", "2", "3")):
            self.assertEqual(line.split('|"', 1)[1].split('"|', 1)[0], number, line)
            self.assertNotIn("very long action", line)

    def test_patched_edge_is_green_even_when_it_diverges(self):
        data = base()
        data["steps"][2]["variant"] = "patched_only"
        data["steps"][2]["diverges"] = True
        flowchart = diagram.render(data)["diagram/entities.mmd"]
        styles = [line for line in flowchart.splitlines() if line.strip().startswith("linkStyle")]
        self.assertEqual(styles, ["  linkStyle 1 stroke:#c0392b,stroke-width:2px",
                                  "  linkStyle 2 stroke:#2e7d32,stroke-width:2px"])

    def test_embed_replaces_the_marked_block_in_place(self):
        target = scaffold(self.root, "synthetic-agent", "CVE-2099-99999")
        readme = target / "README.zh-cn.md"
        text = readme.read_text(encoding="utf-8")
        moved = text.replace(diagram.END, diagram.END + "\n\n## 运行\n")
        self.assertNotIn("## 运行", text)
        self.assertEqual(moved.count(diagram.BEGIN), 1)
        self.assertEqual(diagram.embed(moved, diagram.readme_block(diagram.load(target))).count(diagram.BEGIN), 1)


if __name__ == "__main__":
    unittest.main()
