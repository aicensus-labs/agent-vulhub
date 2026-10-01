"""Factory stage briefs and static gates; no network and no vulnerable service."""

from pathlib import Path
import shutil
import tempfile
import unittest

from runner import factory
from runner.cli import ROOT, scaffold

VALID_DIAGRAM = """\
schema_version = 1
title = "Synthetic mechanism"
summary = "攻击者可控输入进入组件后绕过了边界检查，组件于是执行了本不该执行的动作。"

[[entities]]
id = "attacker"
label = "攻击者 / 攻击输入"
kind = "actor"
trust = "attacker_controlled"
role = "构造触发输入。"

[[entities]]
id = "target"
label = "受影响组件"
kind = "service"
trust = "trusted"
role = "执行有缺陷的检查。"

[[entities]]
id = "sink"
label = "受控效果落点"
kind = "sink"
trust = "trusted"
synthetic = true
role = "接收漏洞产生的效果。"

[[boundaries]]
id = "product"
label = "受影响组件与它信任的数据"
members = ["target", "sink"]
note = "边界本来挡住越界访问，漏洞让它失效。"

[[steps]]
n = 1
phase = "setup"
from = "attacker"
to = "target"
action = "攻击者提供触发输入。"
variant = "both"

[[steps]]
n = 2
phase = "trigger"
from = "target"
to = "target"
action = "漏洞版跳过边界检查。"
variant = "vulnerable_only"
diverges = true

[[steps]]
n = 3
phase = "trigger"
from = "target"
to = "target"
action = "修复版拒绝同一输入。"
variant = "patched_only"
diverges = true

[[steps]]
n = 4
phase = "effect"
from = "target"
to = "sink"
action = "漏洞版产生受控效果。"
variant = "vulnerable_only"
"""

PUBLIC = """\
# Synthetic advisory

## 身份
CVE-2099-99999 / GHSA-aaaa-bbbb-cccc

## 上游项目
https://github.com/acme/mcp-demo at commit 0000000000000000000000000000000000000000

## 漏洞机制
攻击者可控参数进入未校验的路径。

## 修复对照
修复提交改为拒绝越界输入。

## 复现可行性
纯 Python 逻辑，可离线复现。

## 参考
https://github.com/acme/mcp-demo/security/advisories/GHSA-aaaa-bbbb-cccc
"""


class FactoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "environments").mkdir()
        (self.root / "environments.toml").write_text("schema_version = 1\nenvironments = []\n")
        shutil.copytree(ROOT / "templates", self.root / "templates")
        self.directory = scaffold(self.root, "demo", "CVE-2099-99999")
        self.environment = "demo/CVE-2099-99999"
        self.research = self.root / "research" / "demo" / "CVE-2099-99999"

    def write(self, relative: str, text: str) -> Path:
        path = self.root / "environments" / "demo" / "CVE-2099-99999" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def write_research(self, name: str, status: str = "continue") -> None:
        self.research.mkdir(parents=True, exist_ok=True)
        (self.research / name).write_text(
            f'status = "{status}"\nstage = "x"\nenvironment_id = "{self.environment}"\n'
            'reason = "synthetic"\nevidence = []\n', encoding="utf-8")

    def pass_stages(self, *stage_ids: str) -> None:
        """Mark earlier stages passed so a later gate is allowed to run."""
        state = factory.read_state(self.root, self.environment)
        for stage_id in stage_ids:
            state["stages"][stage_id] = "passed"
        factory.write_state(self.root, self.environment, state)

    def test_brief_names_stage_and_blind_files(self):
        text = factory.brief(self.root, self.environment, "build")
        self.assertIn("Stage `build`", text)
        self.assertIn("盲建", text)
        self.assertIn("reproduce.py", text)
        self.assertIn("verify.py", text)

    def test_brief_rejects_unknown_stage_and_environment(self):
        with self.assertRaises(factory.FactoryError):
            factory.brief(self.root, self.environment, "deploy")
        with self.assertRaises(factory.FactoryError):
            factory.brief(self.root, "demo/CVE-2000-00000", "analyze")

    def test_analyze_gate_requires_sections_and_continue(self):
        self.assertFalse(factory.gate(self.root, self.environment, "analyze")["passed"])
        (self.research).mkdir(parents=True, exist_ok=True)
        (self.research / "public.md").write_text("# incomplete\n", encoding="utf-8")
        self.write_research("analyze-res.toml")
        result = factory.gate(self.root, self.environment, "analyze")
        self.assertFalse(result["passed"])
        self.assertTrue(any("## 身份" in problem for problem in result["problems"]))
        (self.research / "public.md").write_text(PUBLIC, encoding="utf-8")
        self.assertTrue(factory.gate(self.root, self.environment, "analyze")["passed"])

    def test_generate_gate_rejects_todo_and_stub(self):
        self.pass_stages("analyze")
        self.assertFalse(factory.gate(self.root, self.environment, "generate")["passed"])
        self.write("diagram.toml", VALID_DIAGRAM)
        self.write_research("generate-res.toml")
        # The gate also checks rendered output, so an unrendered edit is drift.
        from runner import diagram
        diagram.write_all(self.directory, diagram.load(self.directory))
        result = factory.gate(self.root, self.environment, "generate")
        self.assertFalse(result["passed"])
        self.assertTrue(any("reproduce.py" in problem for problem in result["problems"]))
        self.write("reproduce.py", "print('real reproduction')\n")
        result = factory.gate(self.root, self.environment, "generate")
        self.assertTrue(result["passed"], result["problems"])

    def test_check_gate_runs_static_commands(self):
        self.pass_stages("analyze", "generate", "build", "validate", "solve")
        result = factory.gate(self.root, self.environment, "check", execute=True)
        self.assertTrue(result["passed"], result["problems"])
        self.assertEqual([run["returncode"] for run in result["runs"]], [0, 0])

    def test_docker_gate_is_explicit(self):
        self.pass_stages("analyze", "generate", "build")
        result = factory.gate(self.root, self.environment, "validate")
        self.assertFalse(result["passed"])
        self.assertIn("--execute", " ".join(result["problems"]))

    def test_gate_refuses_to_run_before_earlier_stages_pass(self):
        """A later gate on an unfinished environment would be meaningless."""
        with self.assertRaisesRegex(factory.FactoryError, "requires 'analyze' to pass first"):
            factory.gate(self.root, self.environment, "check", execute=True)
        with self.assertRaisesRegex(factory.FactoryError, "requires 'analyze' to pass first"):
            factory.gate(self.root, self.environment, "validate", execute=True)

    def test_validate_stage_owns_the_first_verifier(self):
        """Regression: `validate` could never pass.

        `runner reproduce` unconditionally execs /lab/verify.py, and produces a
        `not_run` failure when it is missing or still the scaffold stub. But
        `verify.py` used to be declared solve-only output, which made the gate
        unsatisfiable for every environment: validate could not pass until solve
        had run, and solve is gated behind validate.
        """
        validate = next(stage for stage in factory.STAGES if stage.id == "validate")
        self.assertIn("verify.py", validate.outputs)
        self.assertIn("fixtures/", validate.reads)
        # solve still owns hardening it, so both stages declare the artifact.
        solve = next(stage for stage in factory.STAGES if stage.id == "solve")
        self.assertIn("verify.py", solve.outputs)

    def test_validate_brief_demands_the_first_verifier(self):
        text = factory.brief(self.root, self.environment, "validate")
        self.assertIn("你必须写出首版 `verify.py`", text)
        self.assertIn("/lab/verify.py", text)

    def test_check_gate_cannot_pass_on_an_empty_scaffold(self):
        """Regression: `check` passed on a draft that was never generated or built."""
        with self.assertRaises(factory.FactoryError):
            factory.gate(self.root, self.environment, "check", execute=True)
        state = factory.read_state(self.root, self.environment)
        self.assertEqual(state["stages"]["check"], "not_run")

    def test_reproduce_gate_honours_declared_exceptions(self):
        command = factory.reproduce_command(self.root, self.environment, "validate")
        self.assertNotIn("--allow-exceptions", command)
        self.assertIn("--scenario", command)
        path = self.root / "environments" / "demo" / "CVE-2099-99999" / "metadata.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "exceptions = []",
                'exceptions = [{ rule = "network.lab.subnet", reason = "synthetic" }]'),
            encoding="utf-8")
        command = factory.reproduce_command(self.root, self.environment, "solve")
        self.assertIn("--allow-exceptions", command)
        self.assertNotIn("--scenario", command)
        self.assertIn("--rounds", command)

    def test_state_round_trip(self):
        factory.gate(self.root, self.environment, "analyze")
        state = factory.read_state(self.root, self.environment)
        self.assertEqual(state["stages"]["analyze"], "failed")
        self.assertEqual(state["stages"]["build"], "not_run")
        self.assertTrue(factory.state_path(self.root, self.environment).is_file())


if __name__ == "__main__":
    unittest.main()
