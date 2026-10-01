"""Orchestrate the six-stage reproduction factory for a staged draft.

The design follows CVE-Factory (https://github.com/livecvebench/CVE-Factory):
split the overwhelming "reproduce this CVE" task into isolated generation
stages, then re-couple them through progressively stricter objective gates
instead of an agent's self-assessment. Adapted to this repository's contract:

===========  ==================  ==========================================
stage        CVE-Factory         agent-vulhub artifacts and gate
===========  ==================  ==========================================
analyze      Analyzer            ``research/<env>/public.md`` from the
                                 advisory, fix commit and upstream source
generate     Generator           ``diagram.toml`` + ``reproduce.py`` +
                                 fixtures (logical, no Docker)
build        Builder             ``Dockerfile`` + pinned ``build.inputs``;
                                 blind to reproduce/verify
validate     Validator           vulnerable attack passes, benign passes
solve        Solver              ``verify.py``; patched attack blocked,
                                 three rounds
check        Checker             ``runner check`` + diagram/QA sweep
===========  ==================  ==========================================

This module never decides that a vulnerability was reproduced: it runs the
repository's own objective commands and records their exit status. A stage that
has not run stays ``not_run``.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

from . import diagram

SCHEMA = 1
# Commands run from the checkout that owns the `runner` package; AVH_ROOT then
# points them at the staging registry being worked on.
CHECKOUT = Path(__file__).resolve().parents[1]
ANALYSIS_SECTIONS = (
    "## 身份",
    "## 上游项目",
    "## 漏洞机制",
    "## 修复对照",
    "## 复现可行性",
    "## 参考",
)
STATUSES = ("not_run", "continue", "error", "pause")


class FactoryError(ValueError):
    """The requested stage, environment or gate is not available."""


@dataclass(frozen=True)
class Stage:
    id: str
    title: str
    role: str
    goal: str
    outputs: tuple[str, ...]
    reads: tuple[str, ...]
    gate: str
    needs_docker: bool = False
    blind: tuple[str, ...] = field(default_factory=tuple)


STAGES: tuple[Stage, ...] = (
    Stage(
        id="analyze",
        title="信息收集",
        role="Analyzer",
        goal=(
            "阅读 advisory、修复提交和上游源码，把可核对的事实蒸馏成研究笔记；"
            "信息不足时以 error 结束，不要猜。"
        ),
        outputs=("research/public.md", "research/analyze-res.toml"),
        reads=("candidates/<ID>.toml",),
        gate="static",
    ),
    Stage(
        id="generate",
        title="逻辑组件生成",
        role="Generator",
        goal=(
            "只依据 public.md 写出漏洞图解 diagram.toml、攻击输入 fixtures 与机制 PoC "
            "reproduce.py；此阶段不碰 Docker。"
        ),
        outputs=("diagram.toml", "reproduce.py", "fixtures/", "research/generate-res.toml"),
        reads=("research/public.md",),
        gate="static",
    ),
    Stage(
        id="build",
        title="环境构建（盲建）",
        role="Builder",
        goal=(
            "构建固定版本、可离线安装的 vulnerable/patched 镜像与 build.inputs；"
            "不得阅读 reproduce.py/verify.py/fixtures 来决定装什么。"
        ),
        outputs=("Dockerfile", "metadata.toml", "research/build-res.toml"),
        reads=("research/public.md", "metadata.toml"),
        gate="lint",
        blind=("reproduce.py", "verify.py", "end_to_end.py", "fixtures/"),
    ),
    Stage(
        id="validate",
        title="漏洞验证",
        role="Validator",
        goal="让漏洞版攻击用例通过、漏洞版正常任务通过；修复版攻击必须被阻断。",
        # validate 必须写出首版 verify.py：runner reproduce 无条件执行 /lab/verify.py，
        # 没有它就无从判定「漏洞版攻击成功」。solve 再加固并跑全四场景。
        outputs=("verify.py", "research/validate-res.toml"),
        reads=("reproduce.py", "diagram.toml", "fixtures/"),
        gate="reproduce-vulnerable",
        needs_docker=True,
    ),
    Stage(
        id="solve",
        title="修复对照与验证器",
        role="Solver",
        goal="加固 verify.py 独立核对证据，并跑通四场景三轮；失败时修正环境而不是放宽断言。",
        outputs=("verify.py", "research/solve-res.toml"),
        reads=("reproduce.py", "diagram.toml", "fixtures/"),
        gate="reproduce-rounds",
        needs_docker=True,
    ),
    Stage(
        id="check",
        title="整体质检",
        role="Checker",
        goal="静态校验、图解漂移、TODO 残留、装置词与脱敏全部清零，并保留 draft 身份。",
        outputs=("research/check-res.toml",),
        reads=(),
        gate="check",
    ),
)

STAGE_BY_ID = {stage.id: stage for stage in STAGES}
APPARATUS_HINT = "、".join(diagram.APPARATUS[:6])
RESULT_STATUS = re.compile(r'status\s*=\s*"(continue|error|pause)"')

# The in-container entrypoint contract, shared by the generate/validate/solve briefs.
LAB_CONTRACT = """\
运行器把 `runner/lab_support.py` 复制到镜像的 `/lab/lab_support.py`，两个脚本都从它导入：

```python
from lab_support import parser, read_context, record, verify
```

`reproduce.py` 的固定结构：

- `args = parser(__doc__).parse_args()`；`context = read_context(args.context)`；
- 依据 `context["scenario"]`（`attack` / `benign`）从 `/lab/fixtures/` 读取固定输入；
- **调用被固定的上游代码本体**（不要重写或抽取漏洞函数）；
- 把可观察效果写到 `args.output` 目录，并给出 `target_ready` 布尔值；
- 返回 `record(context, args.output, observation, {"<effect-file>": <bytes|str>})`；
  `observation` 必须显式包含 `target_ready` 和 `execution_status`（`completed`/`failed`/`not_run`）。

`verify.py` 的固定结构（`validate` 产出首版，`solve` 加固）：

- 只读 `facts.json`、`observation.json` 与效果文件，**不得重跑攻击**；
- 用 `verify(args.context, args.output, check)`，其中 `check` 返回
  `(check_id, passed, expected, actual)`；`check_id` 必须是
  `vulnerable_effect_observed`（漏洞版攻击）、`patched_effect_blocked`（修复版攻击）
  或 `benign_task_passed`（正常任务）之一。
- `runner reproduce` **无条件执行** `/lab/verify.py`：缺了它或它返回 `not_run`(2)，
  整个复现就算失败。所以 `validate` 必须先写出一份能判定漏洞版攻击的 verifier。

`fixtures/manifest.toml` 的 `[files]` 必须按相对路径记录每个 fixture 的 SHA-256
（`manifest.toml` 与 `README.md` 除外）；攻击输入与正常输入都要有。
"""


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def split_environment(environment_id: str) -> tuple[str, str]:
    parts = environment_id.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise FactoryError(f"Invalid environment id: {environment_id!r}")
    return parts[0], parts[1]


def environment_directory(root: Path, environment_id: str) -> Path:
    product, identifier = split_environment(environment_id)
    directory = Path(root) / "environments" / product / identifier
    if not (directory / "metadata.toml").is_file():
        raise FactoryError(f"Environment is not scaffolded in this root: {environment_id}")
    return directory


def research_directory(root: Path, environment_id: str) -> Path:
    product, identifier = split_environment(environment_id)
    directory = Path(root) / "research" / product / identifier
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def state_path(root: Path, environment_id: str) -> Path:
    return research_directory(root, environment_id) / "state.json"


def read_state(root: Path, environment_id: str) -> dict:
    path = state_path(root, environment_id)
    if not path.is_file():
        return {
            "schema_version": SCHEMA,
            "environment_id": environment_id,
            "updated_at": now(),
            "stages": {stage.id: "not_run" for stage in STAGES},
            "notes": {},
        }
    return json.loads(path.read_text(encoding="utf-8"))


def write_state(root: Path, environment_id: str, state: dict) -> None:
    state["updated_at"] = now()
    state_path(root, environment_id).write_text(
        json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def result_status(path: Path) -> str:
    """Read ``status`` from an agent result file, or ``not_run`` when absent."""
    if not path.is_file():
        return "not_run"
    match = RESULT_STATUS.search(path.read_text(encoding="utf-8"))
    return match.group(1) if match else "not_run"


def _read_candidate(root: Path, environment_id: str) -> dict:
    _, identifier = split_environment(environment_id)
    path = Path(root) / "candidates" / f"{identifier}.toml"
    if not path.is_file():
        return {}
    return tomllib.loads(path.read_text(encoding="utf-8"))


def brief(root: Path, environment_id: str, stage_id: str) -> str:
    """Return the full agent prompt for one stage (Role/Goal/Resources/Verification)."""
    stage = STAGE_BY_ID.get(stage_id)
    if stage is None:
        raise FactoryError(f"Unknown stage: {stage_id!r}; expected one of {', '.join(STAGE_BY_ID)}")
    directory = environment_directory(root, environment_id)
    research = research_directory(root, environment_id)
    candidate = _read_candidate(root, environment_id)
    _, identifier = split_environment(environment_id)

    lines = [
        f"# Stage `{stage.id}` — {stage.title}（{stage.role}）",
        "",
        f"环境 ID：`{environment_id}`",
        f"环境目录：`{directory}`",
        f"研究目录：`{research}`",
        "",
        "## Role（角色）",
        "",
        f"你是本次复现流水线中的 **{stage.role}**。只做这一阶段，不要越界替别的阶段做决定。",
        "",
        "## Goal（目标）",
        "",
        stage.goal,
        "",
        "## 输入事实（只读）",
        "",
    ]
    if candidate:
        lines += [
            f"- canonical identifier：`{candidate.get('identifier', identifier)}`"
            f"（aliases：`{', '.join(candidate.get('aliases', [])) or '无'}`）",
            f"- advisory：{candidate.get('advisory_url', '')}",
            f"- 标题：{candidate.get('title', '')}",
            f"- 参考链接：{'; '.join(candidate.get('references', [])) or '无'}",
        ]
        if stage.id == "analyze":
            lines.append(
                "- 候选 provenance：`"
                + str((Path(root) / "candidates" / f"{identifier}.toml"))
                + "`"
            )
    else:
        lines.append("- 没有候选 provenance 文件；这是手工创建的环境。")
    for item in stage.reads:
        lines.append(f"- 允许阅读：`{item}`")
    if stage.blind:
        lines += [
            "",
            "### 信息隔离（盲建）",
            "",
            "为了不让你照着断言去凑环境，**禁止阅读**下列文件："
            + "、".join(f"`{item}`" for item in stage.blind)
            + "。如果需要知道依赖，只依据 `research/public.md` 与上游源码/文档判断。",
        ]

    lines += [
        "",
        "## Resources（可用工具与命令）",
        "",
        "- 只允许改动本环境目录和 `research/` 目录，以及本阶段声明的输出。",
        "- 运行仓库命令时必须带 `AVH_ROOT` 指向当前 staging：",
        f"  ```sh",
        f"  AVH_ROOT={root} python3 -m runner check",
        f"  AVH_ROOT={root} python3 -m runner diagram {environment_id}",
        f"  AVH_ROOT={root} python3 -m runner lint {environment_id}",
        f"  AVH_ROOT={root} python3 -m runner build {environment_id} --offline",
        f"  AVH_ROOT={root} python3 -m runner reproduce {environment_id} --build --rounds 3",
        f"  ```",
        "- analyze 阶段可以用 web_search / web_fetch；后续阶段只用本地文件与 Docker。",
        "",
        "## 必须产出",
        "",
    ]
    lines += [f"- `{item}`" for item in stage.outputs]
    lines += [
        "",
        "每个阶段必须写一份结果文件（TOML），状态只能是 `continue` / `error` / `pause`：",
        "",
        "```toml",
        f'status = "continue"',
        f'stage = "{stage.id}"',
        f'environment_id = "{environment_id}"',
        f'updated_at = "{now()}"',
        'reason = "一句话说明本阶段结论"',
        "evidence = []   # 支持结论的 URL、文件或命令",
        "```",
        "",
        "- `error`：信息不足或机制不可复现，**必须**说明缺什么，不要编造。",
        "- `pause`：需要别的阶段返工，写明文件与原因。",
        "",
        "## Verification（客观验收）",
        "",
        f"本阶段的验收命令：`AVH_ROOT={root} python3 -m runner factory gate {environment_id} "
        f"--stage {stage.id}`。",
        "验收由脚本执行，不以你的自述为准。",
    ]
    if stage.id == "analyze":
        lines += [
            "",
            "`research/public.md` 必须恰好包含这些二级标题，且每节都有可核对内容：",
            "",
            *[f"- `{section}`" for section in ANALYSIS_SECTIONS],
            "",
            "写清 vulnerable/patched 的版本、**完整 40 位 commit**、源码 URL，以及修复提交改了哪一处检查。"
            "如果找不到修复提交或无法离线构建，直接写 `status = \"error\"`。",
        ]
    if stage.id == "generate":
        lines += [
            "",
            "`diagram.toml` 的规则（完整契约见 `docs/diagram-contract.md`）：",
            "",
            "- 主体类型只有 `actor|client|service|tool|store|sink`；阶段只有 `setup|trigger|effect`；",
            "- 每个主体必须有 `role`；步骤 `n` 必须 `1..N` 连续且引用已声明主体；",
            "- 至少一步 `diverges = true`，其 `variant` 必须是 `vulnerable_only` 或 `patched_only`；",
            "- 每个主体要么被步骤引用，要么 `static = true`；一个主体最多属于一个信任边界；",
            f"- `summary`、主体 `label`、边界 `label`、步骤 `action` 里不得出现装置词（如 {APPARATUS_HINT}）。",
            "",
            "写之前先过一遍攻击者视角四问：它想要什么、它实际能控制什么、"
            "哪些是环境前提而不是攻击动作、效果最终落到谁手里。",
            "",
            "然后必须运行渲染并确认无漂移：",
            "",
            "```sh",
            f"AVH_ROOT={root} python3 -m runner diagram {environment_id}",
            f"AVH_ROOT={root} python3 -m runner diagram {environment_id} --check",
            "```",
            "",
            "### `reproduce.py` 与 fixtures 的入口契约",
            "",
            LAB_CONTRACT,
        ]
    if stage.id == "build":
        lines += [
            "",
            "`metadata.toml` 的 `build.inputs` 每项形如 "
            "`{ name = \"...\", url = \"https://...\", sha256 = \"<64 hex>\" }`，"
            "必须包含源码归档与所有离线安装所需依赖；`build.base_image` 必须固定 digest。",
            "Dockerfile 必须 `ARG BASE_IMAGE` / `FROM ${BASE_IMAGE}`，并在 `--network none` 下可构建。",
        ]
    if stage.id in {"validate", "solve"}:
        lines += [
            "",
            "四场景含义：漏洞版攻击必须成功、修复版攻击必须被阻断、两版正常任务都必须通过。",
            "证据只能来自产品真实产生的效果；候选/PoC 自报的 `success` 字段不算证据。",
            "启动失败、超时、缺证据都不能算作修复阻断。",
        ]
        if stage.id == "validate":
            lines += [
                "",
                "### 你必须写出首版 `verify.py`",
                "",
                "`runner reproduce` 无条件执行镜像里的 `/lab/verify.py`，因此本阶段**必须产出**"
                "`verify.py`；脚手架留下的桩只会让复现以 `not_run` 失败。",
                "本阶段只跑 `--scenario vulnerable`：先让漏洞版攻击被独立证据判定为成功。"
                "`solve` 阶段会在此基础上加固，并跑全四场景三轮。",
                "",
                LAB_CONTRACT,
            ]
        if stage.id == "solve":
            lines += ["", "### `verify.py` 的入口契约", "", LAB_CONTRACT]
    if stage.id == "check":
        lines += [
            "",
            "逐项确认：",
            "",
            "- [ ] `AVH_ROOT` check 通过，`diagram --all --check` 无漂移；",
            "- [ ] 环境目录内没有 `TODO` 残留（metadata/README/diagram）；",
            "- [ ] 图解只描述漏洞本身，没有 runner/verify/结果卷等装置词；",
            "- [ ] fixtures 中没有真实凭据、真实用户数据或宿主路径；",
            "- [ ] `lifecycle` 仍是 `draft`，`verification.*.status` 与真实执行一致。",
        ]

    if stage.needs_docker:
        lines += [
            "",
            "> 本阶段需要 Docker，并且会真实运行漏洞代码。必须在一次性、可销毁的环境里执行，"
            "不要对生产宿主机运行。",
        ]
    return "\n".join(lines)


def write_brief(root: Path, environment_id: str, stage_id: str) -> Path:
    path = research_directory(root, environment_id) / f"brief-{stage_id}.md"
    path.write_text(brief(root, environment_id, stage_id) + "\n", encoding="utf-8")
    return path


def _run(command: list[str], root: Path, timeout: int) -> dict:
    # DOCKER_CONFIG and BUILDX_CONFIG are forwarded because Docker and the buildx
    # builder each need a writable state directory, and some hosts (and sandboxes)
    # point them away from ~/.docker.
    environment = {"AVH_ROOT": str(Path(root).resolve()), "PATH": "/usr/bin:/bin:/usr/local/bin"}
    for key in ("DOCKER_CONFIG", "BUILDX_CONFIG"):
        if os.environ.get(key):
            environment[key] = os.environ[key]
    completed = subprocess.run(
        command, cwd=str(CHECKOUT), env=environment,
        capture_output=True, text=True, timeout=timeout,
    )
    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
    }


def _gate_analyze(root: Path, environment_id: str, directory: Path, research: Path) -> list[str]:
    problems = []
    public = research / "public.md"
    if not public.is_file():
        return ["research/public.md is missing"]
    text = public.read_text(encoding="utf-8")
    for section in ANALYSIS_SECTIONS:
        if section not in text:
            problems.append(f"research/public.md is missing section {section}")
    if result_status(research / "analyze-res.toml") != "continue":
        problems.append("research/analyze-res.toml status is not continue")
    return problems


def _gate_generate(root: Path, environment_id: str, directory: Path, research: Path) -> list[str]:
    problems = []
    data = diagram.load(directory)
    if data is None:
        return ["diagram.toml is missing"]
    try:
        diagram.validate(directory, data)
    except ValueError as error:
        problems.append(f"diagram.toml invalid: {error}")
    if "TODO" in (directory / "diagram.toml").read_text(encoding="utf-8"):
        problems.append("diagram.toml still contains TODO placeholders")
    reproduce = (directory / "reproduce.py").read_text(encoding="utf-8")
    if "NOT IMPLEMENTED" in reproduce:
        problems.append("reproduce.py is still the template stub")
    problems.extend(_in_container_reference_problems(directory))
    from .cli import read_toml
    metadata_path = directory / "metadata.toml"
    metadata = read_toml(metadata_path) if metadata_path.is_file() else {}
    problems.extend(_variant_environment_problems(directory, metadata))
    try:
        drift = diagram.drift(directory, data)
    except ValueError as error:
        drift = [str(error)]
    problems.extend(f"diagram drift: {item}" for item in drift)
    if result_status(research / "generate-res.toml") != "continue":
        problems.append("research/generate-res.toml status is not continue")
    return problems


def _in_container_reference_problems(directory: Path) -> list[str]:
    """Reject runtime scripts that read files the image never contains.

    ``metadata.toml`` stays on the host: the Dockerfile copies only ``inputs/``,
    ``reproduce.py``, ``verify.py``, ``end_to_end.py``, ``fixtures/`` and
    ``lab_support.py`` into ``/lab``, and ``_prepare_candidate_container`` deletes
    every other top-level file there. A script that *reads* it therefore dies with
    ``FileNotFoundError`` on the first real run, which the static ``build`` gate
    cannot see because it never materialises the image.

    Only a real read counts. Prose that names the file (a comment or a docstring
    explaining where a pinned revision was taken from) is not a defect, so the
    check parses the module and looks for the name in a call argument, a path
    join, or a bare string used as an operand.
    """
    problems = []
    for name in ("reproduce.py", "verify.py", "end_to_end.py"):
        path = directory / name
        if not path.is_file():
            continue
        if _reads_metadata_toml(path.read_text(encoding="utf-8")):
            problems.append(
                f"{name} reads metadata.toml, which is never present in the image "
                f"(only inputs/, reproduce.py, verify.py, end_to_end.py, fixtures/ "
                f"and lab_support.py are copied into /lab); inline the value or read it "
                f"from fixtures/ instead")
    return problems


def _reads_metadata_toml(source: str) -> bool:
    """True when ``source`` reads ``metadata.toml`` without guarding for absence.

    A defensive read (``if not path.is_file(): return {}``) is fine: it degrades to
    the inlined constants. An unguarded ``_read_toml(ENVIRONMENT_DIR / ...)`` is
    not: the file is absent in the image, so the run dies with ``FileNotFoundError``.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        # An unparsable script is reported by its own gate; do not guess here.
        return False

    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", None)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                docstrings.add(id(body[0].value))

    names = {
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
        and node.value.endswith("metadata.toml") and id(node) not in docstrings
    }
    if not names:
        return False

    guarded = any(
        isinstance(call.func, ast.Attribute) and call.func.attr == "is_file"
        for node in ast.walk(tree) if isinstance(node, ast.If)
        for call in ast.walk(node.test) if isinstance(call, ast.Call)
    )

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        # `_read_toml`/`_load_toml` are local wrappers around tomllib; a call that
        # passes the metadata path to one of them is just as fatal as a bare open().
        if name not in {"open", "read_text", "read_bytes", "load", "loads"} \
                and "toml" not in name:
            continue
        if not guarded and any(
            isinstance(inner, ast.Constant) and inner.value in names
            for inner in ast.walk(node)
        ):
            return True
    return False


def _variant_environment_problems(directory: Path, metadata: dict) -> list[str]:
    """Reject runtime scripts that hand a variant its own environment.

    The contract is that ``vulnerable`` and ``patched`` differ only in the pinned
    artifact: the harness must present both revisions with the same environment and
    the same attack, so that whatever differs in the result is attributable to the
    fix. A variant-guarded environment assignment breaks that: it is the harness,
    not the pinned revision, that produces the difference the verifier then reads.

    This catches the concrete defect found in ``minds-platform/CVE-2026-73678``,
    where the patched arm alone received ``COWORK_REQUIRE_AUTH=true`` -- an
    explicitly-set value that selects a branch which bypasses the very validator
    the environment claims to demonstrate, so the observed refusal came from the
    harness rather than from the fix.

    Artifact selection stays allowed, because that *is* the variant: choosing
    ``/src/patched`` over ``/src/vulnerable``, or which keyword a build step takes,
    is legitimate. Only writes that reach the target's environment or config are
    flagged: a ``KEY=value`` literal appended to a list, a ``SCREAMING_CASE`` key
    set on a mapping, or an ``os.environ`` / ``os.putenv`` / ``os.setenv`` write.

    A documented exception is available for the rare case where a revision
    genuinely requires different configuration to run the same scenario: list the
    environment variable in ``[runtime].variant_env_exceptions`` with a reason.
    """
    excepted = set()
    runtime = metadata.get("runtime") or {}
    for item in runtime.get("variant_env_exceptions") or []:
        if isinstance(item, str):
            excepted.add(item)
        elif isinstance(item, dict) and isinstance(item.get("name"), str):
            excepted.add(item["name"])

    problems: list[str] = []
    for name in ("reproduce.py", "verify.py", "end_to_end.py"):
        path = directory / name
        if not path.is_file():
            continue
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source)
        except SyntaxError:
            # An unparsable script is reported by its own gate; do not guess here.
            continue
        for statement, lineno in _variant_guarded_statements(tree):
            for target, value in _environment_assignments(statement):
                if target in excepted:
                    continue
                problems.append(
                    f"{name}:{lineno} assigns {target} to the target "
                    f"environment under a variant guard; the two revisions must run "
                    f"in the same environment so that only the pinned fix explains a "
                    f"behavioural difference. Move it out of the variant guard, drive "
                    f"it from the pinned revision's own configuration, or declare it "
                    f"in [runtime].variant_env_exceptions with a reason")
    return problems


def _variant_guarded_statements(tree: ast.AST) -> list[tuple[ast.stmt, int]]:
    """``(statement, lineno)`` for each statement selected by ``variant``.

    Covers both ``if``/``else`` arms and conditional expressions, whose synthetic
    wrappers carry no source position of their own.
    """
    found: list[tuple[ast.stmt, int]] = []
    seen: set[int] = set()

    def add(statement: ast.stmt, lineno: int) -> None:
        for item in _flatten(statement):
            if id(item) not in seen:
                seen.add(id(item))
                found.append((item, lineno))

    for node in ast.walk(tree):
        if isinstance(node, ast.If) and _mentions_variant(node.test):
            for branch in (node.body, node.orelse):
                for statement in branch:
                    add(statement, statement.lineno)
        elif isinstance(node, ast.IfExp) and _mentions_variant(node.test):
            # `os.putenv(k, v) if variant == "patched" else None` is the same write
            # written as an expression; record the call for inspection.
            for value in (node.body, node.orelse):
                if isinstance(value, ast.expr) and not isinstance(value, ast.Constant):
                    for sub in ast.walk(value):
                        if isinstance(sub, ast.stmt):
                            add(sub, sub.lineno)
                        elif isinstance(sub, ast.Call):
                            add(ast.Expr(value=sub), sub.lineno)
    return found


def _mentions_variant(test: ast.expr) -> bool:
    return any(
        isinstance(node, ast.Name) and "variant" in node.id
        for node in ast.walk(test)
    )


def _flatten(statement: ast.stmt) -> list[ast.stmt]:
    """The statement plus any statements nested inside its own control flow."""
    found = [statement]
    for node in ast.walk(statement):
        if node is statement:
            continue
        if isinstance(node, ast.stmt):
            found.append(node)
    return found


def _environment_assignments(statement: ast.stmt) -> list[tuple[str, str]]:
    """``(name, description)`` for each target-environment write in ``statement``.

    The whole subtree is scanned, so a write nested in a ``try`` block or written as
    a conditional expression is found too.
    """
    found: list[tuple[str, str]] = []

    def env_name(text: str) -> bool:
        return bool(re.match(r"^[A-Z][A-Z0-9_]*=", text))

    def key_name(text: str) -> bool:
        return bool(re.match(r"^[A-Z][A-Z0-9_]*$", text))

    for node in ast.walk(statement):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Subscript):
                    base = target.value
                    base_name = base.attr if isinstance(base, ast.Attribute) else getattr(base, "id", "")
                    key = _literal_text(target.slice)
                    if base_name in {"environ", "env", "putenv"}:
                        if key and key_name(key):
                            found.append((key, "os.environ write"))
                    elif key and key_name(key):
                        found.append((key, "mapping key write"))
                elif isinstance(target, ast.Name) and isinstance(node.value, ast.Constant) \
                        and isinstance(node.value.value, str) and env_name(node.value.value):
                    # `entry = "COWORK_REQUIRE_AUTH=true"` for a later append.
                    found.append((node.value.value.split("=", 1)[0], "KEY=value literal"))
        elif isinstance(node, ast.Call):
            func = node.func
            call_name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if call_name in {"append", "extend", "insert"} and node.args:
                text = _literal_text(node.args[0])
                if text and env_name(text):
                    found.append((text.split("=", 1)[0], "KEY=value appended"))
            elif call_name in {"putenv", "setenv"} and node.args:
                text = _literal_text(node.args[0])
                if text and key_name(text):
                    found.append((text, f"os.{call_name}"))
    return found


def _literal_text(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _locally_built_base_image(metadata: dict) -> str | None:
    """Return the base image name when it can only exist on the machine that built it.

    A builder agent that experiments with ``docker build`` leaves tagged images
    behind (``avh-probe-py311``, ``avh-rust-probe:tmp4``, ...). Pointing
    ``build.base_image`` at one of those passes every static check on the host that
    has it and then fails with "pull access denied" on any other machine, so the
    environment is not reproducible. ``avh-`` is this tool's own resource prefix.
    """
    name = (metadata.get("build") or {}).get("base_image", "").split("@")[0]
    if re.match(r"^(?:local/)?avh-", name):
        return name
    return None


def _gate_build(root: Path, environment_id: str, directory: Path, research: Path,
                execute: bool, timeout: int) -> tuple[list[str], list[dict]]:
    from .build import validate_sources
    from .cli import read_toml

    problems, runs = [], []
    metadata = read_toml(directory / "metadata.toml")
    try:
        validate_sources(directory, metadata)
    except ValueError as error:
        problems.append(f"build.inputs invalid: {error}")
    if "Environment recipe is not implemented" in (directory / "Dockerfile").read_text(encoding="utf-8"):
        problems.append("Dockerfile is still the template stub")
    local_base = _locally_built_base_image(metadata)
    if local_base:
        problems.append(
            f"build.base_image {local_base!r} is a locally built probe image, not a "
            f"published base; it passes here only because this host still has it and "
            f"would fail with 'pull access denied' anywhere else. Pin a public base "
            f"image with a digest")
    if result_status(research / "build-res.toml") != "continue":
        problems.append("research/build-res.toml status is not continue")
    if execute and not problems:
        run = _run([sys.executable, "-m", "runner", "lint", environment_id], root, timeout)
        runs.append(run)
        if run["returncode"] != 0:
            problems.append("runner lint failed")
    return problems, runs


def reproduce_command(root: Path, environment_id: str, stage_id: str) -> list[str]:
    """Build the reproduce invocation a stage gate runs, honouring declared exceptions."""
    from .cli import read_toml

    directory = environment_directory(root, environment_id)
    metadata = read_toml(directory / "metadata.toml")
    exceptions = metadata.get("runtime", {}).get("exceptions", [])
    scenario = ["--scenario", "vulnerable"] if stage_id == "validate" else []
    # The contract requires --allow-exceptions whenever an environment documents
    # isolation exceptions, so the gate must carry the flag for those cases.
    allowed = ["--allow-exceptions"] if exceptions else []
    return [sys.executable, "-m", "runner", "reproduce", environment_id,
            "--build", "--rounds", "3", *scenario, *allowed]


def _gate_reproduce(root: Path, environment_id: str, stage_id: str,
                    execute: bool, timeout: int) -> tuple[list[str], list[dict]]:
    if not execute:
        return ["docker stages require --execute"], []
    command = reproduce_command(root, environment_id, stage_id)
    run = _run(command, root, timeout)
    problems = [] if run["returncode"] == 0 else [f"{' '.join(command)} exited {run['returncode']}"]
    if result_status(research_directory(root, environment_id) / f"{stage_id}-res.toml") != "continue":
        problems.append(f"research/{stage_id}-res.toml status is not continue")
    return problems, [run]


def _gate_check(root: Path, environment_id: str) -> tuple[list[str], list[dict]]:
    problems, runs = [], []
    for command in (
        [sys.executable, "-m", "runner", "check"],
        [sys.executable, "-m", "runner", "diagram", environment_id, "--check"],
    ):
        run = _run(command, root, 120)
        runs.append(run)
        if run["returncode"] != 0:
            problems.append(f"{' '.join(command)} exited {run['returncode']}")
    return problems, runs


def gate(root: Path, environment_id: str, stage_id: str, *, execute: bool = False,
         timeout: int = 1200) -> dict:
    """Run the objective gate for a stage and record the result in state.json.

    Stages are ordered. A gate refuses to run while an earlier stage has not passed,
    because a later gate cannot mean anything about an unfinished environment: the
    ``check`` gate passes on an empty scaffold, which would let a draft that was never
    generated or built look like it cleared quality control.
    """
    root = Path(root)
    stage = STAGE_BY_ID.get(stage_id)
    if stage is None:
        raise FactoryError(f"Unknown stage: {stage_id!r}")
    state = read_state(root, environment_id)
    for earlier in STAGES:
        if earlier.id == stage_id:
            break
        if state.get("stages", {}).get(earlier.id) != "passed":
            raise FactoryError(
                f"Stage {stage_id!r} requires {earlier.id!r} to pass first "
                f"(currently {state.get('stages', {}).get(earlier.id, 'not_run')!r})")
    directory = environment_directory(root, environment_id)
    research = research_directory(root, environment_id)
    runs: list[dict] = []

    if stage_id == "analyze":
        problems = _gate_analyze(root, environment_id, directory, research)
    elif stage_id == "generate":
        problems = _gate_generate(root, environment_id, directory, research)
    elif stage_id == "build":
        problems, runs = _gate_build(root, environment_id, directory, research, execute, timeout)
    elif stage_id in {"validate", "solve"}:
        problems, runs = _gate_reproduce(root, environment_id, stage_id, execute, timeout)
    elif stage_id == "check":
        problems, runs = _gate_check(root, environment_id)
    else:  # pragma: no cover - STAGES is exhaustive
        raise FactoryError(f"No gate for stage {stage_id!r}")

    state["stages"][stage_id] = "passed" if not problems else "failed"
    state["notes"][stage_id] = {
        "checked_at": now(),
        "problems": problems,
        "runs": runs,
    }
    write_state(root, environment_id, state)
    return {"stage": stage_id, "passed": not problems, "problems": problems, "runs": runs}
