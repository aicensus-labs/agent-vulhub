"""Render AI-editable Mermaid mechanism diagrams from structured diagram.toml.

`diagram.toml` is the single source of truth for an environment's vulnerability
diagram. This module validates it, renders the trigger sequence and the entity
/ trust-boundary flowchart, and keeps the README block in sync.

A diagram describes the vulnerability itself: the attacker-controlled input, the
affected upstream components, and the controlled effect. Reproduction tooling
(runner, verifier, result volumes, container orchestration, protocol stubs) is
deliberately not expressible here, so it cannot leak into a trigger chain.
"""

import re
from pathlib import Path
import tomllib

SCHEMA = 1
ID = re.compile(r"[a-z][a-z0-9_]*")
# Vocabulary of the vulnerability itself; harness roles have no kind on purpose.
KINDS = ("actor", "client", "service", "tool", "store", "sink")
TRUST = ("trusted", "semi_trusted", "untrusted_input", "attacker_controlled", "out_of_scope")
PHASES = ("setup", "trigger", "effect")
VARIANTS = ("both", "vulnerable_only", "patched_only")
ARROWS = {"both": "->>", "vulnerable_only": "-->>", "patched_only": "-x"}
FLOW_ARROWS = {"both": "-->", "vulnerable_only": "-.->", "patched_only": "-.->"}
# Diagram-visible text — node labels, arrow messages, subgraph titles, the summary
# — explains the vulnerability itself. Vocabulary that belongs to this repository's
# reproduction apparatus has to stay out of it and live either in the prose fields
# (role, detail, note) or the provenance fields (source, evidence), which the README
# renders as separate sections. Keep this list narrow: it runs in `runner check`,
# and a false positive blocks a legitimate diagram.
APPARATUS = (
    "本仓库", "本实验", "本环境",
    "fixture", "fixtures/",
    "synthetic", "替身",
    "本地假", "假 CLI",
    "verify.py", "observation.json",
    "复现工具链", "观测文件", "结果卷",
)
# Node and subgraph identifiers become Mermaid keywords verbatim; reject collisions.
RESERVED = frozenset({
    "actor", "alt", "and", "call", "class", "classdef", "click", "deactivate", "default",
    "direction", "else", "end", "flowchart", "graph", "href", "linkstyle", "loop", "note",
    "opt", "over", "par", "participant", "rect", "sequencediagram", "style", "subgraph",
})
BEGIN = "<!-- diagram:begin"
END = "<!-- diagram:end -->"
README = "README.zh-cn.md"
SOURCE = "diagram.toml"


def load(directory):
    """Return parsed diagram.toml, or None when the environment has no diagram."""
    path = Path(directory) / SOURCE
    if not path.is_file():
        return None
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise ValueError(f"diagram.toml is not valid TOML: {error}") from error
    if not isinstance(data, dict):
        raise ValueError("diagram.toml must contain a table")
    return data


def _text(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _enum(value, allowed, field):
    if value not in allowed:
        raise ValueError(f"{field} must be one of {', '.join(allowed)}")
    return value


def _vulnerability_only(value, field):
    """Reject reproduction-apparatus vocabulary from diagram-visible text."""
    lowered = str(value).lower()
    for word in APPARATUS:
        if word.lower() in lowered:
            raise ValueError(
                f"{field} describes the reproduction apparatus ({word!r}); "
                "diagram-visible text must describe the vulnerability itself"
            )
    return value


def _fixture_paths(directory):
    manifest = Path(directory) / "fixtures" / "manifest.toml"
    if not manifest.is_file():
        return set()
    entries = tomllib.loads(manifest.read_text(encoding="utf-8")).get("files", {})
    return set(entries) if isinstance(entries, dict) else set()


def _check_reference(directory, fixtures, value, field):
    if not isinstance(value, str) or not value.startswith("fixtures/"):
        return
    relative = value[len("fixtures/"):]
    if not relative or not (Path(directory) / "fixtures" / relative).is_file():
        raise ValueError(f"{field} references a missing fixture: {value}")
    if relative not in fixtures:
        raise ValueError(f"{field} references a fixture absent from fixtures/manifest.toml: {value}")


def validate(directory, data):
    """Static validation; raises ValueError on the first problem found."""
    directory = Path(directory)
    if data.get("schema_version") != SCHEMA:
        raise ValueError(f"diagram schema_version must be {SCHEMA}")
    _text(data.get("title"), "diagram title")
    _vulnerability_only(_text(data.get("summary"), "diagram summary"), "diagram summary")

    entities = data.get("entities")
    if not isinstance(entities, list) or not entities:
        raise ValueError("diagram needs at least one [[entities]] entry")
    by_id = {}
    for index, entity in enumerate(entities):
        if not isinstance(entity, dict):
            raise ValueError(f"entities[{index}] must be a table")
        identifier = _text(entity.get("id"), f"entities[{index}].id")
        if not ID.fullmatch(identifier):
            raise ValueError(f"invalid entity id: {identifier!r}")
        if identifier.lower() in RESERVED:
            raise ValueError(f"entity id is a Mermaid keyword: {identifier!r}")
        if identifier in by_id:
            raise ValueError(f"duplicate entity id: {identifier}")
        _vulnerability_only(_text(entity.get("label"), f"{identifier}.label"), f"{identifier}.label")
        _enum(entity.get("kind"), KINDS, f"{identifier}.kind")
        _enum(entity.get("trust"), TRUST, f"{identifier}.trust")
        _text(entity.get("role"), f"{identifier}.role")
        by_id[identifier] = entity

    boundaries = data.get("boundaries", [])
    if not isinstance(boundaries, list):
        raise ValueError("boundaries must be an array of tables")
    boundary_ids = set()
    for index, boundary in enumerate(boundaries):
        if not isinstance(boundary, dict):
            raise ValueError(f"boundaries[{index}] must be a table")
        identifier = _text(boundary.get("id"), f"boundaries[{index}].id")
        if not ID.fullmatch(identifier):
            raise ValueError(f"invalid boundary id: {identifier!r}")
        if identifier.lower() in RESERVED:
            raise ValueError(f"boundary id is a Mermaid keyword: {identifier!r}")
        if identifier in boundary_ids:
            raise ValueError(f"duplicate boundary id: {identifier}")
        if identifier in by_id:
            raise ValueError(f"boundary id collides with entity id: {identifier}")
        boundary_ids.add(identifier)
        _vulnerability_only(_text(boundary.get("label"), f"{identifier}.label"), f"{identifier}.label")
        _text(boundary.get("note"), f"{identifier}.note")
        members = boundary.get("members")
        if not isinstance(members, list) or not members:
            raise ValueError(f"{identifier}.members must be a non-empty array")
        for member in members:
            if member not in by_id:
                raise ValueError(f"{identifier}.members references unknown entity: {member}")

    placed = [member for boundary in boundaries for member in boundary["members"]]
    if len(placed) != len(set(placed)):
        raise ValueError("an entity may belong to at most one boundary")

    steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ValueError("diagram needs at least one [[steps]] entry")
    fixtures = _fixture_paths(directory)
    referenced = set()
    diverging = 0
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            raise ValueError(f"steps[{index}] must be a table")
        number = step.get("n")
        if not isinstance(number, int) or isinstance(number, bool) or number != index + 1:
            raise ValueError(f"steps must be numbered 1..N in order; expected n = {index + 1}")
        _enum(step.get("phase"), PHASES, f"steps[{index}].phase")
        _vulnerability_only(_text(step.get("action"), f"steps[{index}].action"), f"steps[{index}].action")
        for key in ("from", "to"):
            value = step.get(key)
            if value not in by_id:
                raise ValueError(f"steps[{index}].{key} references unknown entity: {value!r}")
            referenced.add(value)
        variant = _enum(step.get("variant"), VARIANTS, f"steps[{index}].variant")
        if step.get("diverges"):
            if variant == "both":
                raise ValueError(f"steps[{index}] diverges but is not vulnerable_only or patched_only")
            diverging += 1
        _check_reference(directory, fixtures, step.get("evidence"), f"steps[{index}].evidence")

    if diverging == 0:
        raise ValueError("diagram needs at least one step with diverges = true")

    for identifier, entity in by_id.items():
        if identifier not in referenced and not entity.get("static"):
            raise ValueError(f"entity {identifier} appears in no step and is not static = true")
        _check_reference(directory, fixtures, entity.get("source"), f"{identifier}.source")


def _plain(value):
    return re.sub(r"\s+", " ", str(value)).strip()


def _label(value):
    """Safe inside a Markdown table cell or a plain sentence."""
    return re.sub(r"[<>]", "", _plain(value).replace('"', "'").replace("|", "/"))


def _mermaid(value):
    """Safe inside a Mermaid node label, edge label, message or alias."""
    return _label(value).replace("#", "＃").replace(";", ",")


def _banner(data):
    return "%% " + _plain(data["title"]) + " — generated from diagram.toml"


def _order(data):
    seen = []
    for step in data["steps"]:
        for key in (step["from"], step["to"]):
            if key not in seen:
                seen.append(key)
    for entity in data["entities"]:
        if entity["id"] not in seen:
            seen.append(entity["id"])
    return seen


def _sequence(data):
    entities = {entity["id"]: entity for entity in data["entities"]}
    lines = [_banner(data), "sequenceDiagram"]
    for identifier in _order(data):
        entity = entities[identifier]
        keyword = "actor" if entity["kind"] == "actor" else "participant"
        lines.append(f"  {keyword} {identifier} as {_mermaid(entity['label'])}")
    phase = None
    diverged = False
    for step in data["steps"]:
        if step["phase"] != phase:
            phase = step["phase"]
            lines.append(f"  Note over {_pair(step)}: 阶段 {phase}")
        arrow = ARROWS[step["variant"]]
        message = _mermaid("%d %s" % (step["n"], step["action"]))
        lines.append(f"  {step['from']} {arrow} {step['to']}: {message}")
        if step.get("diverges") and not diverged:
            # A vulnerable/patched pair is one fork; annotate it once.
            lines.append(f"  Note over {_pair(step)}: 分歧点：漏洞版与修复版在此分叉")
        diverged = bool(step.get("diverges"))
    return "\n".join(lines) + "\n"


def _pair(step):
    return step["from"] if step["from"] == step["to"] else f"{step['from']},{step['to']}"


def _node(entity):
    marker = "⚠ " if entity.get("synthetic") else ""
    return f'{entity["id"]}["{_mermaid(entity["label"])}<br/>{marker}{entity["kind"]} · {entity["trust"]}"]'


def _flowchart(data):
    entities = {entity["id"]: entity for entity in data["entities"]}
    lines = [_banner(data), "flowchart LR"]
    placed = set()
    boundaries = data.get("boundaries", [])
    for boundary in boundaries:
        lines.append(f'  subgraph {boundary["id"]}["{_mermaid(boundary["label"])}"]')
        for member in boundary["members"]:
            lines.append("    " + _node(entities[member]))
            placed.add(member)
        lines.append("  end")
    for identifier in _order(data):
        if identifier not in placed:
            lines.append("  " + _node(entities[identifier]))
    styles = []
    for index, step in enumerate(data["steps"]):
        arrow = FLOW_ARROWS[step["variant"]]
        # Only the step number. Mermaid places every edge label at its edge
        # midpoint and never resolves collisions, so full action text overlaps
        # as soon as one node has several outgoing edges or two nodes talk both
        # ways. Measured: prose labels collide on 2 of 3 samples, short labels
        # still collide on 1, numbers never do. The prose lives in the sequence
        # diagram, whose steps share this numbering.
        lines.append(f'  {step["from"]} {arrow}|"{step["n"]}"| {step["to"]}')
        # A patched step is the fix blocking, so it wins over the generic
        # divergence colour: red marks the vulnerable side of the fork, green
        # the blocking side. Both steps of a fork set diverges = true.
        if step["variant"] == "patched_only":
            styles.append(f"  linkStyle {index} stroke:#2e7d32,stroke-width:2px")
        elif step.get("diverges"):
            styles.append(f"  linkStyle {index} stroke:#c0392b,stroke-width:2px")
    # Every box keeps its outline colour but no fill, so the diagram reads on any
    # viewer background (GitHub light/dark, slides, transparent exports).
    classes = {
        "actor": "fill:transparent,stroke:#b03a6a",
        "client": "fill:transparent,stroke:#1565c0",
        "service": "fill:transparent,stroke:#5e35b1",
        "tool": "fill:transparent,stroke:#ef6c00",
        "sink": "fill:transparent,stroke:#c0392b",
        "store": "fill:transparent,stroke:#2e7d32",
    }
    for name, style in classes.items():
        lines.append(f"  classDef {name} {style}")
    lines.append("  classDef synthetic stroke-dasharray: 4 2")
    for identifier, entity in entities.items():
        names = [entity["kind"]] if entity["kind"] in classes else []
        if entity.get("synthetic"):
            names.append("synthetic")
        # `class X a,b` is invalid Mermaid: the comma separates node ids, so a
        # comma-joined class list silently drops every style. Emit one per class.
        for name in names:
            lines.append(f"  class {identifier} {name}")
    for boundary in boundaries:
        lines.append(f'  style {boundary["id"]} fill:transparent')
    lines.extend(styles)
    return "\n".join(lines) + "\n"


def render(data):
    """Return the generated artifact paths mapped to their exact content."""
    return {
        "diagram/mechanism.mmd": _sequence(data),
        "diagram/entities.mmd": _flowchart(data),
    }


def readme_block(data):
    lines = [f"{BEGIN} (generated from {SOURCE} by `python3 -m runner diagram`; edit {SOURCE}, not this block) -->",
             f"## 漏洞图解 — {_label(data['title'])}", "", _plain(data["summary"]), "", "### 涉及主体", "",
             "| 主体 | 类型 | 信任级别 | 在漏洞里的作用 | 来源 |",
             "| --- | --- | --- | --- | --- |"]
    for entity in data["entities"]:
        marker = "⚠ " if entity.get("synthetic") else ""
        source = _label(entity.get("source")) if entity.get("source") else "—"
        lines.append(f"| {marker}{_label(entity['label'])} (`{entity['id']}`) | `{entity['kind']}` | "
                     f"`{entity['trust']}` | {_label(entity['role'])} | {source} |")
    boundaries = data.get("boundaries", [])
    if boundaries:
        lines.extend(["", "**信任边界**", ""])
        for boundary in boundaries:
            members = "、".join(f"`{member}`" for member in boundary["members"])
            lines.append(f"- **{_label(boundary['label'])}** (`{boundary['id']}`)：成员 {members}。{_plain(boundary['note'])}")
    loose = [entity["id"] for entity in data["entities"]
             if not any(entity["id"] in boundary["members"] for boundary in boundaries)]
    if loose:
        lines.append(f"- 未列入上述边界：{'、'.join(f'`{item}`' for item in loose)}。")
    if any(entity.get("synthetic") for entity in data["entities"]):
        lines.extend(["", "标 ⚠ 的主体是本仓库合成的替身或无害效果载体，不代表真实外部目标。"])
    lines.extend(["", "### 触发过程", "", "```mermaid", _sequence(data).rstrip("\n"), "```",
                  "", "### 主体与信任边界", "",
                  "箭头上的数字是上面的步骤编号；方框只标主体和信任级别，具体动作见「触发过程」。",
                  "", "```mermaid", _flowchart(data).rstrip("\n"), "```", ""])
    for step in data["steps"]:
        if step.get("diverges"):
            lines.append(f"**分歧点**：第 {step['n']} 步（`{step['variant']}`）{_plain(step['action'])}。")
    lines.append(END)
    return "\n".join(lines) + "\n"


def embed(text, block):
    """Replace the marked block in place, else insert it before the first section."""
    lines = text.splitlines()
    start = next((index for index, line in enumerate(lines) if line.startswith(BEGIN)), None)
    if start is not None:
        end = next((index for index, line in enumerate(lines[start:], start) if line.startswith(END)), None)
        if end is None:
            raise ValueError("README diagram block has a begin marker but no end marker")
        lines[start:end + 1] = block.rstrip("\n").splitlines()
    else:
        section = next((index for index, line in enumerate(lines) if line.startswith("## ")), len(lines))
        lines[section:section] = block.rstrip("\n").splitlines() + [""]
    return "\n".join(lines).rstrip("\n") + "\n"


def expected(directory, data):
    """Return every generated file, including the README, mapped to exact content."""
    directory = Path(directory)
    artifacts = render(data)
    readme = directory / README
    current = readme.read_text(encoding="utf-8") if readme.is_file() else ""
    artifacts[README] = embed(current, readme_block(data))
    return artifacts


def write_all(directory, data):
    """Write generated artifacts; return the paths that actually changed."""
    directory = Path(directory)
    changed = []
    for relative, content in expected(directory, data).items():
        path = directory / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.is_file() or path.read_text(encoding="utf-8") != content:
            path.write_text(content, encoding="utf-8")
            changed.append(relative)
    return changed


def drift(directory, data):
    """Return human-readable drift problems without writing anything."""
    directory = Path(directory)
    problems = []
    for relative, content in expected(directory, data).items():
        path = directory / relative
        if not path.is_file():
            problems.append(f"{relative} is missing")
        elif path.read_text(encoding="utf-8") != content:
            problems.append(f"{relative} is out of date")
    return problems


def check(directory, data):
    """Validate a diagram and its generated artifacts; raise ValueError on drift."""
    validate(directory, data)
    problems = drift(directory, data)
    if problems:
        raise ValueError("; ".join(problems) + "; run: python3 -m runner diagram <id>")
