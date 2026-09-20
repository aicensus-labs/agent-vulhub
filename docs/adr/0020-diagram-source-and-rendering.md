# Render Mechanism Diagrams from a Structured Single Source

为每个复现环境提供说明漏洞机制、触发过程和全部相关主体的图。图采用 Mermaid，由环境内 `diagram.toml` 单一来源渲染，并纳入 `runner check` 的静态校验；图解是说明性文档，不参与输入指纹，也不能替代实验证据。

**Status**: accepted; tooling and template implemented, per-environment coverage in progress

## Decision

### Use Mermaid as the only diagram format

图必须是纯文本、无二进制产物、AI 可编辑，并且能在 GitHub、GitLab、VS Code 中直接渲染，因此选择 Mermaid 代码块而不是 D2、Graphviz 或位图。

两种图对应两类要求：

- `sequenceDiagram` 表达**触发过程**：按阶段和编号展示每个主体之间的消息顺序；
- `flowchart` 表达**主体与信任边界**：把每个主体放进它所属的信任边界，并用带编号的边复述触发链。

渲染产物固定为 `diagram/mechanism.mmd`、`diagram/entities.mmd` 和 `README.zh-cn.md` 中的图解区块，三者都由同一份来源生成。

### Make `diagram.toml` the single source of truth

环境作者和 AI 只编辑 `environments/<product>/<CVE-ID>/diagram.toml`，不手写 Mermaid。手写 Mermaid 无法保证"每个主体都被说明"或"触发步骤引用真实输入"，而结构化来源可以静态校验：

- 主体是显式列表，每个主体必须写 `role`；没有出现在任何步骤里的主体必须显式声明 `static = true`，因此不会出现没有解释的孤立节点；
- 步骤必须引用已声明的主体 id，编号必须是 `1..N` 连续升序，因此触发链不会断裂或跳号；
- 至少一个步骤必须标记 `diverges = true` 且 `variant` 不能是 `both`，强制把"修复在哪里阻断"画出来；
- 引用 `fixtures/...` 的 `evidence`/`source` 必须真实存在且被 `fixtures/manifest.toml` 覆盖，因此图不能引用不存在的攻击输入；
- 一个主体最多属于一个信任边界，避免同一节点被画进两个子图。

### Describe only the vulnerability, not the reproduction harness

图说明的是漏洞本身：攻击者可控输入、受影响的上游组件、被调用的工具、被读写的存储、受控效果落点。复现工具链——运行器、`verify.py`、结果卷、容器与网络编排、协议替身、fixture 装载、观测文件、正常任务对照——不是漏洞的触发过程，也不是漏洞的主体，不得出现在图里。

这条规则不靠文档约定，而是落在 schema 上：主体类型只有 `actor | client | service | tool | store | sink`，阶段只有 `setup | trigger | effect`。`verifier`、`runtime` 类型和 `verify` 阶段被刻意删除，因此工具链角色在结构上写不进来。

替身与无害效果仍然保留在图中，因为它们扮演的是漏洞链上的真实角色（被拼接调用的 CLI、被读取的凭据、攻击者控制的接收端、越界读到的 marker），并用 `synthetic = true` 标 ⚠，避免被误读为真实外部目标。验证器与隔离方式继续写在 README 正文和 `metadata.toml` 里，只是不进入这张图。

校验并入 `python3 -m runner check`，纯静态、不调用 Docker、不执行任何 PoC。生成物与来源不一致时 `check` 失败，并提示运行 `python3 -m runner diagram <id>`。

### Keep diagrams out of the input fingerprint

图解属于说明性文档，与 README 正文同级，不参与 `protocol.fingerprint`：修改图不会使既有 `ready` 证据失效。这与仓库既有规则一致——输入指纹只覆盖材料性 metadata、执行文件、fixture、runner Python 文件和执行协议。

反向约束同样成立：图解不能作为证据。图中出现的每个效果都必须能在 `fixtures/` 或 `results/` 中找到对应事实，`diverges` 步骤描述的漏洞版/修复版差异必须与 `verify.py` 的实际检查一致。图解不能把机制复现表述为真实模型端到端复现。

### Roll out behind an optional file

首版把 `diagram.toml` 作为可选增强：`check` 严格校验已存在的文件，但不要求所有环境都有；`runner diagram --missing` 列出尚未覆盖的环境。全量覆盖后，把 `diagram.toml` 加入 `runner/cli.py` 的 `REQUIRED_FILES` 即可切换为强制要求。

## Non-goals

- 不引入 D2、Graphviz、PlantUML 或 Mermaid CLI 等额外渲染依赖；Mermaid 由查看方（GitHub、VS Code）渲染。
- 不从 `reproduce.py` 自动反推图解。触发步骤的语义必须由维护者或 AI 阅读真实代码后编写。
- 不用图解替代 `docs/environment-contract.md` 规定的三场景验收、独立验证器或证据哈希。
- 不把图渲染成 PNG/SVG 并纳入仓库；需要位图时由使用方在本地按 `.mmd` 生成。

格式与字段细节见 [漏洞图解契约](../diagram-contract.md)。
