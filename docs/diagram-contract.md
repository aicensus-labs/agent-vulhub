# 漏洞图解契约 v1

每个复现环境用一张图说明**漏洞机制**和**触发过程**，并逐条说明**漏洞涉及到的每个主体**。图由环境内的 `diagram.toml` 单一来源渲染，环境作者和 AI 只编辑这份结构化文件，不手写 Mermaid。

图**只描述漏洞本身**：攻击者可控的输入、受影响的上游组件、被调用的工具或子进程、被读写的存储，以及漏洞产生的受控效果。复现工具链——运行器、`verify.py`、结果卷、容器与网络编排、协议替身、fixture 装载、观测文件——不属于漏洞的触发过程，也不属于漏洞的主体，不得出现在图里。

这条规则在 schema 层面落地：主体类型没有 `verifier` 或 `runtime`，阶段没有 `verify`，所以工具链角色在结构上就写不进来。README 正文和 `metadata.toml` 仍然照常说明验证器与隔离方式，只是不进入这张图。

- 单一来源：`environments/<product>/<CVE-ID>/diagram.toml`
- 渲染产物：`diagram/mechanism.mmd`（触发时序图）、`diagram/entities.mmd`（主体与信任边界图）、`README.zh-cn.md` 中的图解区块
- 渲染与校验：`python3 -m runner diagram <product>/<CVE-ID>`，静态校验并入 `python3 -m runner check`

选择 Mermaid 是因为它在 GitHub、GitLab、VS Code 中原生渲染，纯文本、无二进制产物，并且 `sequenceDiagram` 正好表达“触发过程”、`flowchart` 正好表达“主体与信任边界”。

图解是说明性文档，不参与输入指纹：修改图不会使既有 `ready` 证据失效，正如图解不能替代实验证据。图里出现的每个效果都必须能在 `fixtures/` 或 `results/` 中找到对应事实。

## 为什么用结构化来源而不是手写 Mermaid

手写 Mermaid 无法保证“每个主体都被说明”和“触发步骤引用真实输入”。`diagram.toml` 把机制拆成可校验的字段：

- 主体是显式列表，每个主体必须写 `role`，未参与任何步骤的主体必须显式声明 `static = true`，因此不会出现只出现在图里、没有解释的孤立节点；
- 步骤必须引用已声明的主体 id，编号必须连续，因此触发链不会断裂或跳号；
- 至少一个步骤必须标记为漏洞版/修复版的分歧点，强制把“修复在哪里阻断”画出来；
- 引用 `fixtures/...` 的 `evidence`/`source` 必须真实存在且被 `fixtures/manifest.toml` 覆盖，因此图不能引用不存在的攻击输入；
- 主体类型和阶段只覆盖漏洞自身的角色，复现工具链在 schema 里没有对应取值，因此不会被写进触发过程。

## 文件结构

```toml
schema_version = 1
title = "MCP Filesystem 符号链接越界读取"
summary = "用 2~4 句说明漏洞根因、被绕过的信任边界，以及漏洞本身产生的效果。"

[[entities]]
id = "attacker"                       # ^[a-z][a-z0-9_]*$，全局唯一
label = "攻击者 / 攻击材料"            # 图中显示名
kind = "actor"                        # actor | client | service | tool | store | sink
trust = "attacker_controlled"         # trusted | semi_trusted | untrusted_input | attacker_controlled | out_of_scope
role = "构造带符号链接的 read_file 路径参数。"   # 必填：这个主体在漏洞里起什么作用
source = "fixtures/attack.json"       # 可选：上游文件、模块或固定输入
static = false                        # 可选：true 表示是漏洞前提但不参与任何消息步骤
synthetic = false                     # 可选：true 表示本仓库合成的替身或无害效果载体

[[boundaries]]
id = "lab"                            # ^[a-z][a-z0-9_]*$，不得与主体 id 重名
label = "受影响的组件和它信任的数据"
members = ["agent", "server"]         # 必须引用已声明主体
note = "该边界原本隔离允许目录内外，漏洞让它失效。"

[[steps]]
n = 1                                 # 必填：必须为 1..N 连续且升序
phase = "setup"                       # setup | trigger | effect
from = "attacker"                     # 必须引用已声明主体
to = "agent"
action = "提供固定攻击输入"            # 必填：作为箭头标签的一句话
detail = "可选补充说明。"
variant = "both"                      # both | vulnerable_only | patched_only
diverges = false                      # 可选：true 表示漏洞版/修复版在此分叉
evidence = "fixtures/attack.json"     # 可选：证据引用
```

## 字段语义

| 字段 | 含义 |
| --- | --- |
| `kind` | `actor` 人类/攻击者，`client` 调用方，`service` 受影响上游组件，`tool` 被调用的工具或子进程，`store` 被读写的文件/数据库/凭据，`sink` 受控效果落点 |
| `trust` | `trusted` 可信代码，或漏洞要越过的边界内侧的受保护数据；`semi_trusted` 有部分信任，但会把不可信内容带进受信流程（如转发攻击者参数的 Agent 调用方、允许目录里指向外部的符号链接）；`untrusted_input` 没验证过的外部输入；`attacker_controlled` 攻击者完全可控（攻击输入、攻击者自己的接收端）；`out_of_scope` 明确不在本实验范围内 |
| `phase` | `setup` 建立前提，`trigger` 越过边界，`effect` 产生受控效果 |
| `variant` | `both` 两版都会发生，`vulnerable_only` 仅漏洞版，`patched_only` 仅修复版（如拒绝响应） |
| `diverges` | 分歧点必须是 `vulnerable_only` 或 `patched_only`；每份图解至少有一个 |
| `synthetic` | 合成的替身或无害效果载体在图中标 `⚠`，避免把受控 marker 误读为真实外部目标 |
| `static` | 该主体是漏洞前提（如被读取的配置），但不参与任何消息步骤 |
| `evidence` | `fixtures/...` 前缀会被校验存在且被 fixture manifest 覆盖；其他值（如 `observation.json:response_text`）作为运行时事实引用原样保留 |

## 站在攻击者的角度写

触发过程和信任边界要能回答攻击者自己的问题，否则读者会看出逻辑矛盾。写之前先过一遍这四条：

1. **攻击者想要的东西，必须是它自己拿不到的。** 如果图里越界读到的文件、泄露的凭据被标成 `attacker_controlled`，逻辑就崩了——它何必绕这一圈？这类目标应标 `trusted`，并放进一个"边界内侧/攻击者本来够不着"的边界。
2. **分清"攻击者做了什么"和"环境本来是什么样"。** 符号链接、目录外的目标文件、被读取的配置通常来自 `metadata.toml` 的 `prerequisites`，是**前提条件**，不是攻击者的动作。别把它们写成"攻击者在允许目录里建了一条符号链接"，要写成"允许目录里本来就有这样一条符号链接"。
3. **攻击者能控制的通常只有这次调用的参数。** 机制复现里尤其如此：攻击面是一个固定的工具调用，不是攻击者对宿主机的写权限。把攻击者写成能随意操作目标系统的文件，会高估复现证明的东西。
4. **效果要落到攻击者手里。** 数据是从哪里流到哪里？`outside_file -> read_file_tool` 表示文件内容被读出；`kubectl_cli -> attacker_api` 表示凭据送到攻击者的接收端。方向错了，读者就看不出攻击者图什么。

只有攻击者**自己控制**的接收端、自己构造的输入才标 `attacker_controlled`；攻击者想要但够不着的数据标 `trusted`。

## 只解释漏洞本身，不写复现脚手架

图解里的文字——`summary`、主体 `label`、步骤 `action`、边界 `label`——**只描述漏洞本身**：攻击者可控的输入、受影响的上游组件、被读写的存储和最终效果。本仓库用来复现它的东西一律不进去：

- `runner`、`verify.py`、结果卷、容器与网络编排、fixture 装载、观测文件、正常任务对照；
- 「本仓库用 X 代替 Y」这类替身说明；
- 「本实验没有执行 handler」这类局限声明。

这些内容不是没价值，而是**放错了位置**。替身与来源写进 `source`/`evidence`，局限与端到端状态写进环境自己的 `## 前提`、`## 机制复现`、`## 端到端复现`、`## 输入与隔离` 小节。图解区块只回答一个问题：这个漏洞是怎么发生的。

| 位置 | ✗ 混入脚手架 | ✓ 只讲漏洞 |
| --- | --- | --- |
| 主体 `label` | `kubectl 子进程（本地假 CLI）` | `kubectl 子进程` |
| 主体 `label` | `synthetic kubeconfig 凭据存储` | `kubeconfig 凭据存储` |
| 主体 `label` | `受控 API 接收器` | `攻击者指定的 API 地址` |
| 步骤 `action` | `…进入本地专用命令的函数体（本实验没有执行 handler）` | `…进入本地专用命令的函数体` |
| 步骤 `action` | `kubectl 把合成的 PodList 返回给调用方` | `kubectl 把响应返回给调用方` |

`role`、`detail`、`note` 是给读者补背景的散文，可以说明复现方式；但只要能讲清漏洞本身，就不该把笔墨花在脚手架上。校验器会拦截图解可见字段里的装置词，见「校验规则」第 11 条。

## 渲染约定

主体与信任边界图里**主体节点和信任边界子图都用透明填充**，只保留描边颜色：

- 主体节点按 `kind` 取描边色（`actor` 品红、`client` 蓝、`service` 紫、`tool` 橙、`sink` 红、`store` 绿），`synthetic = true` 额外加虚线边框；
- 信任边界子图用 `style <boundary> fill:transparent` 去掉 Mermaid 默认的浅色底；
- 漏洞版/修复版的分歧边用红色加粗，修复版阻断边用绿色加粗。

这样图在 GitHub 浅色/深色主题、幻灯片和透明背景导出里都能直接看，不需要为每种背景重新配色。

**边标签保留 Mermaid 默认的淡色底**，这是有意的：连线上的文字标签正好压在连线上（实测 10 条边里 8 条标签中心距连线 ≤1px），底色是用来遮住穿过文字的连线的。去掉它会让连线从文字中间横穿，可读性反而变差。因此"透明"只适用于方框，不适用于边标签。

**主体与信任边界图的边上只写步骤编号，不写动作文字。** Mermaid 把每条边的标签放在边的中点，并且不做任何标签避让，所以只要一个主体有多条出边、或者两个主体互相通信，整句话的标签就会叠在一起。实测三种写法：

| 边标签 | 8 主体样例 | 6 主体样例 | 7 主体样例 |
| --- | --- | --- | --- |
| 完整动作文字 | 重叠 167×38px | 重叠 155×66px | 无 |
| 数字 + 几个字 | 重叠 106×13px | 无 | 无 |
| 仅步骤编号 | 无 | 无 | 无 |

`flowchart TB` 或加大 `nodeSpacing`/`rankSpacing` 都只能碰巧躲开某一张图（实测 TB 修好了第一张、第二张照旧重叠，间距加倍后画布涨到 2560px 仍然重叠）。因此动作文字统一放在时序图里，两张图共用同一套编号，README 的图解区块会把两段并排放。

**边的颜色表示分歧的两侧**：漏洞版那侧加粗红色，修复版阻断那侧加粗绿色。一个分歧点通常由两步组成（`vulnerable_only` 与 `patched_only`），两步都标 `diverges = true`，因此配色判定必须先看 `variant`，否则修复版的阻断边会被涂成和漏洞版一样的红色。

填充一律为 `fill:transparent`，实现上有一处 Mermaid 陷阱：`class X a,b` 里的逗号分隔的是**节点 id** 而不是 class 名，写成逗号列表会让两个样式都静默失效，因此每个 class 必须单独一条 `class` 语句。

## 校验规则

`python3 -m runner check` 对每个存在 `diagram.toml` 的环境执行以下静态检查：

1. `schema_version = 1`，`title` 与 `summary` 非空；
2. 至少一个主体和一个步骤；
3. 主体 `id` 唯一且匹配 `^[a-z][a-z0-9_]*$`，`label`/`kind`/`trust`/`role` 非空，`kind` 在 `actor|client|service|tool|store|sink` 内，`trust` 在枚举内；
4. 步骤 `n` 恰好是 `1..N` 连续无重复的升序序列，`phase` 在 `setup|trigger|effect` 内，`variant` 在枚举内，`action` 非空；
5. 每个步骤的 `from`/`to` 引用已声明主体；
6. 至少一个步骤 `diverges = true`，且该步骤 `variant != "both"`；
7. 每个主体至少被一个步骤引用，或显式 `static = true`；
8. 边界 `id` 唯一且与主体 id 不重名，`members` 非空并引用已声明主体，`label`/`note` 非空，且一个主体最多属于一个边界；
9. 引用 `fixtures/` 的 `evidence`/`source` 必须存在，且被 `fixtures/manifest.toml` 覆盖；
10. `diagram/mechanism.mmd`、`diagram/entities.mmd` 和 `README.zh-cn.md` 图解区块与 `diagram.toml` 一致；不一致时提示运行 `python3 -m runner diagram <id>`；
11. `summary`、主体 `label`、边界 `label` 和步骤 `action` 里不得出现复现装置词（`本仓库`、`本实验`、`本环境`、`fixture`、`synthetic`、`替身`、`本地假`、`verify.py`、`observation.json` 等），词表见 `runner/diagram.py` 的 `APPARATUS`。`role`/`detail`/`note` 和 `source`/`evidence` 不在此列。

## 工作流

```sh
# 编辑 diagram.toml 后重新渲染，并更新 README 图解区块
python3 -m runner diagram mcp-filesystem/CVE-2025-53109

# 只检查漂移，不写入
python3 -m runner diagram mcp-filesystem/CVE-2025-53109 --check

# 渲染所有已有 diagram.toml 的环境 / 列出还没有图解的环境
python3 -m runner diagram --all
python3 -m runner diagram --missing

# 审计：漂移会让命令失败；尚未补图的环境只打印 MISSING，不算失败
python3 -m runner diagram --all --check

# 静态校验全部环境（含图解）
python3 -m runner check
```

`runner new` 生成的草稿自带可渲染的 `diagram.toml` 骨架，并立即写入图解区块。

## 可选：用真实解析器验证渲染

`runner check` 只做结构化校验，不解析 Mermaid 语法。需要确认图真的能被渲染时，可以在仓库外做一次性验证，不把 Node 依赖引入本仓库：

```sh
mkdir -p /tmp/mermaid-check && cd /tmp/mermaid-check && npm init -y
npm install mermaid@11 jsdom
```

用 jsdom 提供 DOM 后调用 `mermaid.parse()` 逐个解析 `diagram/*.mmd`。已生成的图在这条路径上全部通过；解析器也会正确拒绝非法语法（例如把 `end` 当作节点 id）。节点和边界 id 因此禁止使用 Mermaid 关键字，见校验规则第 3、8 条。

## 覆盖状态

图解目前是可选增强：`check` 严格校验已存在的 `diagram.toml`，但不要求所有环境都有。全量覆盖完成后，把 `diagram.toml` 加入 `runner/cli.py` 的 `REQUIRED_FILES` 即可切换为强制要求。
