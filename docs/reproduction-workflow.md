# 漏洞复现与图解工作流

面向接手这个仓库的人：从一个 CVE 编号开始，到一个「可复现的环境 + 两张说明图」为止。

这份文档讲**按什么顺序做**、**每一步的验收标准**，以及**哪里容易踩坑**。字段和枚举的权威定义在[环境执行协议](environment-contract.md)和[漏洞图解契约](diagram-contract.md)，本文不重复。

---

## 0. 先建立心智模型

仓库里有三个**互相独立**的东西，它们回答不同的问题，证据等级也不同：

| 层 | 回答什么 | 产出 | 是不是证据 |
| --- | --- | --- | --- |
| **机制复现** | 漏洞机制成不成立、修复有没有真的挡住 | `reproduce.py` + `verify.py` → `results/.../report.json` | ✅ 是 |
| **端到端复现** | 真实模型会不会被诱导 | 可选，另行统计 | ✅ 是（独立记录） |
| **图解** | 这个漏洞**是怎么发生的** | `diagram.toml` → 两张 Mermaid 图 | ❌ 不是，只是说明 |

三条铁律：

1. **机制复现通过 ≠ 真实模型被诱导。** 机制层允许用固定模型输出，但必须走真实漏洞代码路径。没有真实模型参与，就不能标 `end_to_end`。
2. **图解不能替代证据。** 图里每个效果都必须能在 `fixtures/` 或 `results/` 找到对应事实，`diverges` 步骤必须和 `verify.py` 的实际检查一致。
3. **图解不参与输入指纹。** 改图不会让既有 `ready` 证据失效——这是有意的，因为图是说明文档。反过来说，改 `metadata.toml`、`reproduce.py`、`verify.py`、fixtures 会让 `check` 拒绝旧 `ready`。

---

## 1. 选型与核实

先判断**这个漏洞值不值得做成环境**，别急着建目录。

- 核对官方 CVE/GHSA 公告、受影响版本、修复 commit。**不要照搬数据库的自动标签**——`agent_unique` 只用于候选召回，实际收录要自己复核信任边界和官方证据。
- 确认它确实是 **Agent 相关**：攻击面在 Agent 的工具调用、上下文、协议或权限边界上，而不是一个恰好被 Agent 用到的普通 Web 漏洞。
- 确认能拿到**固定源码**：漏洞版和修复版都要有明确的 commit 和可下载的归档。

候选池见[候选 CVE 选型](cve-candidates.md)。

---

## 2. 建草稿

```sh
python3 -m runner new <product> <CVE-or-GHSA-ID>
```

产品目录用小写字母、数字和连字符；CVE 用大写规范编号。这会从 `templates/environment/` 复制一套骨架并登记到 `environments.toml`。

骨架里的 `TODO` 占位字符串**必须全部替换**——`check` 不会替你判断内容对不对，但留着 TODO 就是没做完。

---

## 3. 固定源码与依赖

编辑 `metadata.toml`：

- `[vulnerable]` / `[patched]`：完整 commit、版本、`source_url`、`archive` 名称。
- `[build].base_image`：固定 digest（`name@sha256:...`）。
- `[build].inputs`：每项 `{ name, url, sha256 }`。**源码归档和每一个依赖都要列**，因为构建是 `--network none` 的离线安装。

然后把归档放进 `inputs/`，并在 `fixtures/manifest.toml` 里固定攻击/正常输入的 SHA-256。

Dockerfile 必须用 `ARG BASE_IMAGE` / `FROM ${BASE_IMAGE}`，接收 `VARIANT`、`SOURCE_COMMIT`、`SOURCE_ARCHIVE`；拒绝 `ADD` 和匿名 `VOLUME`。

> **约束**：完整安装上游版本，可以直接调用内部函数，**不能抽取或重写漏洞函数代替产品**。替身不能替换被验证的漏洞代码。

---

## 4. 写 PoC 与验证器

两个脚本都接受 `--context /lab/results/context.json --output /lab/results`。

**`reproduce.py`（PoC）**：运行真实产品代码，输出 `facts.json` 和实际效果文件。
**`verify.py`（验证器）**：**只读**事实和效果，**不能重跑攻击**，输出 `verdict.json`。

职责分离是硬要求：验证器独立读证据，PoC 不得直接制造 canary 冒充产品效果。

退出码约定：

| 码 | 含义 |
| --- | --- |
| 0 | 执行完成（**预期的修复拒绝也算完成**） |
| 1 | 执行失败 |
| 2 | 未实现 / 缺前提 |

`verify.py` 的 checks 至少包含 `target_ready` 和对应的 `vulnerable_effect_observed` / `patched_effect_blocked` / `benign_task_passed`，每项要有唯一 `id`、布尔 `passed`、`reason`、`expected`、`actual`、非空 `evidence` 列表。

---

## 5. 验收

```sh
python3 -m runner reproduce <product>/<CVE-ID> --build --rounds 3
```

`--build` 从固定源码构建两版镜像，然后跑**四个独立测试**：漏洞版攻击、修复版攻击，以及两版各自的正常任务。每个测试用全新容器和数据。

- 默认 1 轮；**晋升 `ready` 至少 3 轮**。
- `--scenario vulnerable|patched|benign` 只用于局部调试，**局部通过不满足晋升**。
- 已有 GHCR 镜像的环境省略 `--build`，按元数据 digest 拉取。
- `--offline` 要求所有输入和镜像已缓存。

**读失败原因和日志，不要隐藏失败后重试。** 常见情况的解释见协议里的失败分类表——特别注意：

- 漏洞版缺少 canary ≠ 漏洞不存在，可能是前提没搭对；
- 修复版仍有 canary = 修复对照失败；
- 正常任务失败 = 无法排除服务整体不可用，整轮不通过；
- 超时、启动失败**都不能算修复阻断**。

---

## 6. 写图解（最容易做砸的一步）

编辑 `diagram.toml`，然后渲染：

```sh
python3 -m runner diagram <product>/<CVE-ID>   # 渲染并更新 README 图解区块
python3 -m runner diagram <product>/<CVE-ID> --check   # 只报告漂移，不写入
python3 -m runner diagram --all                # 渲染所有已有图解的环境
python3 -m runner diagram --missing            # 列出还没补图的环境
```

> **只编辑 `diagram.toml`。** `diagram/mechanism.mmd`、`diagram/entities.mmd` 和 README 里的图解区块都是生成物，手写会被下次渲染覆盖。手写 Mermaid 不作为来源（见 [ADR-0020](adr/0020-diagram-source-and-rendering.md)）。

### 6.1 图里放什么

一句话：**只解释漏洞本身**。

图回答两个问题，分别对应两张图：

- `sequenceDiagram` = **触发过程**：攻击者可控输入怎么一步步走到效果。
- `flowchart` = **主体与信任边界**：涉及哪些主体、各自在边界哪一侧、信任级别是什么。

**不要放**复现工具链：运行器、`verify.py`、结果卷、容器与网络编排、协议替身、fixture 装载、观测文件、正常任务对照。schema 里也没有对应取值，结构上写不进去。

**不要放**脚手架话术：`本仓库用 X 代替 Y`、`本实验没有执行 handler`、`（本地假 CLI）`、`synthetic ...`。替身和来源写进 `source`/`evidence` 字段；局限和端到端状态写进环境自己的 `## 前提`、`## 机制复现`、`## 端到端复现`、`## 输入与隔离` 小节。

`runner check` 会拦截图解可见字段（`summary`、主体 `label`、边界 `label`、步骤 `action`）里的装置词。`role`/`detail`/`note` 和 `source`/`evidence` 豁免。

### 6.2 站在攻击者的角度写

写之前过一遍这四条，否则读者会看出逻辑矛盾：

1. **攻击者想要的东西，必须是它自己拿不到的。** 如果图里越界读到的文件、泄露的凭据被标成 `attacker_controlled`，逻辑就崩了——它何必绕这一圈？这类目标标 `trusted`，放进「边界内侧/攻击者本来够不着」的边界。
2. **分清「攻击者做了什么」和「环境本来是什么样」。** 符号链接、目录外的目标文件、被读取的配置通常是**前提条件**，不是攻击者的动作。写「允许目录里本来就有这样一条符号链接」，不要写「攻击者在允许目录里建了一条符号链接」。
3. **攻击者能控制的通常只有这次调用的参数。** 把攻击者写成能随意操作目标系统的文件，会高估复现证明的东西。
4. **效果要落到攻击者手里。** 数据从哪流到哪？方向错了，读者就看不出攻击者图什么。

### 6.3 主体与步骤

- 漏洞涉及的**每个**主体都要在 `[[entities]]` 出现，并且必须有 `role` 说明职责。
- `kind` 只有 `actor|client|service|tool|store|sink`；`trust` 只有 `trusted|semi_trusted|untrusted_input|attacker_controlled|out_of_scope`。
- 每个主体要么被某个步骤引用，要么显式 `static = true`（不参与触发步骤的漏洞前提）。
- 步骤 `n` 必须 `1..N` 连续，且**按真实 `reproduce.py` 路径编号**。
- **至少一步 `diverges = true`** 标出漏洞版/修复版的分叉点，且该步 `variant` 不能是 `both`。一个分歧点通常由两步组成：`vulnerable_only` + `patched_only`，**两步都设 `diverges = true`**。
- 引用 `fixtures/...` 的 `evidence`/`source` 必须真实存在且被 `fixtures/manifest.toml` 覆盖。

### 6.4 两个 Mermaid 陷阱（已踩过）

**边上只写步骤编号，不写动作文字。** Mermaid 把每条边的标签放在边中点，并且**不做任何标签避让**。实测三种写法：

| 边标签 | 8 主体样例 | 6 主体样例 |
| --- | --- | --- |
| 完整动作文字 | 重叠 167×38px | 重叠 155×66px |
| 数字 + 几个字 | 重叠 106×13px | 无 |
| **仅步骤编号** | **无** | **无** |

`flowchart TB` 或加大 `nodeSpacing`/`rankSpacing` 都只能碰巧躲开某一张图。动作文字统一放在时序图里，两张图共用同一套编号。

**`class X a,b` 里的逗号分隔的是节点 id，不是 class 名。** 写成逗号列表会让两个样式**静默失效**（不报错，只是没生效）。每个 class 必须单独一条 `class` 语句。

---

## 7. 提交前门禁

```sh
python3 -m runner check                                  # 纯静态，不调用 Docker
python3 -m runner lint                                   # Compose CLI 解析，不拉取不构建
python3 -m runner diagram --all --check                  # 生成物无漂移
python3 -m unittest discover -s tests -v                 # 工具测试
git diff --check                                         # 空白符
```

`check` 是纯文件静态校验，**不审计脚本行为、不验证公告真实性、也不证明 Docker 隔离有效**。

提交时 **stage 明确路径**，不要把无关的未跟踪文件（如候选清单草稿）一起带进去。

---

## 8. 发布与晋升

```sh
python3 -m runner publish <product>/<CVE-ID> --images <build.json> --repository ghcr.io/<owner>/<package>
python3 -m runner promote <product>/<CVE-ID> --report <report.json> --reviewer <login> --reviewed
```

- `publish` 把输出 digest 写回元数据；**再用这些正式镜像完成验收**。
- `promote` 要求：来源完整、可分发镜像 digest、Linux amd64 原生环境、**同组固定镜像至少 3 轮完整验收且清理成功**。
- `--reviewer`/`--reviewed` 是本地审阅声明，**身份授权依赖 Git 分支保护，不是密码学签名**。涉及隔离例外要两位不同审阅者。
- 先人工审阅来源、安全效果和脱敏，再晋升。

`draft` 表示未完成（缺上游修复也可以留在 draft）；`ready` 只适用于记录的平台。执行材料变化会使旧证据失效。

---

## 9. 踩坑速查

这些是实际踩过的，症状和原因都写清楚，方便你一眼认出来。

| 症状 | 原因 | 处理 |
| --- | --- | --- |
| 改了图但渲染没变 | 直接编辑了 `.mmd` 生成物 | 只改 `diagram.toml`，再跑 `runner diagram` |
| 图里样式没生效，也不报错 | `class X a,b` 逗号列表 | 每个 class 单独一条语句 |
| 边上的文字叠在一起 | Mermaid 标签永远放中点且不避让 | 边上只写步骤编号 |
| 修复版的阻断边被涂成红色 | 配色判定先看了 `diverges` 而没先看 `variant` | 先判 `patched_only` |
| `check` 报装置词 | 图里写了复现脚手架 | 移到 `role`/`detail`/`note` 或环境小节 |
| `--all --check` 报一堆 `MISSING` | 那些环境本来就还没补图 | 非致命；`DRIFT` 才是问题 |
| 生成 Mermaid 用了 3.12 才支持的嵌套引号 f-string | Python 3.11 兼容性 | 拆成临时变量用 `%` 格式化 |

### 通用方法

**先量再改。** 「边上的文字叠在一起」这一条如果靠猜，很容易去调字号或换布局，而真正的原因是 Mermaid 把标签固定放在边中点、从不避让。用真实浏览器量一下每个 `g.edgeLabel` 的 `getBoundingClientRect()` 有没有相交，比挨个试写法快得多——我试了 5 种布局变体，量过之后才确定「仅步骤编号」是唯一在全部 6 种 LR/TB 组合下都不重叠的写法。

**判断「是不是我改坏的」。** 测试挂了先别急着改代码，先建基线对比：用 `git archive HEAD | tar -x -C /tmp/base` 导出一份 HEAD，跑同一套测试。**但要注意工作区可能本来就有别人未提交的改动**——只有 HEAD 基线不够，还要构造一份「当前工作区减去我的改动」的基线。两次结果取交集，才是你真正引入的失败。

另外注意**复现条件要一致**：复用已经跑热的服务实例和重新起一个干净实例，结果可能不同（我遇到过同一棵树两次跑出不同的失败集合，换成同一种条件后就消失了）。

---

## 10. 一页速查

```sh
# 建环境
python3 -m runner new <product> <CVE-or-GHSA-ID>

# 验收（晋升 ready 至少 3 轮）
python3 -m runner reproduce <product>/<CVE-ID> --build --rounds 3

# 图解
python3 -m runner diagram <product>/<CVE-ID>
python3 -m runner diagram --missing
python3 -m runner diagram --all --check

# 门禁
python3 -m runner check && python3 -m runner lint && python3 -m unittest discover -s tests -v

# 发布与晋升
python3 -m runner publish <product>/<CVE-ID> --images <build.json> --repository ghcr.io/<owner>/<package>
python3 -m runner promote <product>/<CVE-ID> --report <report.json> --reviewer <login> --reviewed
```

| 文件 | 是什么 |
| --- | --- |
| `metadata.toml` | 版本、commit、构建输入、验证状态 |
| `reproduce.py` / `verify.py` | PoC / 独立验证器 |
| `fixtures/` | 固定输入 + `manifest.toml` 哈希 |
| `diagram.toml` | **图解单一来源，只编辑这个** |
| `diagram/*.mmd` | 生成物 |
| `README.zh-cn.md` | 含自动生成的图解区块 |

---

## 相关文档

- [环境执行协议](environment-contract.md) — 构建、入口、证据、晋升的权威定义
- [漏洞图解契约](diagram-contract.md) — 图解字段、枚举、渲染约定、校验规则
- [收录流程](../CONTRIBUTING.md) — 十步清单
- [术语](../CONTEXT.md)
- [ADR 索引](adr/) — 每个设计决定的原因，尤其 [0019](adr/0019-agent-generated-poc-evaluation.md)、[0020](adr/0020-diagram-source-and-rendering.md)
