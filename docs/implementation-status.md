# 首版实现与验证记录

## claude-code-action/CVE-2026-47751 配方实现（2026-09-24）

- 该环境原为 `not_run`，完成四场景三轮验收，**12/12 case 通过**（`results/claude-code-action/CVE-2026-47751/20260924T033418Z-0fcca1ebaaab/report.json`），状态转为 `passed`。**未通过环境从 2 个减为 1 个**。
- 原阻塞理由"漏洞归档缺少 restore 模块，缺失本身不等于执行了真实 Action checkout 路径"**事实为真，但推论不完整**，而不完整的那一半藏住了一个可用的复现。缺失是真的：`restore-config.ts` 由修复新增，两版里都没有别的代码读 `.mcp.json`——读它的是 **Claude Code CLI**，从工作目录读。
- 关键错误在旧 PoC 的结构：它**按文件是否存在分叉**。补丁版导入并执行 `restoreConfigFromBase()`；漏洞版因文件不存在直接返回 `not_run`。于是**两个变体从未跑同一条路径，漏洞对照根本没执行**。这与 `factoryfloor`、`vtcode` 的失效模式完全一样——把"我无法搭出对照"误当成"对照不存在"。
- 正确的读法：**漏洞的表现是文件系统状态，不是调用的返回值**。因此 lab 重建状态，并重建把状态变成效果的那一步。
- 实现：容器内建**真实 git 仓库 + bare `origin`**。`origin/main` 放审阅版 `.mcp.json`（server 写 `canary_base.txt`），PR head 覆盖成攻击者 `.mcp.json`（server 写 `canary_proof.txt`），harness 随后启动 CLI 会在工作目录找到的那些 server。漏洞版没有任何东西移除攻击者文件；补丁版调用上游真正发布的 `restoreConfigFromBase()`。
- 编译用**上游 TypeScript 工具链**针对**上游 `src/` 树**，所以补丁路径跑的是上游代码而非 lab 自造的恢复逻辑。`@types/node` 固定为上游 `bun.lock` 的 20.19.9。
- 实测四场景：

  | 场景 | restore 已发布 | 攻击配置存活 | 启动的 server | 攻击 canary | 审阅版 canary |
  |---|---|---|---|---|---|
  | 漏洞版 attack | False | **True** | `attacker` | **True** | False |
  | 补丁版 attack | True | **False** | `reviewed` | **False** | **True** |
  | 漏洞版 benign | False | False | `reviewed`, `helper` | False | True |
  | 补丁版 benign | True | False | `reviewed` | False | True |

- **阳性对照（必要）**：一个只把 `.mcp.json` 删掉的假修复同样能挡住攻击者。故补丁版 attack 额外要求审阅版配置**确实被还原并执行**（`canary_base.txt` 出现）。benign 场景 PR 只加一个无害 server，攻击 canary 始终不出现、审阅版 server 照常运行，避免把"任意破坏"算作修复。
- 构建中三个实际坑：`mkdir -p /lab/src` 后再 `cp -r /lab/app/src /lab/src` 会变成 `/lab/src/src`；`@types/node` 压缩包顶层是 `node v20.19/`（含空格），用 `--strip-components=1` 解包；`typeRoots` 相对 tsconfig 解析，需用绝对路径。
- 如实记录的范围限制：**没有运行 Claude Code CLI 本身**，本环境证明的是修复建立的配置边界，而非 CLI 侧 server 启动；不涉及模型与网络，端到端保持 `not_applicable`。

## vtcode/GHSA-WQGW-CRR5-CR2P 配方实现（2026-09-24）
## vtcode/GHSA-WQGW-CRR5-CR2P 配方实现（2026-09-24）

- 该环境原为 `not_run`，记录了**两条阻塞理由，两条都不成立**。补齐后完成四场景三轮验收，**12/12 case 通过**（`results/vtcode/GHSA-WQGW-CRR5-CR2P/20260924T031827Z-23125682a112/report.json`），状态转为 `passed`，未通过环境从 3 个减为 2 个。
- **阻塞 (1)「缺 Rust 工具链」**：原备注说"vendoring 一个工具链不划算：rustup 工具链解压 1.3–2.7 GB，而 `rust:*` 镜像不是可直接替换的基础镜像，因为它没有 `runtime.harness` 需要的 Python 3"。这个框架本身是错的——**工具链属于 `build.inputs`，不属于基础镜像**。换成官方固定的 `rust-1.93.0` 发布包（压缩 184 MB，与仓库 `rust-toolchain.toml` 的 `channel = "1.93.0"` 一致）后基础镜像不变，Python 3 保留；crates 早已 vendored 且 SHA-256 固定，构建仍全程 `--network none`。这与 `factoryfloor` 的 Swift 是同一手法。
- 构建中两个实际坑：`rust-version = "1.93.0"` 使 rustc 1.90.0 被直接拒绝（先用了镜像里的 1.90.0，报 `requires rustc 1.93.0`）；以及 Docker 默认 fd 上限导致 rustc 报 `Too many open files (os error 24)`，需要提高 `ulimit -n` 并限制 `CARGO_BUILD_JOBS`。
- **阻塞 (2)「没有稳定非交互入口，跑二进制不能证明调用了上游生命周期代码」**：**上游自己的修复就否证了这一点**。补丁新增了 `crates/codegen/vtcode-core/src/hooks/lifecycle/tests/workspace_hook_approval.rs`，直接用 `LifecycleHookEngine` 驱动，完全不经过 TUI。审批闸门在引擎层且是非交互 API：`workspace_gated()` / `workspace_hooks_need_approval()` / `run_session_start()` / `approve_workspace_hooks()`。本环境用上游同样的挂载方式（`mod workspace_hook_approval;`）加入自己的模块并调用真实引擎。
- harness 作为 **crate 内测试模块**运行，因为 `LifecycleHookEngine` 的构造器是 crate 内部可见；这也正是上游够到它的方式，**没有放宽任何上游可见性**。
- 实测四场景：

  | 场景 | gated | 需审批(前) | canary | 跳过原因 | 需审批(后) | 审批后 canary |
  |---|---|---|---|---|---|---|
  | 漏洞版 attack | False | False | **True** | — | — | True |
  | 补丁版 attack | **True** | **True** | **False** | **True** | **False** | **True** |
  | 漏洞版 benign | False | False | True | — | — | True |
  | 补丁版 benign | False | False | **True** | — | — | True |

- **benign 场景为何用 ungated 引擎**（一个容易搞错的地方）：补丁对*仓库来源*的 hook 一律要求审批，即使命令无害。这是有意的安全权衡，不是回归，所以"合法仓库命令被拦"不能当良性对照。真正要防的是**修复过宽**，故 benign 用 ungated（用户级）hook，要求它在两版都照常执行。
- 如实记录的范围限制：交互式 TUI 覆盖层（收集用户答复的那个界面）没有复现，本环境证明的是引擎层闸门；不涉及模型与网络，端到端保持 `not_applicable`。

## factoryfloor/CVE-2026-88063 配方实现（2026-09-24）

- 该环境原为 `not_run`，理由写的是"上游是 macOS Swift GUI，Linux 容器无法构建或运行，拒绝用 shell 替身"。补齐后完成四场景三轮验收，**12/12 case 通过**（`results/factoryfloor/CVE-2026-88063/20260924T021041Z-17c12492f806/report.json`），状态转为 `passed`，未通过环境从 4 个减为 3 个。
- **原来的阻塞理由对 GUI 层成立，对漏洞本身不成立。** 审批闸门不在 GUI 里：`ScriptConfig.runTeardown` 与补丁新增的 `ScriptTrust` 只依赖 Foundation。因此不需要 macOS，用固定的 Swift 5.9.2 Linux 工具链把该版本**真实的** `ScriptConfig.swift`、`CommandBuilder.swift`（补丁版另加 `ScriptTrust.swift`）编进来直接调用即可。这与 `flowise` 的 Pyodide 情形类似：外层跑不了，但安全边界本身是纯逻辑。
- 平台适配只有两处，其余字节与固定版本完全一致：`CryptoKit` 与 `os` 是 Apple 专有模块，Linux 上不存在，以 shim 源码提供；上游文件里只删除 `import os` 与 `import CryptoKit` 两行。工具链是 build input（562.7 MB），**不修改基础镜像**，构建仍全程 `--network none`。
- `CryptoKit` 的 SHA-256 是**完整实现**而非桩，因为审批指纹就建立在它之上——桩会让安全属性失去意义。镜像构建阶段强制用 FIPS 180-4 向量（空串 / `abc` / 一百万个 `a`）自检，不过就不出镜像。
- harness 与上游文件编到**同一模块**，目的是调用 `internal` 的 `ScriptConfig` 而不放宽上游访问级别（上游自己也是用 `@testable import` 做同样的事）。
- **阳性对照是必要的。** 只证明"未审批的脚本没跑"是不够的：一个把 teardown 整个禁掉的假修复会得到完全一样的结果。因此补丁版 attack 场景额外要求：用上游 `ScriptTrust.approve()` 走一遍审批后，同一命令**必须确实执行**。补丁版必须同时满足"未审批不执行"与"审批后执行"。实测四场景：

  | 场景 | 未审批 canary | 审批后 isApproved | 审批后 canary |
  |---|---|---|---|
  | 漏洞版 attack | **True** | False（无审批概念） | True |
  | 补丁版 attack | **False**（阻断） | **True** | **True** |
  | 漏洞版 benign | False | False | True |
  | 补丁版 benign | False | True | True |

- 如实记录的范围限制：advisory 描述的 GUI workstream 触发**没有**被复现，本环境证明的是脚本配置路径上的审批闸门；不涉及模型与网络，端到端保持 `not_applicable`。
- 顺带修正 README 两处过时内容：状态行仍写"尚未复现"，以及基础镜像写成了 `codex-universal@…`（实际是 `buildpack-deps@…`）。

## flowise/CVE-2026-70477 配方实现（2026-09-24）

- 该环境原为 `exit 2` 的空模板。补齐后完成四场景三轮验收，**12/12 case 通过**（`results/flowise/CVE-2026-70477/20260924T014802Z-feca4c164f6e/report.json`），状态转为 `passed`，未通过环境从 5 个减为 4 个。
- **最重要的发现：原来固定的 commit 对是错的。** 它用 3.1.2 release 对 3.1.3 release，但 3.1.3 之前组件已被整体删除——校验器与 CSVAgent 都在 `f4e2794f`（2026-06-10，"Fix Flowise 606"）里被移除，而 3.1.3 发布于 6-25。因此补丁版**没有留下任何可被阻断的代码路径**，四场景门禁在原理上无法满足。这与 `mcp-gateway` 的"纯逻辑可直接调用"不同，是环境配置本身的问题，不是平台限制。
- 查 `pythonCodeValidator.ts` 的提交历史发现它被**六次独立修复**（2026-02-06 引入 → 03-05 → 04-27 → 05-05 → 06-05 → 06-10 删除）。正确对照应取"修复提交本身与其父提交"，最终选定 `3d69baed`（修复前）对 `c79fe56a`（2026-04-27，"Block read_pickle and class definitions"）。该提交做了三件事：把 `read_pickle`/`pickle`/`marshal` 加入黑名单、新增 `class` 规则、为用户自定义 read_csv 字段引入**白名单**校验器 `validateCustomReadCSVFunction`（在 `CSVAgent.ts` 第 147 行接上）。
- 上游**修了漏洞却没加回归测试**：两版 `pythonCodeValidator.test.ts` 都是 349 行且完全不含 `read_pickle`/`class` 用例，所以 harness 必须自己构造。
- 实现方式：用固定的 TypeScript 编译器（5.9.3）编译该版本**自包含、零 import** 的 `pythonCodeValidator.ts`，直接调用真实的 `validatePythonCodeForDataFrame`；校验通过后再执行代码，使效果可观测。校验器是漏洞本身的组件，不是抽取出来的替身。
- 该环境是**唯一 node 基础镜像却声明 `harness = "python3"`** 的环境（模板遗留），而 node 镜像没有 python3，运行直接 `exec: "python3": executable file not found`。改为 `harness = "node"` 并把两个脚本重写为 Node。
- 效果阶段需要 Python 执行 payload，但 node 镜像没有。尝试两条路都失败：`python:3.10-slim` 的运行时基于 Debian trixie（glibc 2.41），在 node 的 bookworm（glibc 2.36）上报 `GLIBC_2.38 not found`。改用 `python-build-standalone` 的固定版本（CPython 3.10.21，27.9 MB）作为 build input，实测在 node 镜像内可直接运行。
- 如实记录的范围限制（都写进了 metadata notes，没有含糊）：(a) 不调用真实模型，模型回合是固定 fixture，因此这是机制复现而非端到端；(b) 产品在 Pyodide 里执行，本环境用独立 CPython 执行，因为离线构建无法获取 Pyodide 与其 pandas/numpy wheel；垫片只提供 `DataFrame` 表面，`read_pickle` 委托给真实 stdlib `pickle`，反序列化本身是真的，且**垫片完全不影响校验器判定**（判定只看代码字符串）；(c) 上游修复是部分的——`df.__getattribute__("__cl"+"ass__")` 与 `df.to_csv(...)` 在补丁版仍然通过，本环境证明的是 `read_pickle` 这条规则，不是黑名单方法本身可靠。

## mcp-gateway/GHSA-g53w-w6mj-hrpp 配方实现（2026-09-24）

- 该环境原为 `exit 2` 的空模板且未声明 `build.inputs`。补齐后已完成四场景三轮验收，**12/12 case 通过**（`results/mcp-gateway/GHSA-g53w-w6mj-hrpp/20260924T013103Z-e879a4943629/report.json`），状态转为 `passed`，未通过环境从 6 个减为 5 个。
- 关键判断：**这段漏洞逻辑是纯 Go，不需要 Envoy、HTTP 服务或 Kubernetes 就能真实调用。** 漏洞在 `ExtProcServer.HandleNoneToolCall`：`initialize` 请求经 `RouteMCPRequest` 的 `default` 分支进入该函数，而 `validateSession()`（JWT 会话校验）只在 `HandleToolCall` 与另一处被调用，**该函数完全不调用它**。因此 `mcp-init-host` 非空时只比较共享的 `router-key`，通过即重写 `:authority` 转发。补丁 0.7.0 改为 `JWTManager.ValidateBackendInitToken()`（HS256 + issuer/audience/purpose/host），且 **`config.MCPServersConfig.RouterAPIKey` 在该版本被整体移除**。两版差异因此可在进程内直接观测。
- 构建方式：**基础镜像不变**（仍为 `buildpack-deps@sha256:97d2909f...`），把固定版本的 Go 工具链与按 variant 分离的 vendor 依赖树作为 `build.inputs`（官方 tarball `go1.25.9`，sha256 取自 go.dev 的 JSON 元数据并本地复核一致）。Dockerfile 在构建期用 `go test -c` 编译出上游 `internal/mcp-router` 的测试二进制，运行期不再需要网络。
- 踩到的坑：`go.mod` 的 `toolchain` 指令在补丁版要求 **go1.25.9**（漏洞版为 1.25.5），而 Docker 构建是 `--network none`，Go 无法自动下载工具链，报 `toolchain not available`。改用 1.25.9 同时满足两版。
- 两版源码结构不兼容，harness 因此按 variant 分文件：漏洞版构造器写 `RouterAPIKey`，补丁版写 `JWTManager`；共享部分放在 `lab_mechanism_test.go`。若强行合并会在补丁版编译失败（字段已不存在）。
- `verify.py` 的 check id 必须与协议约定一致（`target_ready`、`benign_task_passed`、`vulnerable_effect_observed`、`patched_effect_blocked`）。首次运行 12 例全部报 `invalid_evidence: Missing required checks`，原因就是自拟了 check id；协议在 `runner/protocol.py` 中按 (variant, scenario) 强制要求这四个 id。
- 四场景实测结果：漏洞版+attack 观察到 `:authority` 被改写为攻击者主机且 `mcp-init-host`/`router-key` 被剥离；补丁版+attack 返回 HTTP 400 且无任何 header 改写；两版 benign 均正常路由到 broker（`x-mcp-servername=mcpBroker`）。
- 注意：`verify.py` 在输入指纹内，改动它会令既有 build manifest 失效，必须重建后再跑验收。

## 当前状态（2026-09-24）

### 规则更正（2026-09-30）

ADR-0004 及当前晋升校验允许未发布镜像的环境在 `image` 留空时达到 `ready`；只有选择发布镜像时，才要求漏洞版和修复版同时填写固定 digest。以下 2026-09-24 的状态记录保留当时的规则背景，不再代表当前晋升门槛。

- 索引包含 39 个环境：38 个已在 Linux amd64 上完成四场景三轮机制验收并通过，1 个因上游补丁版无法 import 保持 `not_run`。
- **`mcp-filesystem/CVE-2025-53109` 是第一个 `ready` 环境**：两版镜像已推送到 GHCR 并固定 digest（`ghcr.io/glmgbj233/agent-vulhub-mcp-filesystem@sha256:c719ca6e…` / `@sha256:199ac091…`），三轮验收在 digest 固定的 metadata 上重跑，审阅者 `glmgbj233`，证据归档在 `environments/mcp-filesystem/CVE-2025-53109/evidence/`。
- 其余 38 个环境仍为 `draft`，且**两版 `image` 仍为空**——`ready` 的构建侧已就绪，缺口是逐环境的 GHCR 发布 digest。
- 通过环境的 metadata evidence 均指向 2026-09-24 重跑的三轮 `report.json`（每份 12/12 case 通过），且报告指纹与当前工作树一致。
- 唯一剩余的 `not_run` 环境在 `verification.mechanism.notes` 写明了具体阻塞原因，不再有空白备注。
- `python3 -m runner check` 通过；`python3 -m unittest discover -s tests -v` 共 100 项通过；`git diff --check` 通过。
- 真实模型端到端测试仍按环境逐项标记为 `not_applicable`；机制验收不证明模型会选择工具或完成完整工作流。

## 公开基础镜像迁移与重新验收（2026-09-23）

- 原先固定的 `codex-universal` digest 在公开 registry 中不存在（`ghcr.io/openai/codex-universal` 的 77 个公开 tag 均不含该 digest），外部无法复现。已替换为可公开拉取的 `buildpack-deps@sha256:97d2909f…`，使全部环境可被第三方重建。
- 新基础镜像提供 Python 3.10（原为 3.12），因此补齐两类离线运行时输入：Node 22.14.0（`n8n`、`mcp-server-kubernetes` 等）与 pip 25.1.1 wheel 自举（11 个 Python 环境）；13 个 Dockerfile 相应调整，全部在 `--offline` 下构建成功。
- Python 3.10 会激活 `python_version < "3.11"` 标记，使 `anyio` 需要 `exceptiongroup`；该 wheel 原先未打包，已补入 `mcp-server-git/CVE-2025-68143` 与 `praisonai/CVE-2026-40149` 的依赖包并更新 sha256。
- `omnigent/CVE-2026-62674` 原记录的阻塞理由（上游 `pyproject.toml` 要求 Python >=3.12）在公开基础镜像上依然成立：`cel_expr_python`、`rpds-py` 等包只发布 cp311+ 的 wheel。但该环境的 PoC 不触碰这些代码路径（`cel_expr_python` 仅在函数内惰性导入），因此按上游 `uv.lock` 重建了 cp310 可用的依赖闭包，并修正了 PoC 的三处缺陷：路由选择未过滤 HTTP 方法而误取只读 GET 处理器、伪 agent 缺少响应模型所需字段、以及把"补丁正确拒绝"误判为执行失败。修正后 12/12 通过。
- 按 [ADR-0015](adr/0015-maintainer-promotion-and-invalidation.md)，基础镜像与运行时输入属于材料性变化，故全部 28 个受影响环境先降回 `not_run`，完成重建与四场景三轮验收后恢复 `passed`。
- 宿主 Docker 默认地址池（16 个 `/20`）被其他项目的长期网络占满，compose 无法自动分配子网。新增声明式 `runtime.network_pool`（`docs/environment-contract.md` 已记录）：运行器从声明的私有网段为每个 project 分配 `/24` 并跳过与宿主既有网络重叠的候选，仍受 `network.<名称>.subnet` 例外约束。该字段不参与输入指纹，因此不使既有证据失效。

## 严重级别与阻塞说明补全（2026-09-23）

- 全部 39 个环境补上顶层 `severity`，归一化为 `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`NONE`。分布：**CRITICAL 8、HIGH 20、MEDIUM 11**，`UNKNOWN` 0 个（该分布是 2026-09-23 用权威来源逐个复核后的结果，见下条；`praisonai/CVE-2026-44334` 由 CRITICAL 更正为 HIGH）。`runner check` 现在拒绝其他写法（含小写与 CVSS 数字）。`UNKNOWN` 是已声明的合法取值，表示没有任何权威来源发布过评级；它不阻碍晋升——评级缺失是上游事实，不是本仓库能修复的缺陷。
- 取值以**公告页面的权威评级**为准，而不是直接采信 AgentSec 数据库的 `severity` 列。逐条核对后修正了 4 处数据库与公告不一致：`praisonai/CVE-2026-44334`（HIGH→CRITICAL）、`praisonai/CVE-2026-61428`（MEDIUM→HIGH）、`agent-device/GHSA-M7Q5-6423-2MWQ`（无→MEDIUM）、`vtcode/GHSA-WQGW-CRR5-CR2P`（无→HIGH）。GitHub 的 advisory API 对部分公告返回 404（未进 API 索引），但公告页面本身可达，因此**不能**用 API 404 判定公告不存在——这是本次差点误判的坑。
- 6 个 `not_run` 环境补写了具体阻塞原因，不再有空白备注：`factoryfloor/CVE-2026-88063`（归档名与 `build.inputs` 不一致，且产品是 macOS Swift GUI）、`flowise/CVE-2026-70477` 与 `mcp-gateway/GHSA-g53w-w6mj-hrpp`（Dockerfile 仍是 `exit 2` 的未实现模板）、`praisonai/CVE-2026-61445`（上游 v4.6.78 的 `aicoder.py:177` 缺右括号，补丁版无法 import）、`vtcode/GHSA-WQGW-CRR5-CR2P`（基础镜像无 cargo，且 Dockerfile 漏拷 `lab_support.py`）。（其中 `mcp-gateway/GHSA-g53w-w6mj-hrpp` 已于 2026-09-24 补齐配方并通过三轮验收，见下节。）
- `praisonai/CVE-2026-57117` 原备注只说"从未执行"：实测可构建且 PoC 完整，已补跑三轮并通过，状态转为 `passed`。
- 39 个环境全部在 `--offline` 下构建成功（38 个通过 + 1 个已知 `not_run` 阻塞项按预期失败），且每个构建清单的 `input_binding` 与当前工作树一致，0 个过期——`ready` 的构建侧已经就绪，唯一缺口是 GHCR 发布 digest。
- 复核 6 个 `not_run` 时发现并修掉一处隐藏缺陷：`factoryfloor/CVE-2026-88063` 的 `archive` 字段写的是 `vulnerable-source.tar.gz`，而声明的 build input 是 `factoryfloor-vulnerable-source.tar.gz`，导致 `runner build` 以 `archive must name a build input` 拒绝——这不是平台限制，而是 metadata 错误。修正后构建通过，`reproduce.py` 仍按预期返回 `not_run`（macOS GUI 才是真实阻塞）。同时纠正了 `vtcode` 的阻塞描述：真实原因是基础镜像迁移丢了 Rust 工具链（`codex-universal` 自带、`buildpack-deps` 不含），不是此前写的"漏拷 `lab_support.py`"（该环境从未使用它）。
- 逐一验证剩余阻塞是否可解，结论都是不可解且已把理由写准：`praisonai/CVE-2026-61445` 的语法错误在 4.6.x 全线存在（4.6.81/4.6.82/4.6.83 逐一核对），且 **v4.7.0 起 `aicoder.py` 被整体移除**，所以"重新固定到更新版本"这条修复路径实测不通；`vtcode` 除缺 Rust 外还有第二个独立阻塞（交互式 TUI 触发面没有稳定非交互入口），且 rustup 工具链解包 1.3–2.7 GB、`rust:*` 镜像不含 harness 所需的 Python 3，因此补工具链既不经济也不足以解除阻塞。
- 修复 `runtime.network_pool` 的分配缺陷：池为 `/16` 时恰好含 256 个 `/24`，而旧实现以 `len(candidates) > 256` 为条件才启用旋转，于是 `len(candidates) - 256 == 0`，该条件恒不成立，**所有 project 都固定选中池内第一个 `/24`**（实测两个不同 project 都返回 `10.200.0.0/24`），并发运行必然冲突。改为无条件按 project 派生偏移旋转，且偏移量取池大小模数、project id 是每个 case 唯一的随机 UUID，因此不同 project 在池耗尽前得到不同偏移。同时如实记录仍存在的限制：`host_subnets()` 只能看到已创建的网络，两个运行若都在对方建网前完成分配仍可能撞车。
- `runner check` 新增静态证据校验（`check_evidence`）：此前 `ready_check` 只检查已经是 `ready` 的环境，因此 draft 可以在证据已失效的情况下继续声称 `passed`，要等到 `promote` 才被拒绝。现在 `check` 会核对每条 mechanism evidence 是否存在、是否属于本环境、其 `fingerprint` 是否仍与当前工作树一致。这是纯 JSON 比对，不启动容器、不执行 PoC。注意 evidence 路径是**相对仓库根**记录的（与 fixtures、Dockerfile 的相对环境目录不同），这是实现时踩到的第一个坑。
- 修好 harvest 与 `severity` 校验的衔接缺口：`apply_candidate_metadata` 原本只替换 title / agent_specificity / advisories，**从不写 `severity`**，于是 scaffold 出来的 draft 一律停留在模板默认的 `UNKNOWN`——数据库已经知道的评级在入库第一步就丢了。同时数据库该列混用大小写（实测候选里并存 `HIGH` / `high` / `MEDIUM` / `medium`）并且把 KEV 标记 `known_exploited` 也塞在同一列，原样写入会被 `runner check` 拒绝。新增 `normalize_severity()` 统一归一（`moderate`→`MEDIUM`、`known_exploited`→`HIGH`、无法识别→`UNKNOWN`），并同时用于候选记录与 scaffold 出的 metadata。实测 `CVE-2023-36095`（库中 `critical`）现在生成 `severity = "CRITICAL"` 且 staging root 通过 `runner check`；库中该列为空的三条则如实记为 `UNKNOWN`。
- 用独立来源复核了全部 39 个 severity，并改掉 1 处真实错误：`praisonai/CVE-2026-44334` 原写 `CRITICAL`，但 OSV（`GHSA-xcmw-grxf-wjhj`，CVSS 3.1 8.4）与 AgentSec 数据库都记为 `HIGH`，已改为 `HIGH`。复核覆盖面：6 个有 CVE 的环境与 NVD 全部一致；25 个 GHSA-only 环境中 21 个从 OSV 取到评级并全部一致（其中 4 个是 OSV 的 `MODERATE` 写法，归一后即 MEDIUM）。
- **余下 3 个已用 GitHub 仓库级公告 API 补齐，全部一致，现已无未核对项**：`gh api repos/<owner>/<repo>/security-advisories/<GHSA> --jq .severity` 可以拿到**仓库级** GHSA 的权威评级，而这些记录在 OSV 与 GitHub 全局公告库（`advisories/<GHSA>`）里都查不到——这正是它们此前无法自动核对的原因。实测：`callstack/agent-device` = `medium`（仓库 MEDIUM ✅）、`alltuner/factoryfloor` = `high`（仓库 HIGH ✅）、`vinhnx/VTCode` = `high`（仓库 HIGH ✅）。该端点返回的是小写值（`medium`/`high`），与 `normalize_severity()` 的归一结果一致。注意仓库名必须取 `source_url` 的**准确大小写**（`vinhnx/VTCode` 命中，`vTcode/vtcode` 404）。
- 复核过程中修正了自己的两处方法论错误，并写进契约以免重犯：OSV 的 GHSA 查询**区分大小写**（`GHSA-g53w-w6mj-hrpp` 命中、大写形式 404），以及早期一个对比脚本从公告 URL 末段取标识符、导致 25 个环境被误判为"库中无记录"——两处都曾让我得出过错误结论（一度误报仓库与 NVD 在 CVSS 版本上不一致）。最终确认的事实是：仓库值与权威来源**没有** CVSS 版本偏好冲突，那 6 个可比环境全部一致。
- 注意：`docs/environment-contract.md` 与 `runner/*.py` 都在输入指纹内，本次对它们的编辑使全部既有证据失效；已对 33 个通过环境整体重跑三轮验收，报告指纹与当前工作树一致。
- 查清并实测了晋升的步骤顺序（此前只有"33/33 通过静态门禁"的说法，且该说法基于一个把证据路径写成仓库根 `results/...` 的模拟，**那个模拟本身是错的**）。`fingerprint()` 计入两版 `image` digest，而 `input_binding()` 将其清空，因此 digest 必须在生成验收报告**之前**写进 metadata，否则回填 digest 会让报告立即过期；`ready_check` 又用 `contained(directory, review.report)` 按**环境目录**解析路径，而 `reproduce` 写在仓库根 `results/` 下，所以必须经 `promote` 把证据归档进 `environments/<env>/evidence/<run_id>/` 才能通过。细节记在 `docs/blockers-platform-and-materials.md`。
- **更正（2026-09-24）**：上一版这里写着"该顺序已在临时克隆上用合成 digest 完整验证：`promote` 成功且 `ready_check` 复检通过"。**那句话是错的**，实测结果为失败：回填合成 digest 后 `promote` 报 `vulnerable needs pinned commit and image digest`（`runner/cli.py:116`），因为 `promote` 先把 `lifecycle` 置为 `ready` 再跑完整校验，而该校验要求 `IMAGE` 正则匹配两版 `image`，空 digest 必然失败。由此得到比原记录更强的结论：**digest 门禁就在晋升路径上，GHCR 推送必须先解开**。另实测 `mcp-filesystem/CVE-2025-53109` 的报告指纹与**空 digest 状态**下的 metadata 指纹逐位相同，故 digest 一回填该报告即作废。

## 漏洞图解工具链（新增）

- 新增 `diagram.toml` 图解契约、`runner/diagram.py` 渲染与校验模块、`python3 -m runner diagram` 命令和 `templates/environment/diagram.toml` 模板；字段与规则见[漏洞图解契约](diagram-contract.md)和 [ADR-0020](adr/0020-diagram-source-and-rendering.md)。
- 图采用 Mermaid：`sequenceDiagram` 表达触发过程，`flowchart` 表达主体与信任边界；产物为 `diagram/mechanism.mmd`、`diagram/entities.mmd` 和 `README.zh-cn.md` 中的图解区块，全部由 `diagram.toml` 渲染，不手写。
- 图只描述漏洞本身：主体类型限定为 `actor|client|service|tool|store|sink`，阶段限定为 `setup|trigger|effect`。`verifier`/`runtime` 类型和 `verify` 阶段被刻意删除，因此运行器、`verify.py`、结果卷、容器编排、协议替身等复现工具链在 schema 上写不进触发过程；替身与无害效果保留并标 `synthetic = true`。
- 静态校验并入 `runner check`：主体必须有 `role`、步骤编号连续且引用已声明主体、至少一个 `diverges = true` 的分歧步骤、信任边界成员必须存在、`fixtures/...` 引用必须存在且被 fixture manifest 覆盖、生成物不得漂移。
- 图解属于说明性文档，不参与输入指纹；修改图不会使既有 `ready` 证据失效，图解也不能替代证据。
- `runner new` 生成的草稿自带可渲染的图解骨架并立即写入图解区块。
- 覆盖状态：工具、模板和 3 个样例环境（`mcp-filesystem/CVE-2025-53109`、`mcp-server-kubernetes/CVE-2026-61459`、`openharness/CVE-2026-56696`）已完成；其余 36 个环境尚未补图，`python3 -m runner diagram --missing` 可列出。`diagram.toml` 当前是可选增强，全量覆盖后再加入 `REQUIRED_FILES` 强制要求。

以下内容是 2026-09-10 的首版历史记录，保留当时的 6 个环境和 30 项测试统计。

日期：2026-09-10。用户已确认设计并授权实现。本记录描述共享工具和 6 个机制环境；环境仍需维护者审阅后才能晋升 `ready`。

## 已实现

- Python 标准库 CLI：list/check/new、lint、fetch/build、reproduce、publish、promote/refresh。
- 固定内容哈希的源码/依赖缓存、禁网构建、本地 image ID 与 GHCR digest 分别记录、来源 label 检查。
- Compose JSON 解析和默认隔离检查、显式例外、一次性或服务模式、辅助服务 healthcheck。
- 每轮四个独立测试及状态清理，超时、阶段日志、失败原因、缺失证据拒绝和独立 verdict 核对。
- 三轮晋升、维护者声明、例外双审阅、永久小型证据包、manifest、输入指纹失效和历史降级记录。
- 更新模板、执行协议、收录说明；PR 静态 CI 与独立 VM 手动/定时复现工作流。
- 收录 6 个 Agent/MCP CVE 环境：iOS Simulator MCP、Node Code Sandbox MCP、MCP Git、Filesystem 两个路径边界案例，以及 HackMD MCP HTTP connector。
- 新增的三个环境使用完整上游源码和固定依赖：CVE-2025-53109、CVE-2025-53110、CVE-2025-59155；PoC 直接调用真实 MCP handler，验证器独立读取证据。

## 验证

- `python3 -m unittest discover -s tests -v`：30 项通过，不运行漏洞代码。
- `python3 -m runner check`：通过，索引包含 6 个环境。
- `python3 -m runner lint`：6 个环境和模板的 Compose 静态解析通过。
- `git diff --check`：通过。
- 显式 Docker smoke：Python 固定基础镜像、Linux amd64、Docker 29.6.1、Compose 5.3.0；3 轮共 12 测试通过。
- 服务模式和健康辅助服务通过；缺失 verdict、PoC 超时、辅助服务不健康均按预期失败并清理。
- 最后检查 `avh-` 实验容器、网络和 volume 均无残留；本地镜像、源码缓存和诊断报告保留。

Docker 实测报告目录：`results/tooling-smoke/f71882b32cd5/`。这些是合成工具验证，不进入正式环境索引。后续小幅修改增加了报告源版本/宿主架构校验和清理诊断字段，已由最终工具测试覆盖。

## 外部前提与限制

GHCR 发布命令已实现，尚未真实上传；需要维护者账号、目标 package 和登录权限。隔离 CI 配置已写入，但本次未创建 GitHub environment、分支保护或一次性 VM runner，这些需仓库管理员配置。

当前 6 个环境都保持 `draft`：尚未上传 GHCR，也尚未运行 `promote`。首版仅编排机制复现；真实模型入口保留为可选。Dockerfile 静态检查不是完整行为审计，来源标签、证据哈希和审阅者字符串不是密码学真实性证明。来源、无害效果、脱敏、维护者身份及容器工具链变更的语义影响仍需平台审阅与人工复核。

新增环境最近一次三轮报告：`results/mcp-filesystem/CVE-2025-53109/20260910T072747Z-45bb18b44b7d/report.json`、`results/mcp-filesystem/CVE-2025-53110/20260910T072848Z-3c954a207a39/report.json`、`results/hackmd-mcp/CVE-2025-59155/20260910T072946Z-f23140138608/report.json`。三个报告均为 12/12 case 通过并完成清理。

详细参数、证据字段和实现细化见 [环境协议](environment-contract.md)。
