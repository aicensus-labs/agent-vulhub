# 空壳 draft 环境可行性分诊

日期：2026-09-17。范围：`environments.toml` 中全部 39 个环境；其中原先 32 个空壳有 24 个已补齐并通过四场景三轮机制验收，8 个保持 `not_run`（6 个 blocker、1 个待复核项和 1 个真实入口待补项）。另有 7 个既有环境也已通过同样验收，因此当前共有 31 个环境的机制状态为 `passed`。本文不等同于 `ready` 发布结论；固定发布镜像和维护者审阅仍未完成。

## 判定标准

- **可直接实施**：走真实上游代码路径，用容器内本地 fixture（含固定工具参数、固定模型输出）即可形成攻击链，产品无需访问外部服务。允许使用固定镜像的辅助服务（如数据库、向量后端）。
- **需要替身**：必须模拟产品所依赖的外部对象才能形成完整链，例如假上游 API、本地 HTTP receiver、假远端 channel、假 k8s API、模型替身。替身不得替换被验证的漏洞代码。
- **阻塞**：当前没有 Linux amd64 容器内的稳定触发入口，或材料本身不可用。
- **待复核**：触发前提尚未确认。

## 分诊总表

| 环境 | 触发面 | 容器可行性 | 构建成本 | 需要替身 | 结论 | 备注 |
| --- | --- | --- | --- | --- | --- | --- |
| praisonai/CVE-2026-34955 | 内部函数 `SubprocessSandbox` | 高（纯 Python） | 低 | 不需要 | 可直接实施 | 使用 4.5.87/4.5.128，对照 shell 解释执行边界 |
| praisonai/CVE-2026-40149 | 网关审批白名单 HTTP 接口 | 高（本地服务） | 低-中 | 不需要 | 可直接实施 | 使用 4.5.124/4.5.128，对照匿名修改与认证保护 |
| praisonai/CVE-2026-40156 | 工作目录 `tools.py` 自动导入 | 高 | 低 | 不需要 | 可直接实施 | 使用 4.5.117/4.6.32，对照隐式导入与显式 opt-in |
| praisonai/CVE-2026-40158 | AST 沙箱内部函数 | 高 | 低 | 不需要 | 可直接实施 | 使用 4.5.117/4.6.32，对照动态属性绕过 |
| praisonai/CVE-2026-44334 | `recipe serve` + `POST /v1/recipes/run` | 高（本地服务） | 低-中 | 不需要 | 可直接实施 | 固定 recipe 与 `tools.py` |
| praisonai/CVE-2026-44339 | `ToolExecutionMixin.execute_tool` | 高 | 低 | 不需要 | 可直接实施 | 公告 PoC 的 `unittest.mock` 是测试替身，不进入环境 |
| praisonai/CVE-2026-47391 | A2A 示例 `calculate()` → `eval()` | 高（本地机制） | 中 | 需要（仅导入协作者桩） | 需要替身 | 已补齐；真实调用 `calculate()`，不调用模型；仅为 FastAPI/A2A 注册协作者提供最小桩 |
| praisonai/CVE-2026-47395 | `MentionsParser` 的 `@url` | 高 | 低 | 需要（本地 HTTP receiver） | 需要替身 | 攻击目标本身要本地起 |
| praisonai/CVE-2026-55527 | `FileMemory(user_id)` | 高 | 低 | 不需要 | 可直接实施 | |
| praisonai/CVE-2026-55530 | `ast_grep_rewrite` 工具 | 高 | 中（需离线打包 `ast-grep` CLI） | 不需要 | 可直接实施 | |
| praisonai/CVE-2026-55532 | `mcp serve --transport http-stream` + 伪造 Origin | 高（本地服务） | 低-中 | 不需要 | 可直接实施 | curl 即可，无需真实浏览器 |
| praisonai/CVE-2026-55540 | code 工具 + symlink fixture | 高 | 低 | 不需要 | 可直接实施 | |
| praisonai/CVE-2026-56833 | Dynamic Context history/terminal 工具 | 高 | 低 | 不需要 | 可直接实施 | 修复版调整为 4.6.59 |
| praisonai/CVE-2026-57117 | `LocalManagedAgent`/`SandboxedAgent` + compute provider | 待确认 | 待确认 | 待确认 | 待复核 | 须先确认 compute provider 能否容器内本地运行 |
| praisonai/CVE-2026-57120 | `execute_code` 工具 | 高 | 低 | 不需要 | 可直接实施 | 目前是读取原语、非完整 RCE，结论须如实写 |
| praisonai/CVE-2026-57125 | `POST /api/v1/runs` + `approve` 绕过 | 高（本地机制） | 中 | 可选（完整 RCE 链需固定模型输出） | 可直接实施（机制层） | 已补齐；真实 YAML parser 与 approval decorator，审批绕过是确定性的 |
| praisonai/CVE-2026-57129 | `MentionsParser` 的 `@file:` | 高 | 低 | 不需要 | 可直接实施 | |
| praisonai/CVE-2026-61428 | AgentMail webhook `POST` | 高（本地服务） | 低-中 | 不需要 | 可直接实施 | 用固定伪造事件，不连真实 AgentMail |
| praisonai/CVE-2026-61439 | 注入防御阈值判定 | 高 | 低 | 可选（证明传入模型需固定模型输出） | 可直接实施（阈值机制） | 只证明 HIGH 未被阻断 |
| praisonai/CVE-2026-61445 | AICoder 工具调用 | 当前修复归档不可导入 | 低-中 | 不需要 | 阻塞 | v4.6.78 及后续可访问 tag 的 aicoder.py 有语法错误；漏洞版已通过，见 source blocker |
| chainlit/CVE-2026-45018 | 未认证 `POST /mcp` stdio `fullCommand` | 高（单容器 Python 服务） | 中（30–40 个 pip 依赖，无编译） | 不需要 | 可直接实施 | 先建 Socket.IO session；2.12.0 配置为破坏性变更，两版各需 config fixture；镜像需 node+npx |
| claude-code-action/CVE-2026-47751 | Actions 运行器读 `.mcp.json` 起 MCP 进程 | 低（只能覆盖机制级一段） | 高（`claude-agent-sdk` 会拉 CLI） | 需要（假 GitHub 事件上下文 + 假 Anthropic 端点） | 需要替身 | 容器内无法复现 PR 工作流前提，README 须写明降级范围 |
| flowise/CVE-2026-70477 | chatflow CSV Agent → pyodide | 不可离线（构建极重） | 很高（pnpm monorepo + pyodide/pandas/numpy wasm，archive 49–51 MB） | 需要（固定模型输出） | 阻塞 | 3.1.3 直接删除 CSVAgent 与 pyodide |
| mcp-atlassian/GHSA-wm45-qh3g-v83f | 远程 MCP attachment upload 的 `file_path` | 高（streamable-http 单容器） | 低-中（Python，无编译无 DB） | 需要（假 Atlassian API） | 需要替身 | canary 可用 cwd 内文件；假后端须满足 atlassian-python-api 的 REST 契约 |
| mcp-gateway/GHSA-g53w-w6mj-hrpp | 未认证 router hair-pin 路径 | 低（需自建 Envoy ext_proc） | 很高（Go 1.25 + 手写 ext_proc 配置） | 需要（假上游后端） | 阻塞 | 脆弱点在 Envoy ext_proc；上游只有 Istio EnvoyFilter 生成物，自建等于另造部署面 |
| mcp-server-kubernetes/CVE-2026-61459 | stdio 工具 `kubectl_get/describe/delete` 的 `--server` 注入 | 高（stdio JSON-RPC） | 中（npm 依赖 + kubectl 二进制） | 需要（假 k8s API + 假 kubeconfig） | 需要替身 | 用假 API 接收 `Authorization: Bearer` canary；GHSA 生态标为 PyPI 有误，真实产品是 npm 包 |
| n8n/CVE-2026-86996 | Agent workflow tool → `SubworkflowPolicyChecker` | 可（Linux amd64） | 高（pnpm monorepo 数千包 + 前端构建 + DB） | 机制层不需要（真实 agent 链可选假 LLM） | 可直接实施 | 已补齐机制脚本；真实执行函数体，NVD 条目尚未发布；离线依赖固化仍是主要工作量 |
| omnigent/CVE-2026-62674 | `PUT /sessions/{id}/agent` → stdio MCP 子进程 | 不可（上游要求 Python >=3.12，固定基础镜像只有 3.10） | 当前不可用 | 不适用 | 阻塞 | 需先提供可核查的 Python 3.12+ amd64 基础镜像；见 blocker 记录 |
| open-webui/CVE-2026-87017 | knowledge 工具 → 向量后端 `search` | 可（需真实 Qdrant 等非默认后端） | 高（164 行固定依赖 + 前端构建 + 辅助服务） | 不需要（用真实 Qdrant，不是替身） | 可直接实施 | 已补齐机制脚本；默认 Chroma 不受影响，必须显式换后端；受控后端协议只返回 synthetic ID |
| openharness/CVE-2026-56696 | 远端 channel → `/issue`、`/pr_comments` | 可（纯 Python） | 低-中（约 18 个依赖，可离线固化 wheels） | 需要（假远端 channel） | 需要替身 | 无 fixed 版本号，用修复 commit 对照 |
| factoryfloor/CVE-2026-88063 | macOS GUI 创建 workstream | 不可（macOS 14 / Xcode / AppKit） | 不可在 Linux 离线构建 | 不适用 | 阻塞 | 除非维护者接受独立 macOS VM，否则超出 Linux amd64 ready 前提 |
| vtcode/GHSA-WQGW-CRR5-CR2P | 交互式 TUI 的 `session_start` hook | 不可稳定触发（TUI-only） | 当前不可用 | 不需要 | 阻塞 | 两处阻塞见下 |

## 分档小结

| 结论 | 数量 | 环境 |
| --- | --- | --- |
| 可直接实施 | 19 | 16 个 PraisonAI + chainlit + n8n + open-webui；其中 57125 为机制层 |
| 需要替身 | 6 | 47391、claude-code-action、mcp-atlassian、mcp-server-kubernetes、openharness、47395 |
| 待复核 | 1 | praisonai/CVE-2026-57117 |
| 阻塞 | 6 | flowise、mcp-gateway、factoryfloor、vtcode、praisonai/CVE-2026-61445、omnigent |

当前 39 个环境中有 31 个已按环境协议完成 fetch/build、四场景和三轮容器验收，`verification.mechanism.status` 为 `passed`；另有 8 个环境尚未完成可核查的机制验收，其中 6 个 blocker 和 claude-code-action 不得用替身函数或静态字符串冒充复现，详见 [blockers-platform-and-materials.md](blockers-platform-and-materials.md) 和 source-boundary blocker 记录。

## 来源与版本边界校验

- 跨项目 12 个源码 archive 已从 codeload 下载并逐字节比对 sha256，全部与 `metadata.build.inputs` 一致；factoryfloor、vtcode 的本地 `inputs/` 也已解包比对。
- chainlit、flowise、mcp-atlassian、mcp-gateway、mcp-server-kubernetes、n8n、omnigent、open-webui、openharness 的修复 diff 均可对照到机制。
- `factoryfloor/GHSA-923Q-2HMP-PRQ3`、`vtcode/GHSA-WQGW-CRR5-CR2P` 未进 OSV；`n8n/CVE-2026-86996` 的 NVD 条目尚未发布（OSV 的 `nvd_published_at` 为 null）。

## 需修正项

1. `praisonai/CVE-2026-56833`：OSV 记录 `affected: >=3.8.1, <=4.6.58`、`fixed: 4.6.59`，元数据已调整为 4.6.59。
2. `vtcode/GHSA-WQGW-CRR5-CR2P`：`inputs/` 的两个 Cargo vendor 归档实际是 134 字节的 Git-LFS 指针（实际 sha256 `a07254ef…`/`2383c9ed…`，元数据声明的是 LFS oid `917667d6…`/`86043185…`，URL 指向第三方 owner）。即使解决触发方式，`cargo build --locked --offline` 也必然失败，须先换成真实归档。
3. `claude-code-action/CVE-2026-47751`：元数据 `patched` commit `e8a10097` 与官方修复（pull#1066）不是同一 sha，须复核发布 tag 对应关系。
4. `mcp-gateway/GHSA-g53w-w6mj-hrpp`：元数据 `patched` commit `5d96c6f` 与官方修复 commit `6052079` 不同，须确认二者关系。
5. `omnigent/CVE-2026-62674`：advisory 修复 commit 为 `25a22dc`，元数据 patched 为 `6d892ec`（v0.3.0）；`536a75b...6d892ec` 的 compare 返回无可比内容，lineage 未校验。
6. `mcp-server-kubernetes/CVE-2026-61459`：GHSA/PYSEC 把生态标为 PyPI（PyPI 实际只到 0.1.6），真实产品是 npm 包；元数据用的是 npm，但来源说明须更正。
7. `openharness/CVE-2026-56696`：OSV 无 fixed 版本号，只有 `last_affected 0.1.9` 与修复 commit，环境协议允许用固定 commit 作为修复对照。

## 建议实施顺序

1. **机制验收批**：已完成 31 个环境的 `fetch`、离线 build 和四场景三轮验收；报告保存在各环境的 `results/` 目录。
2. **替身批**：5 个需要替身的环境已完成替身边界、fixture 哈希和真实产品调用验收；claude-code-action 仍待补齐真实 Action checkout 入口，发布前仍需维护者复核替身没有替换漏洞代码。
3. **待复核**：确认 `praisonai/CVE-2026-57117` 的 compute provider 是否能在 Linux amd64 容器内稳定运行。
4. **阻塞项**：保持 6 个环境为 `draft`/`not_run`；只有官方 AICoder 修复归档、Envoy 部署、macOS VM、TUI 触发、离线材料或 Python 3.12+ 基础镜像得到解决后再恢复实现。

每个环境仍须满足环境协议完整验收：固定镜像、四组对照（漏洞版攻击/修复版攻击/两版正常任务）、独立验证器、至少三轮通过、GHCR digest 与维护者审阅后才能 `ready`。
