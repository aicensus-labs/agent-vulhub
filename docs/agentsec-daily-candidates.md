# AgentSec-Daily `agent_unique` 候选

盘点日期：2026-09-18

## 结论

外部 worktree 的 reproduction catalog 不是新增来源：

- 外部 AgentSec-Daily checkout 中的 `integrate-db-frontend/agentsec_daily/reproduction_catalog.py` 有 39 个环境，其中 6 个是 legacy、33 个是 `agent_unique`。
- 本仓库 `environments.toml` 也有 39 个环境。两边的 `environment_id` 集合完全相同，没有可以直接从 catalog 复制的新环境。
- 但外部 SQLite 数据库仍有尚未进入 catalog 的 `agent_unique` 记录。按有效 specificity（reviewer metadata 优先）、`approved`、`push`、research value >= 4，并按数据库标识去重后，共有 334 个标识，其中 27 个已经对应当前环境，307 个不在当前 catalog；这不是 307 个独立漏洞，里面包含 CVE/GHSA 别名重复、数据库错误映射和传统漏洞误标。

因此，下面的表是“值得立项核查”的候选，不是已经具备源码归档、镜像和验收结果的环境。

## 第一批候选

这些条目的官方 advisory/CVE 身份、受影响版本和修复版本已经可以从公开一手来源核对。下一步只需按本仓库 contract 收集 vulnerable/patched 源码、锁定依赖和设计四组对照；未完成前不得写入 reproduction catalog。

| 优先级 | canonical identifier | 项目/机制 | 建议环境形态 | 主要来源 |
| --- | --- | --- | --- | --- |
| P0 | `CVE-2026-54561` | MCP Memory Keeper；`context_import` 路径未限制，可把任意可读文件带入持久上下文 | Node MCP server；合成敏感 JSON + 受控文件读取证据 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-54561) |
| P0 | `CVE-2026-53957` | Contentful MCP；LLM 控制的 `host`/`proxy` 改变 CMA 请求目的地并携带 PAT | Node MCP server + loopback receiver；必须用合成 PAT | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-53957) |
| P0 | `GHSA-62f5-cp2p-vq95` / `CVE-2026-75859` | CodeWhale 项目配置把仓库控制的文件路径注入 Agent system prompt | Rust/CLI；恶意仓库 fixture + 合成敏感文件 | [GitHub Advisory](https://github.com/advisories/GHSA-62f5-cp2p-vq95) |
| P0 | `GHSA-7j5w-7r7x-9v27` / `CVE-2026-75913` | CodeWhale `git_show` 把 model-controlled revision 当 Git option，且工具声明为自动批准/只读 | Rust/CLI；验证写入测试文件，不写真实宿主文件 | [GitHub Advisory](https://github.com/advisories/GHSA-7j5w-7r7x-9v27) |
| P0 | `GHSA-h539-c7r8-3xq4` / `CVE-2026-75915` | CodeWhale `js_execution` 未清理父进程环境，环境变量进入模型上下文 | Rust/CLI；合成 marker，禁止读取真实凭据 | [GitHub Advisory](https://github.com/advisories/GHSA-h539-c7r8-3xq4) |
| P0 | `GHSA-gx45-xrj5-g6c4` / `CVE-2026-75911` | CodeWhale 克隆仓库的 `.codewhale/config.toml` 可放宽 `allow_shell` | Rust/CLI；恶意仓库 fixture，验证策略是否被项目配置提升 | [GitHub Advisory](https://github.com/advisories/GHSA-gx45-xrj5-g6c4) |
| P0 | `GHSA-7mqg-cx4g-x2rf` / `CVE-2026-62676` | Omnigent shell guardrail parser fail-open | Python package；直接调用 guardrail，加入 benign/blocked/accepted 三态 | [GitHub Advisory](https://github.com/advisories/GHSA-7mqg-cx4g-x2rf) |
| P0 | `CVE-2026-79745` | MCPHub 非 admin 可改写全局 prompt/resource，影响所有会话 | Node HTTP service；两个用户、权限对照和全局读取对照 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-79745) |
| P0 | `GHSA-rg68-wg77-c3wm` / `CVE-2026-81096` | ToolUniverse Python executor 的沙箱可通过动态属性/导入路径逃逸 | Python service；只使用无害 marker，容器内验证边界 | [GitHub Advisory](https://github.com/advisories/GHSA-rg68-wg77-c3wm) |
| P0 | `GHSA-57gg-9j2p-5v4x` / `CVE-2026-82447` | Skyvern `TextPromptBlock` 二次渲染导致 Jinja 从沙箱逃逸 | Python service；输出 marker，不执行破坏性命令 | [GitHub Advisory](https://github.com/advisories/GHSA-57gg-9j2p-5v4x) |
| P0 | `GHSA-g5r6-gv6m-f5jv` / `CVE-2026-73498` | MCP Atlassian 上传附件缺少路径校验，Agent 可读任意服务器文件 | 复用 MCP Atlassian 项目依赖；合成附件 receiver | [GitHub Advisory](https://github.com/advisories/GHSA-g5r6-gv6m-f5jv) |
| P0 | `GHSA-h44j-f5r5-ph73` / `CVE-2026-59207` | n8n AI Agents MCP connector 绕过 Allowed HTTP Request Domains | 复用 n8n 环境；本地 receiver + allowlist 对照 | [GitHub Advisory](https://github.com/advisories/GHSA-h44j-f5r5-ph73) |
| P0 | `GHSA-74h3-cxq7-vc5q` / `CVE-2026-59216` | Open WebUI Socket.IO 的 session caller 未校验，跨用户执行 code/tool | 复用 Open WebUI 环境；两个用户会话 + 非目标 session 对照 | [GitHub Advisory](https://github.com/advisories/GHSA-74h3-cxq7-vc5q) |
| P0 | `GHSA-399c-3gm2-p29v` / `CVE-2026-56695` | OpenHarness resume 命令暴露其他用户的 session snapshot | 复用 OpenHarness 环境；双用户合成 session | [GitHub Advisory](https://github.com/advisories/GHSA-399c-3gm2-p29v) |
| P0 | `GHSA-gjgq-w2m6-wr5q` / `CVE-2026-54771` | Langroid 未验证 sender，用户可直接提交原始 tool JSON 调用 `handle=True` 工具 | Python package；不需要真实模型，直接验证 user/LLM sender 对照 | [GitHub Advisory](https://github.com/advisories/GHSA-gjgq-w2m6-wr5q) |
| P0 | `GHSA-29w2-fq35-v728` / `CVE-2026-16584` | AWS API MCP Server 启动策略数据加载失败后持续跳过每请求 policy check | Python MCP server；故意损坏初始化输入，使用本地 AWS CLI stub 或 dry-run | [GitHub Advisory](https://github.com/advisories/GHSA-29w2-fq35-v728) |

CodeWhale 的四项应当分别建环境，因为它们命中不同的信任边界（项目配置、只读工具能力、子进程环境、shell 权限）。可以共享 source archive 下载和 Rust 依赖缓存，但不能用一个宽泛的“CodeWhale 有漏洞”复现替代四个机制对照。

## 第二批候选

这些也有明确机制，但实现成本、依赖替身或项目规模更高，适合第一批验收后继续加入：

| canonical identifier | 项目/机制 | 主要成本或风险 |
| --- | --- | --- |
| `CVE-2026-61559` / `GHSA-2h44-8472-frjj` | `@zereight/mcp-gitlab` SSRF | SSRF 属于常见漏洞形态，需要证明 MCP 工具/凭据链带来的 Agent 特异性；使用 loopback receiver。 |
| `CVE-2026-50143` | Apify MCP Actor URL/Origin 混淆导致 bearer token 发往第三方 | 需要构造本地 Actor 元数据和 token receiver，确认公开源码与修复提交。 |
| `CVE-2026-54555` | rtk shell permission splitter 绕过 | Rust CLI/hook，需稳定复现 shell 解析边界和修复前后 allow/deny 结果。 |
| `CVE-2026-55743` | OpenHuman shell allowlist 的 `-execdir`/环境变量绕过 | Rust CLI，需明确沙箱边界并只做无害 marker。 |
| `CVE-2026-72718` | goose 的 Git 配置触发未 sandbox 的命令执行 | 需要恶意 Git fixture；不应接触宿主真实 Git 配置。 |
| `CVE-2026-82217` | Eclipse Theia Agent Mode 文件路径越界写/删 | 完整 IDE/backend 构建面较大，优先做最小 backend 机制 fixture。 |
| `CVE-2026-82233` | SiYuan MCP `asset.upload` 绝对路径越界读取 | Go 应用较大，需确认 MCP 入口和 patched commit 可离线构建。 |
| `GHSA-247c-497m-jx82` / `CVE-2026-81097` | ToolUniverse Ruby “只读 sandbox” 通过未覆盖的 PTY 入口执行命令 | 需要 Ruby/PTY 依赖；必须限制到容器内 marker。 |
| `GHSA-x227-pf99-vffg` / `CVE-2026-57123` | PraisonAI MCP SSE 无认证、无 Origin 校验 | 与现有 PraisonAI 条目高度相关，但数据库把它错误混入另一个 CVE 标题，先做 canonical 校正。 |
| `CVE-2026-57137`、`CVE-2026-57139`、`CVE-2026-57141` | PraisonAI tool approval、MCP HTTP 绑定、codeMode 机制 | 适合复用 PraisonAI source/dependency cache；必须逐项核对官方 CVE 与修复 commit。 |

## 不应直接加入的条目

- 数据库中只有 VulDB 二手描述、没有可核对修复版本或源码位置的记录，例如 `CVE-2026-18236`；先不建环境。
- 同一 advisory 被数据库映射成多个不一致的 `vuln_id` 时，不能用任一行直接生成目录。例如 PraisonAI `CVE-2026-57139` 的行同时出现 `CVE-2026-56834`、`CVE-2026-57123`、`CVE-2026-57124` 等映射；应以官方 GitHub Advisory/NVD 为准。
- 仅因为产品是 Agent/MCP 就标成 `agent_unique` 的普通 SSRF、路径穿越或未认证接口，需要重新判断 Agent 信任边界。`CVE-2026-61559`、`CVE-2026-91935` 等应先完成这一步。
- 没有源码归档、修复对照、固定依赖或安全可观察证据的条目，不能因为数据库 `push` 就写入 `agentsec_daily/reproduction_catalog.py`。

## 与当前仓库的关系

以下是“新增漏洞、复用现有项目环境”的优先集合：

- `mcp-atlassian/GHSA-g5r6-gv6m-f5jv`，当前已有 `mcp-atlassian/GHSA-wm45-qh3g-v83f`。
- `n8n/CVE-2026-59207`，当前已有 `n8n/CVE-2026-86996`。
- `open-webui/CVE-2026-59216`，当前已有 `open-webui/CVE-2026-87017`。
- `openharness/CVE-2026-56695`，当前已有 `openharness/CVE-2026-56696`。
- `omnigent/CVE-2026-62676`，当前已有 `omnigent/CVE-2026-62674`。
- PraisonAI 的新 advisory 可复用现有 `environments/praisonai` 的构建路线，但不能共用一个 PoC；每个漏洞仍需独立的 vulnerable/patched/benign 控制。

## 复核依据

盘点只读打开外部 `data/agentsec_vulnerabilities.sqlite3`，没有读取 `.env`，没有运行任何 PoC，也没有启动容器。有效 specificity 使用 `vulnerability_metadata.agent_specificity`，为空时才回退到 `analysis_results.agent_specificity`；review 状态和推荐来自数据库。公开版本范围和修复版本通过 GitHub Advisory API/页面复核，NVD/CERT 条目仍需在收集源码时补齐 upstream commit 和 archive SHA256。

建议实施顺序：

1. `CVE-2026-54561`、`CVE-2026-53957`、`GHSA-62f5-cp2p-vq95`、`GHSA-7j5w-7r7x-9v27`。
2. `GHSA-7mqg-cx4g-x2rf`、`GHSA-g5r6-gv6m-f5jv`、`GHSA-h44j-f5r5-ph73`、`GHSA-74h3-cxq7-vc5q`、`GHSA-399c-3gm2-p29v`。
3. `GHSA-gjgq-w2m6-wr5q`、`GHSA-29w2-fq35-v728`、`CVE-2026-79745`、`GHSA-rg68-wg77-c3wm`。
4. 再处理 Theia、SiYuan、ToolUniverse Ruby、PraisonAI canonical 校正和其余高成本条目。
