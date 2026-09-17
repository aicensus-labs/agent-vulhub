# Platform And Material Blockers

日期：2026-09-17

这些环境的源码和漏洞描述已经完成初步核查，但当前无法在仓库规定的 Linux amd64、网络隔离、真实上游代码路径下形成可核查的 vulnerable/patched/benign 四场景对照。它们保持 `draft`，PoC 返回 `not_run`；不得用替身函数、静态 canary 或模拟 GUI/Envoy 来制造通过结果。

## flowise/CVE-2026-70477

漏洞版 3.1.2 的触发路径在 `packages/components/nodes/agents/CSVAgent/CSVAgent.ts`：加载 `pyodide` 及 `pandas`/`numpy` WASM，接收模型生成的 Python，再经过验证器后交给 `runPythonAsync()`。3.1.3 的对应 CSV Agent/pyodide 源码被移除，不能直接用同一路径构成修复版对照。

当前固定归档约 49--51 MB，完整离线构建还需要与上游匹配的 pyodide、pandas、numpy WASM 包和 pnpm 依赖。仅复制一个 Python 或 JavaScript 函数会绕过 Flowise 的 node、LangChain、WASM 和验证边界，因此不是可接受的复现。恢复条件是补齐可核查的离线依赖，并确定 3.1.3 的真实替代路径或官方修复对照。

## mcp-gateway/GHSA-g53w-w6mj-hrpp

漏洞点位于 Envoy `ext_proc` 与 MCP Gateway router 的组合部署：未认证 initialize/hair-pin 路径信任 `mcp-init-host` 并改写上游 `:authority`，从而绕过 broker 的 JWT/capability 过滤。上游仓库提供的是由 Istio EnvoyFilter 生成的部署材料，没有能在本项目中直接启动的静态 Envoy bootstrap 和独立 ext_proc 测试入口。

手写一个 Envoy 配置、ext_proc 服务和假上游会重新定义部署面，无法说明结果来自固定 Gateway 版本的真实部署。恢复条件是上游提供独立可运行的 bootstrap/fixture，或维护者明确接受隔离的 Envoy 集成测试环境并补齐两版完整材料。

## factoryfloor/CVE-2026-88063

Factory Floor 是 macOS 14 Swift/AppKit GUI。漏洞需要用户在一次性仓库中创建 workstream，使 GUI 触发仓库脚本预加载；修复版还涉及内容绑定的项目批准。Linux amd64 容器既没有 AppKit/Xcode，也不能提供等价的 GUI 用户动作。

当前 Dockerfile 仅保留固定源码，不能把 shell 脚本直接执行当成 Factory Floor 的复现。恢复条件是使用独立、可销毁的 macOS VM，并为 GUI 操作和证据采集建立与本协议等价的隔离验收流程。

## vtcode/GHSA-WQGW-CRR5-CR2P

漏洞触发面是交互式 VT Code TUI 的 `session_start` hook。当前没有稳定的非交互入口可以区分 TUI 启动失败和 hook 执行；直接运行二进制或 shell 命令不能证明上游生命周期代码被调用。

此外，`inputs/vtcode-vulnerable-cargo-vendor.tar.gz` 和 `inputs/vtcode-patched-cargo-vendor.tar.gz` 都是 134 字节的 Git-LFS 指针，不是 Cargo vendor 归档。实际文件 SHA-256 分别为 `a07254ef0e2bd0971660cfbf04669228f224a1a278e60545fd9f3b1925c614cd` 和 `2383c9ed35ca3de2d02234fc74a8bcb76ffa9b7fff4b0d68362ebfa3591a7b1d`，与 metadata 声明的 LFS 对象哈希不符，且 URL 指向第三方仓库。即使解决 TUI 触发，当前 `cargo build --locked --offline` 也不能成为有效前提。

恢复条件是换成来源可核查的真实 vendor 归档，并先证明稳定非交互触发确实进入 `session_start`；在此之前保持 `draft`/`not_run`。

## omnigent/CVE-2026-62674

Omnigent 0.2.0 的上游 `pyproject.toml` 声明 `requires-python = ">=3.12"`。
本仓库固定的 `codex-universal` amd64 基础镜像只有 Python 3.10.12，且构建
协议禁止联网安装或隐式替换解释器。该版本在导入真实 sessions 路由前即缺少
运行依赖，补包也不能满足解释器版本前提，因此不能把当前脚本结果当作漏洞
复现。

恢复条件是固定一个含 Python 3.12+ 的可核查 amd64 基础镜像，或提供同等可
审计的离线解释器材料，并重新完成两版四场景三轮验收；不得修改上游源码来
绕过版本声明。

## claude-code-action/CVE-2026-47751

修复版新增 `src/github/operations/restore-config.ts`，可以在合成 Git 仓库中
真实执行从 base 恢复 `.claude/` 和 `.mcp.json`。漏洞版归档没有该模块；仅凭
模块不存在和 PR 配置仍在工作树中，不能证明真实 Action 已 checkout 并把配置
交给 Claude CLI，也不满足 PoC 必须执行真实代码的证据要求。

当前 harness 对漏洞版记录 `not_run`，不会伪造成功进程或把配置字符串当成产品
效果。恢复条件是为漏洞版固定可运行的真实 Action checkout/启动入口，并在不
连接 GitHub、Anthropic 或真实 secrets 的前提下完成完整攻击、修复和 benign 对照。
