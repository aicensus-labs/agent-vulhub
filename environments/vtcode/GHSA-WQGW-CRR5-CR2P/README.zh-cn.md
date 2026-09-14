# vtcode / GHSA-WQGW-CRR5-CR2P

状态：草稿。本环境缺少稳定非交互触发前提，仓库内尚未复现，不能宣称已验证。

## 公告与机制

- 官方公告：`GHSA-WQGW-CRR5-CR2P`。
- 根因：漏洞版在 session 启动时自动加载工作区 `vtcode.toml`，将 workspace 提供的 `session_start` 命令交给 `sh -c` 执行，未绑定到该有效命令的逐命令批准。
- Agent 信任边界：仓库作者不应仅凭打开 Agent 会话获得无确认 shell 命令执行。
- 修复来源：`v0.145.0` 将 workspace 生命周期命令绑定到内容指纹，非交互模式未获批准时跳过。

## 前提

- 前提是攻击者可控制工作区根目录 `vtcode.toml`，并诱导用户启动或恢复该工作区中的 Agent 会话。
- 漏洞版无需用户逐命令批准；修复版要求对精确命令集的首次批准。
- 攻击 fixture 使用固定本地 marker 命令，无网络访问、无真实凭据读取。

## 版本与启动

漏洞版为 `v0.144.0` / `058ec4166eaea25bdbedb3f577c905a761cab823`；修复版为 `v0.145.0` / `9bbdc9123d4e01fa8f2e12e7abe341d4c69af66b`。
两版均可从固定源码与 vendored Cargo 依赖离线构建；`metadata.toml` 中的发布镜像 digest 仍为空，因此保持 draft。

Compose 中 `vulnerable` 与 `patched` profiles 分开使用；未指定 profile 不启动服务。镜像变量未配置时 Compose 会明确报错。此模板不暴露宿主端口，也不挂载主机数据。

## 机制复现

`reproduce.py` 目前不执行 TUI。上游 session_start 触发发生在交互式终端初始化路径；容器协议要求稳定非交互触发，否则无法区分 hook 执行与启动失败。
因此 PoC 记录前提不足并返回退出码 2，不使用 shell surrogate 冒充 VTCode。

完成实现后使用 `python3 -m runner reproduce vtcode/GHSA-WQGW-CRR5-CR2P --build --rounds 3`。
两脚本统一接受 `--context <context.json> --output <目录>`，详细字段见仓库 `docs/environment-contract.md`。
PoC 输出 `facts.json` 和效果文件；验证器只读证据，输出含 `target_ready` 及对应效果断言的 `verdict.json`。
镜像必须包含 Python 3 和 `/lab/` 下的脚本、fixtures；`runtime.mode` 选择 `oneshot` 或有 healthcheck 的 `service`。

## 端到端复现

`end_to_end.py` 保持退出码 2；在机制触发尚未解决前，真实模型端到端测试不适用。

## 验证与修复对照

`verify.py` 只核对证据完整性和上下文，在 PoC 明确未执行时返回 2。当前没有可验证效果文件，不输出 passed。

## 清理

默认运行器按每个测试的唯一 Compose project 清理容器、网络和 volume。
`--keep-on-failure` 保留失败项目，项目标识和 Compose 配置在结果目录中；仅清理该项目，不能使用全局 prune。

## 失败诊断

若后续找到稳定非交互入口，应先确认它确实进入上游 session_start 生命周期路径，再比较漏洞版 marker、修复版未批准时无 marker、benign 无 marker。
任何 TUI 启动失败、超时或缺少终端都不能算修复阻断。
启动失败、健康检查失败和超时都不能当作修复阻断。报告中应能定位到阶段、预期、实际和受控证据。

## 构建与输入

两版源码、vendored Cargo 依赖和 SHA-256 已记录在 `metadata.toml`，Dockerfile 使用 `cargo build --locked --offline`。
固定攻击和正常输入放入 `fixtures/` 并登记到 `fixtures/manifest.toml`。固定 seed、环境变量，说明无害效果与真实影响的关系。

## 隔离例外

默认无例外。确需例外时同时填写 `runtime.exceptions`、理由及最小范围，晋升由两位维护者审阅。

## 来源与许可

- 上游源码：`https://github.com/vinhnx/VTCode`，归档内保留上游 `LICENSE`。
- 基础镜像：`codex-universal@sha256:9ba2aa8b4fa406a22c8c9284e1ee6bcb641c5f93a0c4933e58268a53a212d359`。
