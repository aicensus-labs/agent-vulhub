# vtcode / GHSA-WQGW-CRR5-CR2P

状态：草稿，机制层已复现（三轮 12/12 通过）。TUI 交互层未复现，但审批闸门在引擎层且是非交互的，因此可直接驱动真实上游 `LifecycleHookEngine`。

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

TUI 交互层（`prompt_workspace_hook_approval` 的覆盖层）确实无法在容器内稳定驱动。但**审批闸门本身不在 TUI 里**：
它在 `LifecycleHookEngine` 上，且是非交互 API——`workspace_gated()` / `workspace_hooks_need_approval()` /
`run_session_start()` / `approve_workspace_hooks()`。上游自己的修复就附带了这个层面的测试
（`hooks/lifecycle/tests/workspace_hook_approval.rs`），本环境用同样方式挂载自己的模块并调用真实引擎。

- 漏洞版：`new_with_session` 没有 gated 参数，`run_session_start` 直接执行全部 hook，没有审批概念。
- 补丁版：存在工作区控制的 hook 内容时整个引擎被 gate，未审批前**所有** hook 都不执行，并给出 "not approved" 提示。

**阳性对照（必要）**：仅证明"hook 没跑"不够——一个把生命周期 hook 整个禁掉的假修复结果相同。
因此补丁版 attack 场景额外要求：用上游 `approve_workspace_hooks()` 审批后，同一命令集**必须确实执行**。

**benign 场景为何用 ungated 引擎**：补丁对*仓库来源*的 hook 一律要求审批，即使命令无害——这是有意的安全权衡，
不是回归。所以"合法仓库命令被拦"不能当作良性对照。真正要防的是修复过宽，故 benign 用 ungated（用户级）hook，
要求它在两版都照常执行。

平台适配：Rust 工具链（1.93.0，与仓库 `rust-toolchain.toml` 一致）作为 build input，**不修改基础镜像**
（否则会丢掉 `runtime.harness` 需要的 Python 3）；crates 已 vendored 且 SHA-256 固定，构建全程 `--network none`。
harness 作为 crate 内测试模块运行，因为 `LifecycleHookEngine` 的构造器是 crate 内部可见，外部 crate
无法在不放宽上游可见性的前提下组装同样的调用。

使用 `python3 -m runner reproduce vtcode/GHSA-WQGW-CRR5-CR2P --build --rounds 3`。
两脚本统一接受 `--context <context.json> --output <目录>`，详细字段见仓库 `docs/environment-contract.md`。
PoC 输出 `facts.json` 和效果文件；验证器只读证据，输出含 `target_ready` 及对应效果断言的 `verdict.json`。
镜像必须包含 Python 3 和 `/lab/` 下的脚本、fixtures；`runtime.mode` 选择 `oneshot` 或有 healthcheck 的 `service`。

## 端到端复现

`end_to_end.py` 保持退出码 2；TUI 触发层未复现，真实模型端到端测试不适用。

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
