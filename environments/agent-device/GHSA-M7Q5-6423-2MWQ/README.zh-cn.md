# agent-device / GHSA-M7Q5-6423-2MWQ

状态：机制复现已完成，并通过四场景三轮容器验收；保持 `draft`，等待固定发布镜像和维护者审阅。

## 公告与机制

- 官方公告：`GHSA-M7Q5-6423-2MWQ`。
- 根因：漏洞版允许项目 `agent-device.json` 中的 `daemonBaseUrl` 与用户环境中的 `AGENT_DEVICE_DAEMON_AUTH_TOKEN` 组合生效，client-backed 命令会把令牌发送到项目选择的远程端点。
- Agent 信任边界：仓库作者可影响项目配置，但不应获得用户级 daemon 凭据或选择其外发目标。
- 修复来源：`v0.20.4` 的项目配置校验拒绝 `daemonBaseUrl` 等连接字段，请求发出前失败。

## 前提

- 前提是用户环境已有合成认证令牌，并在包含攻击者配置的项目目录执行 `devices --json`。
- 攻击者仅控制项目内 `agent-device.json`；无需新增用户批准或宿主权限。
- 本实验只使用合成令牌 `poc-secret-token` 和容器内 127.0.0.1 接收器，不读取真实凭据。

## 版本与启动

漏洞版为 `v0.20.3` / `b4487f57a7e5c7aff2f50b573fa6bf95e32e0a17`；修复版为 `v0.20.4` / `95b4623461dbdd4b482bdb773a2e61718df8a006`。
两版均从固定源码与 Node 依赖离线构建；`metadata.toml` 中的发布镜像 digest 仍为空，因此保持 draft。

Compose 中 `vulnerable` 与 `patched` profiles 分开使用；未指定 profile 不启动服务。镜像变量未配置时 Compose 会明确报错。此模板不暴露宿主端口，也不挂载主机数据。

## 机制复现

`reproduce.py` 在容器内启动仅监听 127.0.0.1 的 HTTP 接收器，写入项目 `daemonBaseUrl`，执行完整上游 CLI `devices --json`，记录请求头、路径和退出状态，超时 30 秒。
攻击场景应看到 `GET /agent-device/health` 与 `POST /agent-device/rpc` 携带合成令牌；benign 场景不写项目配置。

完成实现后使用 `python3 -m runner reproduce agent-device/GHSA-M7Q5-6423-2MWQ --build --rounds 3`。
两脚本统一接受 `--context <context.json> --output <目录>`，详细字段见仓库 `docs/environment-contract.md`。
PoC 输出 `facts.json` 和效果文件；验证器只读证据，输出含 `target_ready` 及对应效果断言的 `verdict.json`。
镜像必须包含 Python 3 和 `/lab/` 下的脚本、fixtures；`runtime.mode` 选择 `oneshot` 或有 healthcheck 的 `service`。

## 端到端复现

本漏洞不需要真实模型参与即可验证机制，`end_to_end.py` 保持退出码 2，不执行端到端测试。

## 验证与修复对照

`verify.py` 独立读取 `facts.json` 与 `observation.json`，校验上下文、哈希和四组对照：漏洞版两个认证请求、修复版拒绝且零请求、benign 零请求以及目标可执行。最新三轮报告四组对照均通过；这仍是机制验收，不等于 `ready`。

## 清理

默认运行器按每个测试的唯一 Compose project 清理容器、网络和 volume。
`--keep-on-failure` 保留失败项目，项目标识和 Compose 配置在结果目录中；仅清理该项目，不能使用全局 prune。

## 失败诊断

如果漏洞版缺少两个请求，检查 CLI 构建、环境令牌和项目配置是否写入；如果修复版仍发出请求，检查版本与补丁 commit。
如果 benign 出现认证请求，说明配置泄漏到了无项目场景；若 CLI 超时或拒绝执行，先修启动前提，不能将失败解释为修复阻断。
启动失败、健康检查失败和超时都不能当作修复阻断。报告中应能定位到阶段、预期、实际和受控证据。

## 构建与输入

两版源码、Node 依赖归档和 SHA-256 已记录在 `metadata.toml`，Dockerfile 仅使用已校验输入并离线构建。
固定攻击和正常输入放入 `fixtures/` 并登记到 `fixtures/manifest.toml`。固定 seed、环境变量，说明无害效果与真实影响的关系。

## 隔离例外

默认无例外。确需例外时同时填写 `runtime.exceptions`、理由及最小范围，晋升由两位维护者审阅。

## 来源与许可

- 上游源码：`https://github.com/callstack/agent-device`，归档内保留上游 `LICENSE`。
- 基础镜像：`node@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3`。
