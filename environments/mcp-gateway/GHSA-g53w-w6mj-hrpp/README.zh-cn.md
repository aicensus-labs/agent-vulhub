# mcp-gateway / GHSA-g53w-w6mj-hrpp

状态：`draft`，阻塞。源码和公告已完成初步核查，但缺少可独立启动的 Envoy/ext_proc 部署入口，不构成漏洞验收结果。

## 公告与机制

漏洞点位于 Envoy `ext_proc` 与 MCP Gateway router 的组合部署：未认证 initialize/hair-pin 路径信任 `mcp-init-host` 并改写上游 `:authority`，从而绕过 broker 的 JWT/capability 过滤。上游仓库提供的是由 Istio EnvoyFilter 生成的部署材料，不是可直接运行的独立 bootstrap 和 ext_proc 测试入口。

## 前提

需要真实 Gateway router、Envoy ext_proc、注册后端和受控 JWT/router-key 请求。假上游本身可以是 synthetic receiver，但不能用自建 Envoy 配置替换上游部署语义。

## 版本与启动

TODO：补全 metadata、Dockerfile/镜像 digest 和 Compose，再写出精确启动命令。

Compose 中 `vulnerable` 与 `patched` profiles 分开使用；未指定 profile 不启动服务。镜像变量未配置时 Compose 会明确报错。此模板不暴露宿主端口，也不挂载主机数据。

## 机制复现

当前不能在仓库协议内稳定执行。手写 Envoy bootstrap、ext_proc 服务和假后端会重新定义部署面，无法证明结果来自固定 Gateway 版本的真实组合。`reproduce.py` 保持退出码 2，不执行 router surrogate。

完成实现后使用 `python3 -m runner reproduce mcp-gateway/GHSA-g53w-w6mj-hrpp --build --rounds 3`。
两脚本统一接受 `--context <context.json> --output <目录>`，详细字段见仓库 `docs/environment-contract.md`。
PoC 输出 `facts.json` 和效果文件；验证器只读证据，输出含 `target_ready` 及对应效果断言的 `verdict.json`。
镜像必须包含 Python 3 和 `/lab/` 下的脚本、fixtures；`runtime.mode` 选择 `oneshot` 或有 healthcheck 的 `service`。

## 端到端复现

该漏洞与模型无关；真实模型不能补齐 Envoy/ext_proc 前提，因此端到端测试不适用。

## 验证与修复对照

当前没有 target-ready 事实，不能输出 passed。恢复条件是上游提供独立 bootstrap/fixture，或维护者接受隔离的 Envoy 集成测试环境，并补齐两版真实部署材料。

## 清理

默认运行器按每个测试的唯一 Compose project 清理容器、网络和 volume。
`--keep-on-failure` 保留失败项目，项目标识和 Compose 配置在结果目录中；仅清理该项目，不能使用全局 prune。

## 失败诊断

Envoy/ext_proc 启动失败、缺少生成的 EnvoyFilter 或后端未注册都只能归为前提不足；不能把它们当成修复阻断。恢复实现后需分别检查 router-key、JWT validator、`:authority` 重写及正常 MCP 请求。
启动失败、健康检查失败和超时都不能当作修复阻断。报告中应能定位到阶段、预期、实际和受控证据。

## 构建与输入

TODO：填写两版源码 archive、完整 commit，记录 `build.inputs` 中每个下载的 SHA-256；依赖安装必须支持禁网构建。
固定攻击和正常输入放入 `fixtures/` 并登记到 `fixtures/manifest.toml`。固定 seed、环境变量，说明无害效果与真实影响的关系。

## 隔离例外

默认无例外。确需例外时同时填写 `runtime.exceptions`、理由及最小范围，晋升由两位维护者审阅。

## 来源与许可

源码、版本、commit、归档哈希和基础镜像记录在 `metadata.toml`；阻塞原因另见 `docs/blockers-platform-and-materials.md`。当前不声明任何镜像或机制验收通过。
