# 首版实现与验证记录

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
