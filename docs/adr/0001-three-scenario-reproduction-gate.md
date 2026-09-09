# Require Three Scenarios for a Passing Reproduction

每个 CVE 环境的 Docker 复现必须自动完成 `vulnerable`、`patched` 和 `benign` 三类场景，并汇总可核查证据后才能通过。这样可以区分漏洞效果、修复阻断和服务本身不可用；单独的攻击成功或进程退出码不足以证明复现质量。

**Status**: accepted
