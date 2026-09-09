# Default to Restricted Container Isolation

复现实验默认使用内部网络、无端口发布、无宿主机目录挂载、无特权或 `host` 网络，并丢弃全部 capabilities、启用 `no-new-privileges` 和资源限制；证据写入受控结果位置。需要突破边界的 CVE 必须记录具体理由和最小范围，以确保漏洞测试不会把真实宿主机资源当成攻击目标。

**Status**: accepted
