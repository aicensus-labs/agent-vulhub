# Keep Docker Reproduction Out of Pull Request CI

Pull Request CI 只执行索引、元数据、Dockerfile 静态检查和仓库工具测试，不拉取或运行漏洞服务。真实 Docker 复现通过维护者触发的手动或定时工作流在隔离 VM 中执行，并保存三轮证据；外部贡献者的 Pull Request 不自动触发该工作流，以避免不受信任代码获得容器运行权限或网络访问。

**Status**: accepted
