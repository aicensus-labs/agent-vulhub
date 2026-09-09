# Keep Pinned Source as the Canonical Build Input

GHCR 只分发已验证的不可变镜像，不能替代源码。每个环境必须记录源码 URL、完整 commit、Dockerfile 和依赖约束，并支持从这些固定输入重建漏洞版与修复版；运行器可直接拉取 GHCR digest 加速复现，但必须保留并验证源码构建路径。

**Status**: accepted
