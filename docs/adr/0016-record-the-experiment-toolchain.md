# Record the Complete Experiment Toolchain

每份复现结果必须记录 runner commit/version、Docker Engine 版本、Compose 版本、宿主平台和实验镜像 digest。runner、验证器或容器工具链发生影响实验语义的变化时，既有 `ready` 证据失效并需重新完成三轮验收，避免把同一镜像在不同执行器上的结果混为一谈。

**Status**: accepted
