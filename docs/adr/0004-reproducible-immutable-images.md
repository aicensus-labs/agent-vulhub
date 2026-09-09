# Build and Reference Immutable Experiment Images

每个 CVE 环境必须从仓库内 Dockerfile 和构建上下文生成漏洞版、修复版实验镜像；源码使用完整 commit SHA，基础镜像使用 digest，最终镜像 digest 写入 `metadata.toml`，Compose 与结果证据只引用不可变 digest。这样可以追溯构建来源并避免浮动标签改变复现含义。

**Status**: accepted
