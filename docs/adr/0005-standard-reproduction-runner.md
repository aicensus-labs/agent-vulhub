# Use One Standard Reproduction Runner

所有 CVE 环境通过仓库运行器的统一入口完成固定镜像检查或构建、三场景编排、验证、证据收集和清理；环境脚本只实现 CVE 特定逻辑，CI 的 `check` 仍只做静态检查。统一生命周期让超时、未就绪和残留容器等失败状态得到一致处理，也避免每个环境维护无法互操作的启动命令。

**Status**: accepted
