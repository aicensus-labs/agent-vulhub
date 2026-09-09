# Gate PoC Execution on Healthchecks

长运行目标服务和依赖必须声明 Docker `healthcheck`，运行器只在必需服务 healthy 后执行 PoC；一次性实验需提供等价的启动成功条件和全局超时。健康检查失败、启动崩溃、超时及验证失败分别记录，避免把基础设施问题误判为修复阻断。

**Status**: accepted
