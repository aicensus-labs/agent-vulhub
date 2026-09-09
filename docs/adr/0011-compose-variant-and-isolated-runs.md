# Compose Variants Run in Isolated Projects

每个环境用互斥的 `vulnerable`/`patched` profile 提供目标变体，依赖服务按需加入同一 Compose 项目；目标镜像携带 PoC、验证器和 fixtures，PoC 与验证器分别以一次性进程执行。运行器为每轮使用唯一 project 名和 volume，并在结束时销毁，以保证内部函数触发、服务入口和状态依赖都能在同一受控拓扑中完成且不互相污染。

**Status**: accepted
