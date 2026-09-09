# Separate the Reproducer from the Verifier

每个环境将 `reproduce.py` 定义为运行真实上游代码并产生事实证据的机制层 PoC，将 `verify.py` 定义为独立读取证据并判定 `vulnerable`、`patched`、`benign` 条件的验证器；两者随实验镜像在容器内执行，宿主机只做编排和结果收集。这样既能直接调用内部模块，又避免用 PoC 自报的退出码替代可复核的效果检查。

**Status**: accepted
