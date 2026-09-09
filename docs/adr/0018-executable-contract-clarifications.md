# Distinguish Local Build Identity and Published Digests

本地源码构建产物用 Docker image ID 固定执行，正式 GHCR 产物用仓库 digest；运行器分别记录，避免要求每次本地实验都先上传镜像。这细化 ADR-0004，源码、依赖哈希和镜像内容标识仍不可浮动，相同输入不承诺逐字节相同产物。

每轮三类场景实际有四个测试，两版正常任务分别执行；每个测试创建新项目和 volume。静态 check 保持只读并拒绝旧 ready，refresh 或下一次执行命令完成降级。永久证据包保存可独立复核的小型事实与 verdict，以免 CI artifact 过期后无法审阅。

**Status**: accepted implementation clarification
