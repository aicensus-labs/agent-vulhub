# Share the Build Context Across Vulnerable and Patched Variants

环境默认使用同一个 Dockerfile 和构建上下文，通过 variant 参数选择漏洞版与修复版各自固定的源码输入；通用依赖和实验脚本保持一致，减少对照漂移。若两个版本无法共用配方，可以拆分 Dockerfile，但必须说明差异并证明实验依赖可比。

**Status**: accepted
