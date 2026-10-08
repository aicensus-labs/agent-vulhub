# PraisonAI Source-Boundary Review

日期：2026-09-17。

这份记录保留早期版本核查中发现的源边界问题。前四个环境后来已改用重新核对的
版本对照并补齐真实机制脚本，现已完成四场景三轮容器验收，因此不再属于当前
blocker 索引；metadata 仍保持 draft，等待发布镜像和维护者审阅。

## CVE-2026-34955

早期的 v4.5.96/v4.5.97 对照没有对应修复差异。当前环境使用
v4.5.87/v4.5.128，并直接调用上游 SubprocessSandbox.execute，对照 shell
解释执行和修复版阻断。

## CVE-2026-40149

早期的 v4.5.127/v4.5.128 方向不可信。当前环境使用
v4.5.124/v4.5.128，通过真实 gateway route 对照匿名 allow-list 修改和
认证保护。

## CVE-2026-40156

早期的 v4.5.127/v4.5.128 不能构成对照。当前环境使用
v4.5.117/v4.6.32，通过真实 ToolResolver 对照隐式 tools.py 导入和显式
PRAISONAI_ALLOW_LOCAL_TOOLS opt-in。

## CVE-2026-40158

早期只观察到 v4.5.128 删除检查代码，不能单独作为修复证据。当前环境使用
v4.5.117/v4.6.32，以真实 direct executor 的 AST 属性边界作为对照；该对照已
完成四场景三轮容器验收。

## CVE-2026-61445（已解除）

漏洞版 v4.6.77 的 `AICoder.apply_llm_response()` 已通过真实调用确认会将
model-shaped `write_to_file` 请求写到 workspace 外，正常 workspace 内写入也
能完成。但官方修复 tag v4.6.78 的同一模块包含语法错误：
`if any(token in cmd for token in (..., ">"):` 缺少右括号，模块无法导入。
后续可访问的 v4.6.79--v4.6.94 仍保留该错误；更晚的上游提交直接移除了这个
legacy UI 模块，不能作为同一路径的修复版对照。

当前环境保留固定的 v4.6.77/v4.6.78 源码。经维护者确认后，新增独立、固定 SHA-256 的
`praisonai-v4.6.78-aicoder-syntax-repair.patch` 作为构建输入：patched 镜像仍从
未修改的官方 v4.6.78 归档构建，只在构建阶段补上第 177 行缺失的右括号，漏洞版不应用。
这使官方修复逻辑可执行，同时明确这是本仓库的派生对照构建，不是官方重新发布物。

2026-10-08 已完成 Linux amd64 三轮四场景验收，12/12 case 通过：漏洞版攻击产生越界
写入，patched 版由真实 AICoder 拒绝路径穿越，两版 benign 写入均成功。报告归档在
`environments/praisonai/CVE-2026-61445/evidence/20261008T084307Z-a13ac036f815/`。

## 当前恢复条件

前四项的源版本选择已更新；61445 的原始上游归档阻塞已通过本地派生对照解除。剩余条件是
固定依赖可离线构建、四场景连续三轮通过，以及维护者审阅证据和来源。
