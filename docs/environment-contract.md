# 环境和验证约定

## 身份与版本

- 索引 `environments.toml` 的每条记录包含 `id` 和 `path`。
- `id` 为 `<product>/<CVE-ID>`，`path` 为 `environments/<product>/<CVE-ID>`。
- 同一 CVE 可以跨产品出现；同一个产品/CVE 可以在环境目录内维护多个 scenario。
- `metadata.toml` 是该环境的详细信息源。官方公告发布时间、加入仓库时间、实际验证时间是不同概念。
- 漏洞版和修复版分别记录产品版本、源码完整 commit SHA、镜像 digest。镜像 tag 不作为组件准确版本的唯一依据。

## 两层复现

| 层 | 可固定的输入 | 必须证明的内容 |
| --- | --- | --- |
| mechanism | 模型输出、工具参数、预先建立的会话状态 | 真实执行链发生所述权限/能力边界失效 |
| end_to_end | 攻击材料、任务、模型参数 | 真实模型读取攻击材料后形成完整攻击链 |

入口约定：`reproduce.py` 为机制复现；`end_to_end.py` 为真实模型复现；`verify.py` 独立读取测试证据。脚本在实验容器/VM 内执行，不默认在开发主机上运行。

完成环境后应在 README 列出每个入口的精确参数、执行位置、依赖和超时。骨架不假设所有产品都有 Python，也不自动把这些脚本注入任意目标镜像。

退出码：0 表示该入口完成且验收通过；1 表示验收失败；2 表示未实现、缺参数或环境不满足。启动失败、超时、模型拒绝服务均不能被记为修复阻断成功。

## 验收与证据

至少提供三个场景：

1. `vulnerable`: 攻击能产生预定的无害效果，例如在模拟边界外创建 canary 文件。
2. `patched`: 相同攻击输入不产生越界效果，且目标服务已正常就绪。
3. `benign`: 正常业务任务在两版都可完成。

结果建议输出 JSON，保存到被 Git 忽略的 `results/<environment>/<run-id>/`，并在需长期保留时将脱敏摘要放入环境目录中独立的证据文件：

```json
{
  "schema_version": 1,
  "environment_id": "<product>/<CVE-ID>",
  "scenario": "<scenario-name>",
  "layer": "mechanism",
  "started_at": "<UTC ISO-8601>",
  "source_commit": "<full-commit>",
  "image_digest": "<image@sha256:digest>",
  "platform": "<os/architecture>",
  "checks": {
    "vulnerable_effect_observed": null,
    "patched_effect_blocked": null,
    "benign_task_passed": null
  },
  "outcome": "not_run",
  "evidence": []
}
```

这只是结果格式约定，当前工具没有实现实验调度或结果签名验证。占位字段和 `null` 不能作为通过证据。真实模型实验另外保存模型标识、参数、运行次数、成功次数、失败/超时次数及成本，不只保存一次成功截图。

## 环境边界

默认 Compose 不发布端口、不挂载主机目录、不使用 host 网络或特权模式。需要额外能力时在该 CVE 的 README 解释具体原因并限定实验边界。真实模型测试需要联网时，写明必要的目的地及模拟外传接收器，使用假凭据。

CI 仅解析元数据和检查工具，不拉取镜像、不执行任何 environment 下的代码。后续自动复现应使用单独的临时执行机和独立工作流。
