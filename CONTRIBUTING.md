# 新增漏洞环境

完整的分步工作流、每一步的验收标准和踩坑速查见[漏洞复现与图解工作流](docs/reproduction-workflow.md)。下面是可以直接照着勾的清单。

1. 核对官方 CVE/GHSA、受影响版本和修复来源。重新判断 Agent 关联性，不直接照搬现有数据库的自动标签。
2. 使用 `python3 -m runner new <product> <CVE-ID>` 创建草稿。产品目录用小写字母、数字和连字符，CVE 用大写规范编号。
3. 填写 `metadata.toml`、README、镜像配方和 fixtures。保留第三方材料原始链接及许可。模板中的占位字符串必须替换。
4. 实现 `reproduce.py` 和 `verify.py` 的标准参数及证据协议。PoC 执行产品，验证器独立读证据；真实模型 `end_to_end.py` 可选，不伪造结果。
5. 在 `fixtures/manifest.toml` 固定攻击及正常输入哈希；在 `build.inputs` 固定源码归档、依赖的 URL 和哈希。Dockerfile 必须能从缓存输入禁网安装完整产品。
6. 使用 `runner reproduce <id> --build --rounds 3` 在独立 Linux amd64 环境验收，两版攻击和两版正常任务每轮各跑一次。阅读失败原因和日志，不隐藏失败后重试。
7. 编写 `diagram.toml` 说明漏洞机制、触发过程和涉及的每个主体，再运行 `runner diagram <id>` 渲染时序图、主体图和 README 图解区块。图只写漏洞本身（攻击者可控输入、受影响组件、被调用的工具、被读写的存储、受控效果落点），不要写运行器、`verify.py`、结果卷、容器编排、协议替身等复现工具链；主体必须有职责说明，步骤必须按真实 `reproduce.py` 路径编号，并标出漏洞版/修复版的分歧步骤；引用 `fixtures/...` 的证据必须真实存在。字段和规则见[漏洞图解契约](docs/diagram-contract.md)。
8. 需要分发时显式运行 `runner publish <id> --images <build.json> --repository ghcr.io/<owner>/<package>`，将输出 digest 写回元数据，再使用这些正式镜像完成验收。
9. 维护者审阅公告、代码、配方及完整证据，确认脱敏后执行 `runner promote <id> --report <report.json> --reviewer <login> --reviewed`。隔离例外需两位不同审阅者，用两次 `--reviewer` 记录。
10. 运行 `python3 -m runner check`、`python3 -m runner lint` 和工具测试，再提交明确的环境目录和索引变更。

## 大模型 PoC 评测材料

新增 Agent-PoC 适配时，不要把修复版、reference PoC、验证器或预期结论放入 Level 1 任务包。环境只声明候选格式、入口、目标接口和受控效果采集方式；构建、隔离、四场景执行、清理和失败分类由统一 runner 负责。候选退出码不是漏洞证据，必须复用独立验证器和 `facts.json`/`verdict.json` 协议。Adapter 未完成独立效果采集审阅前，`verification.agent_poc.adapter_status` 必须保持 `not_run`，不能改成 `accepted`。

Agent-PoC 评测不能替代机制复现或 `ready` 晋升要求。实现前先阅读 [ADR-0019](docs/adr/0019-agent-generated-poc-evaluation.md) 和[环境执行协议](docs/environment-contract.md#agent-poc-任务与候选执行协议)，并明确记录 Agent、模型、工具链和任务 manifest 哈希。

`draft` 表示未完成，缺上游修复也可保留草稿；`ready` 表示同组固定镜像三轮完整验收且已经维护者审阅，仅适用于记录的平台。材料变化会使证据失效；`check` 拒绝旧 ready，`refresh` 或下次执行命令降为 draft，并保留历史。

本地审阅者字段不提供身份认证；仓库管理员应通过受保护分支和平台审阅规则限制晋升权限。静态检查不审计脚本行为、不验证公告真实性，也不证明 Docker 隔离有效。永久证据包须独立可复核，不能依赖 90 天后可能过期的 CI 日志。

涉及宿主逃逸的案例使用独立 VM；容器内的“工作区外”测试应指向 VM/容器内部的模拟目录。不要把真实主机目录当作攻击目标。
