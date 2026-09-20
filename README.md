# Agent Vulhub

Agent 安全漏洞的 Docker 机制复现仓库。每个环境固定完整上游源码、依赖和镜像，提供 PoC、独立验证器、修复对照与可复核证据。

当前索引包含 39 个真实上游源码的 CVE/GHSA 机制环境，均保持 `draft`，尚未宣称为 `ready` 或发布 GHCR 镜像。其中 31 个已完成 Linux amd64 容器内四场景三轮机制验收并通过，另有 8 个因平台、源码材料或前置条件问题保持 `not_run`。已验收环境使用容器内 synthetic 效果验证漏洞路径和修复对照；合成 Docker 冒烟测试仅验证运行器，不构成漏洞复现证明。仓库名称为暂定名，与 Vulhub 官方无隶属关系。

已收录环境：

- `agent-device/GHSA-M7Q5-6423-2MWQ`
- `factoryfloor/CVE-2026-88063`
- `hackmd-mcp/CVE-2025-59155`
- `ios-simulator-mcp/CVE-2025-52573`
- `mcp-filesystem/CVE-2025-53109`
- `mcp-filesystem/CVE-2025-53110`
- `mcp-server-git/CVE-2025-68143`
- `node-code-sandbox-mcp/CVE-2025-53372`
- `vtcode/GHSA-WQGW-CRR5-CR2P`
- `praisonai/CVE-2026-34955`
- `praisonai/CVE-2026-40149`
- `praisonai/CVE-2026-40156`
- `praisonai/CVE-2026-40158`
- `praisonai/CVE-2026-44334`
- `praisonai/CVE-2026-44339`
- `praisonai/CVE-2026-47391`
- `praisonai/CVE-2026-47395`
- `praisonai/CVE-2026-55527`
- `praisonai/CVE-2026-55530`
- `praisonai/CVE-2026-55532`
- `praisonai/CVE-2026-55540`
- `praisonai/CVE-2026-56833`
- `praisonai/CVE-2026-57117`
- `praisonai/CVE-2026-57120`
- `praisonai/CVE-2026-57125`
- `praisonai/CVE-2026-57129`
- `praisonai/CVE-2026-61428`
- `praisonai/CVE-2026-61439`
- `praisonai/CVE-2026-61445`
- `chainlit/CVE-2026-45018`
- `claude-code-action/CVE-2026-47751`
- `flowise/CVE-2026-70477`
- `mcp-atlassian/GHSA-wm45-qh3g-v83f`
- `mcp-gateway/GHSA-g53w-w6mj-hrpp`
- `mcp-server-kubernetes/CVE-2026-61459`
- `n8n/CVE-2026-86996`
- `omnigent/CVE-2026-62674`
- `open-webui/CVE-2026-87017`
- `openharness/CVE-2026-56696`

本批新增的 20 个 PraisonAI 环境和 10 个跨项目环境已固定漏洞版和修复版源码并完成静态校验；其中 24 个空壳环境已完成机制验收，8 个因前置条件不足或真实入口缺失保持 `not_run`。VT Code、Factory Floor 以及其余 blocker 环境不以静态材料或替身函数冒充复现结果。

## 使用

索引工具仅需 Python 3.11+ 标准库；构建和实验需要 Linux amd64 原生 Docker，以及支持 JSON config、--no-env-resolution、up --wait 的 Compose 插件。

```sh
python3 -m runner list
python3 -m runner check
python3 -m runner lint
python3 -m runner diagram --missing
python3 -m unittest discover -s tests -v
```

新增环境并完成配方与实验脚本后：

```sh
python3 -m runner new <product> <CVE-or-GHSA-ID>
python3 -m runner reproduce <product>/<CVE-ID> --build --rounds 3
```

--build 从固定源码构建两版镜像，然后运行四个独立测试：漏洞版攻击、修复版攻击，以及两版各自的正常任务。默认 1 轮，晋升 ready 至少 3 轮，每个测试使用全新容器和数据。

也可先 build，再通过 --images 指定输出的 build.json 复用本地不可变镜像；已有 GHCR 镜像的环境省略 --build 即按元数据 digest 拉取。--offline 要求所有输入和镜像已缓存。

```sh
python3 -m runner build <product>/<CVE-ID>
python3 -m runner reproduce <product>/<CVE-ID> --images <build.json> --offline
python3 -m runner reproduce <product>/<CVE-ID> --scenario vulnerable --keep-on-failure
```

## 结果与状态

结果保存在 results/<product>/<CVE-ID>/<run-id>/，有 report.json、各测试 result.json、独立 verdict、效果证据及日志。退出码 0/1/2/3 分别表示所选测试通过、实验失败、未运行/前提不足、基础设施或证据错误。缺少证据、服务启动失败不能当作修复成功。

ready 表示已由维护者审阅并通过三轮完整验收；缺修复对照的环境保持 draft。执行材料变化会使旧证据失效，check 拒绝旧 ready，refresh 或下一次执行命令降级并保留历史。

```sh
python3 -m runner promote <product>/<CVE-ID> --report <report.json> --reviewer <login> --reviewed
python3 -m runner refresh
```

## 目录

```text
environments.toml       环境索引
environments/           真实 CVE/GHSA 环境（当前 39 个，均为 draft）
templates/environment/  环境配方、PoC、验证器、fixture 和图解模板
runner/                 索引、源码构建、Compose 编排、证据校验、图解渲染和晋升
tests/                  静态工具测试和显式 Docker smoke
docs/                   执行协议、设计记录和 ADR
results/                本地实验结果（Git 忽略）
.cache/sha256/          按哈希缓存构建输入（Git 忽略）
```

模板仍明确返回未实现，不能因存在模板文件而标记为成功。机制复现允许固定模型输出，但必须走真实漏洞代码路径；真实模型端到端复现另行记录。

## 漏洞图解

每个环境用 `diagram.toml` 作为图解的单一来源，说明漏洞机制、触发过程和涉及的每个主体。图用 Mermaid 渲染：时序图表达触发过程，流程图表达主体与信任边界。AI 或维护者只编辑结构化字段，渲染器负责生成 `diagram/mechanism.mmd`、`diagram/entities.mmd` 和 README 中的图解区块，因此不会出现只画不解释的孤立主体。

图只描述**漏洞本身**——攻击者可控输入、受影响的上游组件、被调用的工具、被读写的存储、受控效果落点。运行器、`verify.py`、结果卷、容器编排、协议替身这类复现工具链不属于漏洞的触发过程，schema 里也没有对应取值，写不进去；替身与无害效果保留并标 ⚠。

```sh
python3 -m runner diagram <product>/<CVE-ID>          # 渲染并更新 README 图解区块
python3 -m runner diagram --all                       # 渲染所有已有图解的环境
python3 -m runner diagram --missing                   # 列出尚未补图的环境
python3 -m runner diagram <product>/<CVE-ID> --check  # 只报告漂移，不写入
```

`runner check` 会静态校验每份图解：主体必须有职责说明，步骤编号必须连续并引用已声明主体，必须标出漏洞版/修复版的分歧步骤，引用 `fixtures/...` 的证据必须真实存在。图解是说明性文档，不参与输入指纹，也不能替代实验证据。

格式与字段见[漏洞图解契约](docs/diagram-contract.md)和 [ADR-0020](docs/adr/0020-diagram-source-and-rendering.md)。目前 3 个环境已覆盖，其余 36 个待补；`diagram.toml` 当前是可选增强，全量覆盖后切换为强制要求。

## 大模型生成 PoC

仓库已实现统一 Agent-PoC 任务打包和候选执行命令，但当前还没有环境完成 Agent-PoC Adapter 的验收。使用 `agent-task` 生成 Level 1 任务包，再用 `agent-evaluate` 在隐藏的 vulnerable/patched 对照中执行候选；修复版、reference PoC、验证器和预期效果不进入任务包。同一候选按 vulnerable/patched/benign 四个场景执行，并由独立验证器判断实际效果。

维护者编写的 `reproduce.py` 仍是机制基准 PoC，不得冒充模型生成结果。详细协议见 [ADR-0019](docs/adr/0019-agent-generated-poc-evaluation.md) 和[环境执行协议](docs/environment-contract.md#agent-poc-任务与候选执行协议)。

## 文档与 CI

详见[执行协议](docs/environment-contract.md)、[收录流程](CONTRIBUTING.md)、[设计记录](docs/design-session.md)、[候选 CVE 选型](docs/cve-candidates.md)和[术语](CONTEXT.md)。

PR CI 只运行静态检查和工具测试。真实复现使用独立工作流，需要管理员配置受保护的 vulhub-lab environment 和一次性 VM runner；GHCR 登录和发布权限也需维护者配置。

工具链 Docker smoke 显式执行，需要缓存的固定 Python 镜像；该命令不会收录任何真实 CVE：

```sh
python3 -m tests.docker_smoke --base-image python@sha256:<digest> --exercise-failures
```

关联 AgentSec 时使用 CVE/官方别名，不把环境加入时间当作漏洞披露时间，见[关联约定](docs/agentsec-integration.md)。仓库尚未选择开源许可证；引入上游材料时保留来源与许可。
