# Agent Vulhub

面向 Agent/MCP 生态的 CVE/GHSA 机制复现环境集合。每个环境包含固定的上游源码、Docker 配置、PoC 和独立验证器，用于在隔离环境中复核漏洞触发路径与修复对照。

> [!WARNING]
> 本项目与官方 Vulhub 无隶属关系。当前所有环境均为 `draft`，实验结果只代表记录的平台和固定材料，不能视为生产安全结论。

## 当前状态

| 指标 | 数量 |
| --- | ---: |
| 已收录环境 | 39 |
| 机制验收通过 | 31 |
| 尚未运行 | 8 |
| `ready` 环境 | 0 |
| 已发布 GHCR 镜像 | 0 |

“机制验收通过”不等于 `ready`：`ready` 还要求固定的可分发镜像、至少三轮完整验收和维护者审阅。验证使用容器内的 synthetic 效果和修复对照；Docker smoke 只验证工具链，不构成漏洞复现证明。

## 快速开始

索引和静态检查只需要 Python 3.11+。完整复现需要 Linux amd64 原生 Docker 和支持 Compose 的插件。

```sh
python3 -m runner list
python3 -m runner check
python3 -m runner lint
python3 -m unittest discover -s tests -v
```

运行一个已完成机制验收的环境：

```sh
python3 -m runner reproduce mcp-filesystem/CVE-2025-53109 --build --rounds 1
```

`--build` 会从固定输入构建漏洞版和修复版镜像，再分别运行攻击和正常任务。完整验收流程见[复现与图解工作流](docs/reproduction-workflow.md)。

## 环境

- [环境索引](docs/environments.md)：按产品和 CVE/GHSA 浏览全部环境
- [原始环境注册表](environments.toml)：机器可读的唯一索引
- [漏洞环境目录](environments/)：每个环境的配方、PoC、验证器和 fixtures

## 文档

- [环境执行协议](docs/environment-contract.md)：输入固定、隔离、证据和状态定义
- [新增环境](CONTRIBUTING.md)：收录、验收和提交要求
- [漏洞图解契约](docs/diagram-contract.md)：机制图的来源和校验规则
- [Agent-PoC 评测设计](docs/adr/0019-agent-generated-poc-evaluation.md)：实验性 Agent 生成 PoC 流程
- [设计决策](docs/adr/)：仓库工具链和验证规则的 ADR

## 安全边界

漏洞环境默认使用容器隔离，只允许受控的 synthetic 效果。涉及宿主逃逸、额外网络、权限或挂载的案例必须使用独立实验 VM，并在元数据中记录例外。不要在真实主机凭据或生产环境上运行 PoC。

仓库当前尚未声明开源许可证。在许可证明确之前，不应默认将本仓库内容视为可自由再分发；各环境引用的上游源码和材料仍以其原始许可证为准。

## 参与贡献

欢迎提交新的环境、修复现有复现或改进工具链。请先阅读[贡献指南](CONTRIBUTING.md)和[环境执行协议](docs/environment-contract.md)，并保留上游来源、版本和许可证信息。
