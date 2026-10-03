# Agent Vulhub

面向 Agent/MCP 软件的漏洞复现环境集合。每个环境固定受影响版本和修复版本，并提供 Docker 配置、复现脚本、验证器和测试输入，用于在隔离环境中检查漏洞触发路径和修复行为。

> [!WARNING]
> 本项目与官方 Vulhub 无关。PoC 仅用于授权测试和安全研究，请在一次性 Linux 环境中运行，不要使用生产凭据或连接生产服务。当前环境均为 `draft`，复现结果不等同于完整安全评估。

## 项目状态

截至当前仓库快照：

| 项目 | 数量 |
| --- | ---: |
| 收录环境 | 276 |
| 机制检查通过 | 275 |
| 尚未运行 | 1 |

## 环境内容

环境按产品和漏洞编号组织：

```text
environments/<product>/<CVE-or-GHSA>/
├── metadata.toml       # 版本、来源和验证状态
├── Dockerfile          # 漏洞版和修复版镜像构建配方
├── compose.yaml        # 本地运行配置
├── reproduce.py        # 复现入口
├── verify.py           # 独立验证器
└── fixtures/            # 固定输入和测试材料
```

源码版本、基础镜像和构建依赖记录在 `metadata.toml` 中。默认从固定输入本地构建，不依赖预构建镜像；首次构建需要联网，之后可以使用 `--offline` 复用缓存。

## 快速开始

静态检查需要 Python 3.11+。完整复现需要 Linux amd64、Docker Engine 和 Compose 插件。

```sh
git clone https://github.com/aicensus-labs/agent-vulhub.git
cd agent-vulhub

python3 -m runner list
python3 -m runner check
python3 -m runner lint
```

运行一个环境：

```sh
python3 -m runner reproduce mcp-filesystem/CVE-2025-53109 --build --rounds 1
```

需要重复验收时，将 `--rounds` 调整为 `3`。离线运行可以追加 `--offline`，前提是所需输入已经在本地缓存。

## 仓库导航

- [环境索引](docs/environments.md)：按产品和 CVE/GHSA 浏览环境
- [环境注册表](environments.toml)：机器可读的环境清单
- [复现工作流](docs/reproduction-workflow.md)：构建、运行和验收步骤
- [环境执行协议](docs/environment-contract.md)：输入、隔离、证据和状态约定
- [贡献指南](CONTRIBUTING.md)：新增或修改环境的要求
- [漏洞图解契约](docs/diagram-contract.md)：机制图字段和校验规则
- [设计决策](docs/adr/)：工具链和仓库行为的记录

## 贡献

请先阅读[贡献指南](CONTRIBUTING.md)，再创建环境或提交修复。环境应保留上游来源、版本、许可证信息和固定哈希，并提供可独立检查的复现证据。

提交前运行：

```sh
python3 -m runner check
python3 -m runner lint
python3 -m unittest discover -s tests -v
```

## 安全与许可

漏洞环境应在隔离的、可丢弃的主机或虚拟机中运行。涉及宿主机文件、权限提升、网络访问或逃逸的案例，不要直接在日常工作站上执行。

本仓库目前没有项目级开源许可证。许可证明确前，不应默认复制、修改或再分发仓库内容；环境中引用的第三方源码和依赖仍受其各自许可证约束。
