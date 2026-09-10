# Agent Vulhub

Agent 安全漏洞的 Docker 机制复现仓库。每个环境固定完整上游源码、依赖和镜像，提供 PoC、独立验证器、修复对照与可复核证据。

当前索引包含 6 个真实上游源码的 CVE 机制环境，均保持 `draft`，尚未宣称为 `ready` 或发布 GHCR 镜像。每个环境使用容器内 synthetic 效果验证漏洞路径和修复对照；合成 Docker 冒烟测试仅验证运行器，不构成漏洞复现证明。仓库名称为暂定名，与 Vulhub 官方无隶属关系。

已收录环境：`ios-simulator-mcp/CVE-2025-52573`、`node-code-sandbox-mcp/CVE-2025-53372`、`mcp-server-git/CVE-2025-68143`、`mcp-filesystem/CVE-2025-53109`、`mcp-filesystem/CVE-2025-53110` 和 `hackmd-mcp/CVE-2025-59155`。

## 使用

索引工具仅需 Python 3.11+ 标准库；构建和实验需要 Linux amd64 原生 Docker，以及支持 JSON config、--no-env-resolution、up --wait 的 Compose 插件。

```sh
python3 -m runner list
python3 -m runner check
python3 -m runner lint
python3 -m unittest discover -s tests -v
```

新增环境并完成配方与实验脚本后：

```sh
python3 -m runner new <product> <CVE-ID>
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
environments/           真实 CVE 环境（当前 6 个，均为 draft）
templates/environment/  环境配方、PoC、验证器和 fixture 模板
runner/                 索引、源码构建、Compose 编排、证据校验和晋升
tests/                  静态工具测试和显式 Docker smoke
docs/                   执行协议、设计记录和 ADR
results/                本地实验结果（Git 忽略）
.cache/sha256/          按哈希缓存构建输入（Git 忽略）
```

模板仍明确返回未实现，不能因存在模板文件而标记为成功。机制复现允许固定模型输出，但必须走真实漏洞代码路径；真实模型端到端复现另行记录。

## 文档与 CI

详见[执行协议](docs/environment-contract.md)、[收录流程](CONTRIBUTING.md)、[设计记录](docs/design-session.md)、[候选 CVE 选型](docs/cve-candidates.md)和[术语](CONTEXT.md)。

PR CI 只运行静态检查和工具测试。真实复现使用独立工作流，需要管理员配置受保护的 vulhub-lab environment 和一次性 VM runner；GHCR 登录和发布权限也需维护者配置。

工具链 Docker smoke 显式执行，需要缓存的固定 Python 镜像；该命令不会收录任何真实 CVE：

```sh
python3 -m tests.docker_smoke --base-image python@sha256:<digest> --exercise-failures
```

关联 AgentSec 时使用 CVE/官方别名，不把环境加入时间当作漏洞披露时间，见[关联约定](docs/agentsec-integration.md)。仓库尚未选择开源许可证；引入上游材料时保留来源与许可。
