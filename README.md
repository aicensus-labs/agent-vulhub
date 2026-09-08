# Agent Vulhub

Agent 安全漏洞复现环境库。每个 CVE 保存独立环境、攻击输入、复现步骤、修复对照和验证证据。

当前是仓库骨架，环境索引为空；尚未提供或验证任何真实 CVE。仓库名称为暂定名，不代表与 Vulhub 官方存在隶属关系。

## 快速开始

索引管理只需 Python 3.11+，无第三方依赖，不需要 Docker：

```sh
python3 -m runner list
python3 -m runner check
python3 -m unittest discover -s tests -v
```

新增草稿时，用已核实的产品目录名和真实 CVE 编号替换参数：

```sh
python3 -m runner new <product> <CVE-YYYY-NNNN>
```

命令创建 `environments/<product>/<CVE-ID>/` 并注册到 `environments.toml`。它不会联网、安装依赖、启动容器或执行复现脚本。新建条目均为 `draft`，不代表确认漏洞。

## 目录

```text
environments.toml             环境索引，身份由 product/CVE 构成
environments/                 真实 CVE 环境，目前为空
templates/environment/        环境模板，不参与索引和验证计数
runner/                       索引、静态检查和草稿生成 CLI
docs/                         收录、验证及 AgentSec 关联约定
tests/                        仓库工具测试，不是漏洞复现测试
.github/workflows/check.yml    静态检查与工具测试
```

每个环境采用相同结构：

```text
metadata.toml                 公告、版本、来源、运行需求和验证状态
README.zh-cn.md               原理、前提、复现及修复对照说明
compose.yaml                  漏洞版和修复版的独立 Compose profiles
Dockerfile                    需要自行构建时补全的配方
fixtures/                     模拟仓库、网页、工具输出及假数据
reproduce.py                  机制复现入口
end_to_end.py                 真实模型端到端入口
verify.py                     独立效果验证入口
.env.example                  运行变量示例，不含真实凭据
```

模板脚本会明确返回“未实现”和退出码 2。模板 Dockerfile 也拒绝构建；维护者须完成配方、实验边界和验收后才能运行。Compose 提供可解析的占位服务，但只有明确选择 profile 并设置镜像才可启动。

## 复现标准

机制复现与真实模型端到端复现分别记账。前者可以固定模型输出，但必须走真实漏洞代码路径；后者需要记录模型标识、参数、重复次数和攻击成功分母。

“通过”至少要有漏洞版效果、修复版阻断、正常任务成功三类证据。固定源码 commit 与镜像 digest，保留攻击前提和具体场景。详见 [环境规范](docs/environment-contract.md) 和 [收录流程](CONTRIBUTING.md)。

## 与 AgentSec 关联

以 CVE 和官方别名关联现有漏洞，独立保存环境加入时间与验证时间。只附加仓库路径、固定 commit 和验证状态，不将新环境当作当天新披露漏洞。详见 [关联约定](docs/agentsec-integration.md)。

本骨架没有设置开源许可证。正式公开分发前需由维护者选择许可证；引入第三方代码时须保留其许可和来源。
