# AgentSec 候选到复现环境的自动化流水线

本文说明如何把外部 AgentSec-Daily checkout 里的 `agent_unique` 漏洞自动转成
本仓库格式的复现环境，包括 `mcp-filesystem/CVE-2025-53109` 那样的结构化图解。

设计参考了 [CVE-Factory](https://github.com/livecvebench/CVE-Factory)（[论文](https://arxiv.org/abs/2602.03012)、
[架构文档](https://github.com/livecvebench/CVE-Factory/blob/main/docs/architecture.md)）：
把「复现一个 CVE」这件大任务拆成彼此隔离的生成阶段，再用**客观脚本**而不是 agent 自述把它们
逐步耦合回去。本仓库已有的 `runner check/lint/build/reproduce` 就是这套客观关卡，缺的只是
候选抽取和阶段编排。

## 能自动化的和不能自动化的

| 环节 | 能否自动 | 说明 |
| --- | --- | --- |
| 候选抽取与去重 | ✅ 完全自动 | 只读 AgentSec SQLite，确定性筛选 |
| 草稿骨架与图解骨架 | ✅ 完全自动 | `runner harvest --scaffold` |
| 队列、进度、关卡编排 | ✅ 完全自动 | `runner batch`，进度持久化在 `state.json`，可恢复 |
| 漏洞机制研究 | ⚠️ agent + 一手来源 | 必须读 advisory、修复提交和真实源码 |
| `diagram.toml` 内容 | ⚠️ agent 撰写 + 静态校验 | 渲染自动，内容不可凭空生成 |
| `reproduce.py` / `verify.py` | ⚠️ agent 撰写 + 容器验收 | 必须真实调用上游代码 |
| 三轮四场景验收 | ✅ 命令自动，结论需人审 | `runner reproduce --rounds 3` |
| 晋升 `ready` / 发布镜像 | ❌ 人工 | 见 `docs/environment-contract.md` |

agent 环节可以用并行 subagent 扇出：每个候选的 brief 是自包含提示词，互不依赖，
因此可以按 wave 并行推进（实测 6 个候选并行 analyze，其中 4 个产出可核对事实）。

**关键诚实性约束**：流水线产出的任何东西在通过验收前都是 `draft` + `not_run`。
候选 provenance、图解、草稿骨架都不构成「漏洞已复现」的证据。机制复现与真实模型端到端
分别记录，模拟模型不算端到端成功。批量驱动也不会替 agent 阶段背书——产出文件不存在时
只报 `awaiting-agent`。

**候选中有一部分本就不可复现**，这不是流水线失败。实测一类是闭源产品（Cursor IDE 无源码
仓库与修复提交）、一类是闭源托管服务且厂商未提供补丁（Sentry Seer）。这类候选的
`analyze` 阶段应当如实写 `status = "error"` 并说明缺什么，关卡会如实判失败。

## 六个阶段

阶段定义在 `runner/factory.py`，与 CVE-Factory 的对应关系：

| 阶段 | CVE-Factory | 产出 | 客观关卡 |
| --- | --- | --- | --- |
| `analyze` | Analyzer | `research/<env>/public.md` | 六节齐全 + 结果文件 `continue` |
| `generate` | Generator | `diagram.toml`、`reproduce.py`、`fixtures/` | 图解 schema 校验、无 TODO、无漂移、PoC 非模板 |
| `build` | Builder | `Dockerfile`、`metadata.toml` 的 `build.inputs` | `build.inputs` 合法、Dockerfile 非模板、`runner lint` |
| `validate` | Validator | 漏洞版攻击与正常任务通过 | `runner reproduce --build --scenario vulnerable` |
| `solve` | Solver | `verify.py`、修复对照 | `runner reproduce --build --rounds 3` |
| `check` | Checker | QA 记录 | `runner check` + `diagram --check` |

CVE-Factory 的几个核心设计被保留：

- **上下文隔离**：每个阶段是一份独立的 brief（`research/<env>/brief-<stage>.md`），
  阶段之间只通过蒸馏过的 Markdown 传递事实，不共享对话历史。
- **信息不对称（盲建）**：`build` 阶段的 brief 明确禁止阅读 `reproduce.py`、`verify.py`、
  `fixtures/`，避免「照着断言去凑环境」。这与本仓库 ADR-0019 的 Level 1 任务包同源。
- **客观验收**：`factory gate` 运行本仓库自己的命令并记录退出码，agent 的自述不算通过。
- **结果协议**：每阶段写 `<stage>-res.toml`，状态为 `continue` / `error` / `pause`；
  `error` 表示信息不足或机制不可复现，必须说明缺什么，不允许编造。

本仓库比 CVE-Factory 多出的一层是**结构化图解契约**：图由 `diagram.toml` 单一来源渲染，
主体类型和阶段枚举在 schema 上就排除了复现工具链，见 `docs/diagram-contract.md`。

## 使用

### 1. 抽取候选并生成草稿

```sh
: "${AGENTSEC_DAILY_ROOT:?set to the AgentSec-Daily checkout root}"
DB="$AGENTSEC_DAILY_ROOT/integrate-db-frontend/data/agentsec_vulnerabilities.sqlite3"

# 盘点：只写候选 provenance，不建环境
python3 -m runner harvest --db "$DB" --out staging

# 批量建草稿（默认跳过已收录的标识与别名）
python3 -m runner harvest --db "$DB" --out staging --limit 10 --scaffold

# 指定一个漏洞，强制复用已有产品目录
python3 -m runner harvest --db "$DB" --out staging \
  --identifier CVE-2026-40111 --product praisonai --scaffold
```

筛选口径：有效 specificity（`vulnerability_metadata` 优先，回退 `analysis_results`）
为 `agent_unique`、推荐为 `push`、`research_value >= 4`；按 canonical identifier 去重，
别名与 references 中的标识参与覆盖率比对。

### 2. 逐阶段推进

```sh
export AVH_ROOT=$PWD/staging
ID=praisonai/CVE-2026-40111

python3 -m runner factory brief "$ID" --stage analyze   # 生成 agent brief
python3 -m runner factory gate  "$ID" --stage analyze   # 跑客观关卡
python3 -m runner factory status "$ID"                  # 查看六阶段状态

# 需要 Docker 的阶段必须显式 --execute
python3 -m runner factory gate "$ID" --stage build    --execute
python3 -m runner factory gate "$ID" --stage validate --execute
python3 -m runner factory gate "$ID" --stage solve    --execute
```

每个 brief 是自包含的 agent 提示词：Role / Goal / 输入事实 / 资源与命令 / 必须产出 /
验收命令。把它交给一个 subagent 或人工维护者执行即可。

### 3. 批量推进（`runner batch`）

候选池有几百个，逐个敲命令不现实。`runner batch` 把「排队 → 看进度 → 跑关卡」串起来，
并且**可恢复**：进度来自每个环境的 `research/<env>/state.json`，中断后重跑不会重复劳动。

```sh
export AVH_ROOT=$PWD/staging

# 入队并写出每个环境下一阶段的 brief
python3 -m runner batch queue --batch-id wave-002 \
  --environment vulnerability/CVE-2024-10252 \
  --environment inspector/CVE-2025-58444

# 看进度：谁完成了、谁卡在哪一阶段、卡的原因
python3 -m runner batch progress --batch-id wave-002 --json

# 推进客观关卡；Docker 阶段必须显式 --execute
python3 -m runner batch run --batch-id wave-002 --stage validate --execute
python3 -m runner batch run --batch-id wave-002 --execute --limit 5
```

批量驱动有两条刻意的保守规则：

1. **agent 阶段不会被自动标记通过。** `analyze`/`generate`/`solve` 只有在产出文件已存在时
   才会尝试关卡，否则报 `awaiting-agent` 并给出 brief 路径。批量运行永远不会因为「跑过了」
   就把一个没有研究笔记或没有验证器的环境判为通过。
2. **没有 `--execute` 就不起容器。** Docker 阶段报 `awaiting-execute`，`attempted` 保持 0。

`run` 的退出码在任一环境 `failed`/`error` 时为 1，便于接 CI。

#### 在 VS Code Remote 会话里跑 agent 的 GUI 陷阱

派 agent 做 `analyze`/`generate` 时，**必须显式禁止它调用任何"打开"类命令**，否则会弹出
VS Code 窗口。原因不在 agent，在本机环境被编辑器接管了：

- 会话里的 `BROWSER` 被指向 VS Code 自己的
  `~/.vscode-server/cli/servers/*/server/bin/helpers/browser.sh`；
- 该脚本执行 `code --openExternal "$@"`，**每调用一次就开一个窗口**；
- `code` CLI 同时在 `PATH` 上，`xdg-open` 在无 `DISPLAY` 时也走 `BROWSER` 回退；
- Python 的 `webbrowser.open()` 同样经由它。

于是任何上游代码里的 `xdg-open` / `webbrowser.open` / `open@` 调用，只要被 agent 真的执行，
就会变成一串编辑器窗口。这与漏洞本身无关，纯属宿主环境副作用。

写 brief 或 workflow prompt 时必须带上这类约束：

```
绝不允许启动任何编辑器/浏览器/GUI 进程，包括 code、xdg-open、
sensible-browser、open、webbrowser.open()。不得为了"理解机制"而执行
上游的打开类代码路径；只允许静态阅读与文本分析。
```

本阶段是**静态**的，本来就不需要执行任何上游代码——看到 agent 想「跑一下」URL 打开逻辑，
直接按越界处理。

### 4. 静态校验 staging

staging 是一个自洽的 registry root（自带 `environments.toml`、`templates/` 软链），
所以本仓库所有静态命令都能直接作用在草稿上：

```sh
AVH_ROOT=$PWD/staging python3 -m runner check
AVH_ROOT=$PWD/staging python3 -m runner diagram --all --check
AVH_ROOT=$PWD/staging python3 -m runner lint
```

`AVH_ROOT` 只覆盖 registry root，`python3 -m runner` 仍从本 checkout 加载。

## staging 目录结构

```text
staging/                              # 默认在 .gitignore 中
├── environments.toml                 # staging 自己的索引
├── templates -> ../templates         # 复用维护中的模板，避免漂移
├── candidates/
│   ├── index.json                    # 本次抽取的完整清单与筛选口径
│   └── <IDENTIFIER>.toml             # 单个候选的 provenance（含库哈希）
├── research/<product>/<ID>/
│   ├── state.json                    # 六阶段状态机
│   ├── brief-<stage>.md              # 每阶段 agent brief
│   ├── public.md                     # Analyzer 蒸馏的研究笔记
│   └── <stage>-res.toml              # 阶段结果
└── environments/<product>/<ID>/      # 可晋升的草稿环境（与正式环境同构）
    ├── metadata.toml  README.zh-cn.md  compose.yaml  Dockerfile
    ├── reproduce.py   verify.py        end_to_end.py
    ├── diagram.toml   diagram/*.mmd
    └── fixtures/      inputs/
```

研究笔记刻意放在环境目录**之外**：`fingerprint()` 会遍历环境目录下的所有非文档文件，
把 staging 专用产物混进去会污染材料指纹。`diagram/` 和 `*.md` 本身不参与指纹。

## 从 staging 并入主仓库

草稿通过 `validate` + `solve` 并经过维护者审阅后：

1. 把 `staging/environments/<product>/<ID>/` 复制到 `environments/<product>/<ID>/`；
2. 运行 `python3 -m runner check`，确认索引未注册该目录时会报 `Unregistered`；
3. 在 `environments.toml` 中登记该条目（或直接复制后运行注册流程）；
4. 按 `docs/environment-contract.md` 收集证据、跑三轮验收，再考虑 `promote`。

`candidates/` 与 `research/` 是 staging 专用审计材料，不进入正式环境目录。

## 端到端实录

流水线已在 `staging/environments/praisonai/CVE-2026-40111`（PraisonAI `memory/hooks.py`
命令注入，`GHSA-v7px-3835-7gjx`）上从候选一路跑到四场景验收，六个阶段全部 `passed`：

| 阶段 | 结果 | 关键产出 |
| --- | --- | --- |
| analyze | passed | `research/.../public.md`（165 行，含修复提交与版本边界核对） |
| generate | passed | `diagram.toml`（7 步、2 个分歧点）、攻击/正常 fixtures、机制 PoC |
| build | passed | 两个 commit 的归档 SHA-256 + 不可变镜像 ID |
| validate | passed | 漏洞侧三轮场景 |
| solve | passed | 四场景三轮全部通过，`verification.mechanism.status = passed` |
| check | passed | `runner check` + `diagram --check` |

`metadata.toml` 仍保持 `lifecycle = "draft"`：机制已验证，但**晋升 `ready` 必须人工审阅并走
`promote`**，流水线不会自行提升。

对照结论（来自容器内真实代码，不是开关）：

- 漏洞版：`hooks.json` 里 `/bin/echo benign-hook; /bin/echo hooks-injected-marker > <canary>`
  的分号被 `/bin/sh` 解释，canary 内容为 `hooks-injected-marker`；
- 修复版：同一载荷被 `shlex.split` 拆成参数，`echo` 只把它原样打印，canary 不存在；
- 两侧正常输入都通过，hook stdout 为 `benign-hook-ok`。

`analyze` 阶段还纠正了 advisory 自身的两处不准：官方写 "fixed 1.5.128"，但实测 1.5.126 的
sdist 已含 `shlex.split`；advisory 声称 `BEFORE_TOOL`/`AFTER_TOOL` 会经由 `memory/hooks.py`
自动触发，实际 `HooksManager` 是 standalone/opt-in。这类核对正是 agent 阶段相对纯模板生成的价值。

## 已知限制

- 产品 slug 是**临时**的：当 advisory 与 references 都没有指向真实仓库时会退化为标题启发式，
  provenance 里的 `product_source` 会标成 `title_heuristic`。并入前必须用 `--product` 纠正。
- `analyze` 是唯一允许联网的阶段；后续阶段只用本地文件与 Docker。
- Docker 阶段会真实运行漏洞代码，必须在一次性、可销毁的环境里执行，不要对生产宿主机运行。
- 本流水线不会自动把环境标成 `ready`，也不会自动发布镜像。
- **文档与实现不一致（待维护者定夺）**：`docs/environment-contract.md` 称声明
  `runtime.network_pool` "不改变指纹"，但 `fingerprint()` 把整个 `metadata["runtime"]`
  计入材料，实测加上 `network_pool` 后 `input_binding` 会变化
  （`9f1a3692…` → `558e6360…`）。既有环境都是带着 `network_pool` 记录指纹的、自洽，
  所以**不宜**直接改函数——那会让已发布环境的证据全部失配。请维护者二选一：改文档措辞，
  或改代码并把既有环境的指纹一并刷新。
- `validate`/`solve` 关卡会自动为声明了 `runtime.exceptions` 的环境补上
  `--allow-exceptions`（`docs/environment-contract.md` 要求执行时必须显式带上该标志）。
  宿主 Docker 默认地址池耗尽时，新环境需要在 `metadata.toml` 里声明
  `network_pool` 与 `network.lab.subnet` 例外，否则 compose 无法分配子网。
