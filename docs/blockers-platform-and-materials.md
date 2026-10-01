# Platform And Material Blockers

日期：2026-09-23

这些环境的源码和漏洞描述已经完成初步核查，但当前无法在仓库规定的 Linux amd64、网络隔离、真实上游代码路径下形成可核查的 vulnerable/patched/benign 四场景对照。它们保持 `draft`，PoC 返回 `not_run`；不得用替身函数、静态 canary 或模拟 GUI/Envoy 来制造通过结果。

## flowise/CVE-2026-70477

漏洞版 3.1.2 的触发路径在 `packages/components/nodes/agents/CSVAgent/CSVAgent.ts`：加载 `pyodide` 及 `pandas`/`numpy` WASM，接收模型生成的 Python，再经过验证器后交给 `runPythonAsync()`。3.1.3 的对应 CSV Agent/pyodide 源码被移除，不能直接用同一路径构成修复版对照。

当前固定归档约 49--51 MB，完整离线构建还需要与上游匹配的 pyodide、pandas、numpy WASM 包和 pnpm 依赖。仅复制一个 Python 或 JavaScript 函数会绕过 Flowise 的 node、LangChain、WASM 和验证边界，因此不是可接受的复现。恢复条件是补齐可核查的离线依赖，并确定 3.1.3 的真实替代路径或官方修复对照。

## mcp-gateway/GHSA-g53w-w6mj-hrpp

漏洞点位于 Envoy `ext_proc` 与 MCP Gateway router 的组合部署：未认证 initialize/hair-pin 路径信任 `mcp-init-host` 并改写上游 `:authority`，从而绕过 broker 的 JWT/capability 过滤。上游仓库提供的是由 Istio EnvoyFilter 生成的部署材料，没有能在本项目中直接启动的静态 Envoy bootstrap 和独立 ext_proc 测试入口。

手写一个 Envoy 配置、ext_proc 服务和假上游会重新定义部署面，无法说明结果来自固定 Gateway 版本的真实部署。恢复条件是上游提供独立可运行的 bootstrap/fixture，或维护者明确接受隔离的 Envoy 集成测试环境并补齐两版完整材料。

## factoryfloor/CVE-2026-88063

Factory Floor 是 macOS 14 Swift/AppKit GUI。漏洞需要用户在一次性仓库中创建 workstream，使 GUI 触发仓库脚本预加载；修复版还涉及内容绑定的项目批准。Linux amd64 容器既没有 AppKit/Xcode，也不能提供等价的 GUI 用户动作。

当前 Dockerfile 仅保留固定源码，不能把 shell 脚本直接执行当成 Factory Floor 的复现。恢复条件是使用独立、可销毁的 macOS VM，并为 GUI 操作和证据采集建立与本协议等价的隔离验收流程。

已修复一处 metadata 缺陷：`vulnerable.archive`/`patched.archive` 原写 `vulnerable-source.tar.gz`/`patched-source.tar.gz`，而声明的 build inputs 是 `factoryfloor-vulnerable-source.tar.gz`/`factoryfloor-patched-source.tar.gz`，导致 `runner build` 直接以 `archive must name a build input` 拒绝。修正后 `runner build --offline` 可完成并产出两版镜像，`reproduce.py` 按预期返回 `not_run`（exit 2）而不是调用替身 shell。平台阻塞本身不变。

## vtcode/GHSA-WQGW-CRR5-CR2P

漏洞触发面是交互式 VT Code TUI 的 `session_start` hook。当前没有稳定的非交互入口可以区分 TUI 启动失败和 hook 执行；直接运行二进制或 shell 命令不能证明上游生命周期代码被调用。

**另有一处公开基础镜像迁移引入的回归**：Dockerfile 执行 `cargo build --locked --offline`，而新的 `buildpack-deps` 基础镜像不含 Rust 工具链（原先固定的 `codex-universal` 自带），因此构建以 `/bin/sh: 1: cargo: not found`（exit 127）失败。crates 本身已经 vendor 齐全（两份约 181 MB 的归档，均按 SHA-256 固定），缺的只是编译器；恢复需要补一个固定的离线 Rust 工具链输入（解包后约 1 GB）后重跑四场景验收。

这两个 Cargo vendor 归档由 Git LFS 跟踪；metadata 现在使用当前仓库的
`media.githubusercontent.com` 端点，并已按声明 digest 实测下载成功。干净
clone 需要能访问该仓库的 LFS 对象。本地 `git lfs checkout` 已把两份归档
展开为约 8.8 MB 的真实 vendor 归档。剩余触发面问题仍要求先证明稳定非交互
入口确实进入 TUI 的 `session_start` hook；在此之前保持 `draft`/`not_run`。

恢复条件是换成来源可核查的真实 vendor 归档，并先证明稳定非交互触发确实进入 `session_start`；在此之前保持 `draft`/`not_run`。

## omnigent/CVE-2026-62674（已解除）

原阻塞理由是本仓库固定镜像只提供 Python 3.10，而 Omnigent 声明
`requires-python = ">=3.12"`。经复核，该声明对本环境的 PoC 路径并不成立：
`cel_expr_python`、`rpds-py` 等包确实只发布 cp311+ 的 wheel，但 `cel_expr_python`
只在函数内惰性导入，PoC 不触碰该路径。已按上游 `uv.lock` 重建 cp310 可用的依赖
闭包（`python-runtime-deps.tar.gz`），并修正 PoC 的三处缺陷：路由选择未过滤 HTTP
方法而误取同路径的只读 GET 处理器、伪 agent 对象缺少响应模型所需字段、以及把
"补丁正确拒绝"误判为执行失败。现已在公开基础镜像上完成四场景三轮验收并通过。

仍存在的限制：`requires-python >= 3.12` 依然写在上游 `pyproject.toml` 里，若将来
PoC 需要触及 `cel_expr_python` 或其他 cp311+ 依赖，就需要重新引入 Python 3.12+
的可核查离线解释器材料。

## 共享构建输入可拉取性

metadata 中指向 `raw.githubusercontent.com/aicensus-labs/agent-vulhub/main/...`
的依赖归档已在本次核验中全部返回 200；在干净 clone 中对相关环境逐项执行
`runner fetch` 也通过 SHA-256 校验。该可拉取性阻塞不再适用。

`agent-device` 与 `vtcode` 的 4 个 Git-LFS 输入已改用
`media.githubusercontent.com/media/aicensus-labs/...`，并按 metadata 声明
digest 实测下载成功。`vtcode` 的本地 LFS 对象也已 checkout 成真实 Cargo
vendor 归档。

基础镜像替换暴露的 Node 和 pip 运行时缺口已用固定离线输入处理：
`mcp-server-kubernetes` 与 `n8n` 引入 Node 22.14.0，11 个 Python 环境通过
pip 25.1.1 wheel 自举安装。这些改动均已重建并完成四场景三轮重新验收。

## praisonai/CVE-2026-61445（上游补丁版无法 import）

固定的修复版 v4.6.78（tag `v4.6.78`，commit `393de394087e3badc79acfec490323bcc99638bd`）
在 `src/praisonai/praisonai/ui/components/aicoder.py` 第 177 行有未闭合括号：

```python
if any(token in cmd for token in (";", "&&", "||", "|", "`", "$(", ">"):
```

`any(` 从未闭合，`compile()` 抛 `SyntaxError: invalid syntax`，因此 PoC 必须调用的
模块无法加载。漏洞版 v4.6.77 可正常 import 并复现效果，只有补丁对照不可用。
同族的 `praisonai/CVE-2026-61439` 使用同样的版本对却通过，因为它不 import 该模块。

**重新固定版本这条路已实测排除，且 2026-09-24 又按提交历史完整复核了一遍**（此前只核对了
release tag，那是不够的）：该文件共有 11 个提交。v4.6.78 之前的三个提交
`89229c5c760f`（2026-05-08）、`e33b4b4b39e0`（2026-05-05）、`37f979979ca9`（2026-05-01）
**都能正常 parse**，但**都不含任何修复**——元字符守卫、`_blocked_commands` 黑名单、
`_safe_path` 路径穿越守卫是在 `393de394087e` 里**一起**引入的，也就是引入语法错误的同一个
提交；之后没有任何提交修复它，`c24015a9c520`（2026-07-15）直接把 `aicoder.py` 删掉了。
**不存在既能编译又含修复的上游版本。**

**修复范围比原记录更宽，这一点影响"能否用替代对照"的判断。** v4.6.78 在 `aicoder.py` 里改了
三处，不是一处：新增 `_blocked_commands`；新增 `_safe_path`（调用已发布的
`praisonai/code/utils/file_utils.py:is_path_within_directory`）并把 `apply_llm_response`
改接过去，用于 `write_to_file` 的路径穿越；以及那个坏掉的元字符守卫。路径穿越那一半**语法完好、
依赖也在固定树里**，但同一个未闭合括号让整个模块无法 import，两半一起不可达。另外
`write_to_file` 自身始终没有校验，守卫在调用方，所以修复无法与那个编译不过的文件分离。

修复它等于修改上游源码，`docs/environment-contract.md` 不允许；而且这里的改动会落在**被测函数
本身**，而非脚手架，证据将取决于维护者对作者意图的判断，而不是已发布的产物。
结论：该环境在找到可用的补丁对照前保持 `not_run`；若上游日后发布修好第 177 行的 4.6.x
版本，应重新检查。

## ready 与 GHCR 发布（2026-09-24：凭据已解开，试点已 ready）

**本节记录的门禁已于 2026-09-24 解开**：维护者执行了
`gh auth refresh -s write:packages` 与 `docker login ghcr.io`，随后完成试点
`mcp-filesystem/CVE-2025-53109` 的发布与晋升，它成为本仓库第一个 `ready` 环境。
下面保留原始阻塞描述，并记录实际走通的流程与途中发现的两个问题。

原始阻塞（已解除）：

- `runner publish` 需要维护者事先 `docker login ghcr.io`。当时宿主机没有可用的
  GHCR 凭据（`/tmp/docker-config/config.json` 无 auths，`GHCR_TOKEN`/`CR_PAT`/`GITHUB_TOKEN`
  均未设置），因此无法推送镜像，也就无法得到 `repo@sha256:...` 形式的可分发 digest；
  两版 metadata 的 `image` 字段（ready 门禁要求）因此只能留空。
- `runner promote` 要求互不相同的审阅者：声明了 `runtime.exceptions` 的环境需要两位。
  本仓库绝大多数环境因宿主地址池耗尽声明了 `network.lab.subnet` 例外，因此需要两名
  维护者。**这一项仍未解决**，但试点环境未声明 exceptions，故只需一名审阅者即可晋升。

### 走通的发布与晋升流程（试点实测）

1. `runner publish <env> --images <build.json> --repository ghcr.io/<owner>/<pkg>`
   —— 推送 `{variant}-{binding[:16]}` 两个 tag，并从 `RepoDigests` 提取唯一 digest。
2. **手动**把两版 digest 写回 `metadata.toml` 的 `image`（`publish.py` 只写
   `publication.json`，不回填 metadata）。
3. `runner reproduce <env> --offline --rounds 3` —— 必须在 digest 已固定的 metadata 上
   重跑，否则报告指纹与晋升时所需的不一致。
4. `runner promote <env> --report <report.json> --reviewer <name> --reviewed`
   —— 归档证据到 `environments/<env>/evidence/<run_id>/`。

`--reviewed` 是必需参数；`--reviewer` 会写进 `review.reviewers`，必须是真实审阅者。

5. `runner prune --repository ghcr.io/<owner>/<pkg> [--apply]` —— 清掉 push 留下的无 tag 版本。
   一次 `docker push` 会注册 4 个无 tag 版本（镜像 manifest 之外的 attestation/provenance
   manifest 各占一个 package version），只有镜像 manifest 带 `{variant}-{binding[:16]}` tag。
   试点推了 2 次就累积 8 个无 tag 版本，按比例 500 个环境会产生 3000 个。无 tag 版本无人引用，
   删除不影响有 tag 版本共享的 blob，因此不会动 `metadata.toml` 里的 digest；命令默认只报告，
   加 `--apply` 才真删，且永不删有 tag 版本。

镜像可见性没有 REST API：对 container package 的 `PATCH .../packages/container/<name>` 一律
返回 404（实测个人与 org 端点都一样），只能由 org admin 在网页设置页切换。若 package 保持
private，Free 计划 500MB 配额连一个环境都放不下（一对镜像约 0.9GB），且该配额与 Actions
artifacts 共享。

验证 digest 是否真的可取，用 `docker pull` 而**不要**用 `docker manifest inspect`——后者对
GHCR 会误报 `manifest unknown`（实测：同一 digest 无缓存 `docker pull` 成功）。

### 途中发现并修复的问题：`check_evidence` 的路径基准不一致

本仓库此前从未有过 `ready` 环境，因此这个 bug 直到试点晋升后才暴露：`runner check`
对唯一那个 `ready` 环境报 `missing evidence evidence/<run_id>/report.json`。

根因是两个解析基准互相矛盾：

| 位置 | 基准 | 结果 |
| --- | --- | --- |
| `promote` 写 `review.report` | 环境目录 | `evidence/<run_id>/report.json` |
| `ready_check`（`lifecycle.py:23`） | 环境目录 | 一致 |
| `check_evidence`（`cli.py:139`） | **仓库根** | 不一致 → 报 missing |

`verification.mechanism.evidence` 的既有约定是仓库根相对（草稿期写成 `results/...`），
而 `promote` 归档后 `ready_check` 又按环境目录解析，两者无法同时满足。修复方式：
`check_evidence` 改为**先按环境目录解析，失败再回退到仓库根**，因此晋升前后两种形式
都能通过。

**连带影响（重要）**：`runner/*.py` 在输入指纹内，改它会作废**全部**环境的三轮证据；
更关键的是 `input_binding()`（`runtime.py:125`）也调用 `fingerprint()`，所以改 runner
还会改变镜像的 `org.agent-vulhub.inputs` 标签——已推送镜像会因此失效，必须**重建并
重新推送**。试点因此重建、重推、重跑三轮、重新晋升了一次。全部 38 个通过环境已整体
重跑三轮验收以对齐新指纹（实测单个环境重建+三轮约 36 秒）。

另外，对声明了 `runtime.exceptions` 的环境重跑验收必须加 `--allow-exceptions`，否则
会在 `verify_or_config` 阶段以 `Compose isolation rule: network.lab.subnet` 失败。

### 试点之外仍未完成的 ready 条件

- 其余 38 个环境的 `image` 仍为空，需要逐环境 publish + 回填 + 重跑 + promote。
- 需要两名审阅者的环境尚未有第二个审阅者。

其余 ready 条件已经满足：39 个环境的 `title`、`advisories`、`agent_specificity`、
两版 `version`/`source_url`/`commit` 均已填写；**38 个环境有通过且指纹与工作树一致的
三轮机制证据**（唯一例外是 `praisonai/CVE-2026-61445`，见上一节）。`agent_poc.adapter_status`
保持 `not_run` 是刻意的——真实模型入口仍未接入，未声明 accepted 前 `agent-evaluate`
不会把候选自报文件当作通过。

### 两项门禁的当前计数（2026-09-24 实测）

| ready 条件 | 满足数 | 说明 |
|---|---|---|
| ≥3 轮机制验收 | **38/38** | 已通过验收的环境全部满足；缺的只有 praisonai 的补丁对照 |
| 构建输入固定 | **38/38** | 源码 commit、每项输入 URL+SHA-256、基础镜像 digest 全部固定 |
| 维护者审阅 | 1 | 29 个环境声明 `runtime.exceptions`（全部是 `rule` 类），需 2 名审阅者 |

结论：**`ready` 的瓶颈是维护者审阅，不是验收证据，也不再是镜像发布。**
发布镜像是可选的（[ADR-0004](../adr/0004-reproducible-immutable-images.md)），复现性由固定输入
保证，使用者用 `runner reproduce <env> --build` 自行构建。29 个声明 `runtime.exceptions` 的环境
仍需 2 名审阅者，这是当前唯一未解开的结构性约束（400 个环境约需 800 次人工审阅）。

### 晋升的步骤顺序不能颠倒（实测）

`fingerprint()` 把两版 `image` digest 计入输入（它只排除 `lifecycle`、`verification`、
`review`、`title`、`description`、`advisories`），而 `input_binding()` 反而把 `image`
清空——前者是验收报告要绑定的对象，后者是构建清单要绑定的对象。这带来一个容易踩的顺序
约束：**digest 必须在生成验收报告之前就写进 metadata**，否则报告生成后任何 digest 回填
都会让报告立即过期。正确顺序是

1. `runner build` → 本地镜像与构建清单（清单绑定 `input_binding`，与 digest 无关）；
2. `runner publish` → 推送并取得 `repo@sha256:...`，回填两版 `image`；
3. `runner reproduce --rounds 3` → **在已固定 digest 的 metadata 上**跑验收，报告指纹才与
   最终状态一致；
4. `runner promote` → 把证据归档进 `environments/<env>/evidence/<run_id>/` 并把
   `review.report` 记为**相对环境目录**的路径。

第 4 步的归档不是可选项：`ready_check` 用 `contained(directory, review.report)` 解析路径，
即相对**环境目录**，而 `runner reproduce` 写在仓库根的 `results/` 下。因此直接指向
`results/...` 的 metadata 无法通过 `ready_check`，必须经过 `promote` 归档。

**digest 门禁就在晋升路径上。** 2026-09-24 用临时克隆实测确认了这一点：
（本节早先写过"该顺序已用合成 digest 完整验证：`promote` 成功"——**那句话是错的**，
实测结果为失败，已按下面的事实更正。）

- 在临时克隆里回填合成 digest 后执行 `promote`，直接被拒绝：
  `vulnerable needs pinned commit and image digest`（`runner/cli.py:116`）。原因是 `promote`
  先把 `lifecycle` 置为 `ready`，随后跑完整校验，而该校验要求 `IMAGE` 正则匹配两版 `image`
  ——空 digest 必然失败。
- 该预测随后在真实环境上得到印证：`mcp-filesystem/CVE-2025-53109` 完成 digest 回填后，
  先前那份在空 digest 下生成的报告立即被 `runner check` 判为 stale，必须重跑三轮。

结论：**GHCR 推送是这条链的第一块，必须最先解开**；在它解开之前，验收报告也无法生成成
可用于晋升的形态。这不影响已完成的三轮验收本身（那些报告证明的是机制，仍然有效），
只影响把它们提升为 `ready`。

### 解除 GHCR 凭据阻塞需要维护者执行的命令（已于 2026-09-24 执行）

执行前 `gh` 的 token scopes 为 `gist, read:org, repo, workflow`，**缺 `write:packages`**；
`/tmp/docker-config/` 下没有 `config.json` 的 auths，即 Docker 未登录 ghcr.io。维护者执行的命令是：

```bash
gh auth refresh -s write:packages
gh auth token | docker login ghcr.io -u glmgbj233 --password-stdin
```

注意 `gh auth refresh` 会**重新签发 token**，所以 `docker login` 必须在它之后执行。
若 `refresh` 不接受该 scope，退路是创建带 `write:packages` 的 PAT 后直接
`docker login ghcr.io -u glmgbj233 --password-stdin`。

授权完成后的试点流程（`runner publish` 要求 `--repository` 为小写
`ghcr.io/owner/package`，`glmgbj233` 已满足）：

```bash
# 1. 推送并取得 repo@sha256:... （只写 results/<env>/<run>/publication.json，不回填 metadata）
python3 -m runner publish <env> --images <build.json> --repository ghcr.io/glmgbj233/<package>

# 2. 把两个 variant 的 digest 手动写进 metadata.toml 的 image 字段
# 3. 在已固定 digest 的 metadata 上重新验收三轮
python3 -m runner reproduce <env> --offline --rounds 3 --images <build.json>

# 4. 归档证据并晋升（--reviewed 是必需的：声明已审阅证据、来源、安全与脱敏）
python3 -m runner promote <env> --report <report.json> --reviewer <name> --reviewed
```

第 2 步必须手动做：`runner/publish.py` 只写 `publication.json`，不修改 `metadata.toml`。

试点环境选 `mcp-filesystem/CVE-2025-53109`：构建产物最小、推送最快，适合先验证整条
digest 流程。其两版 `image` 字段当前均为空，`mechanism` 已是 `passed`。

## claude-code-action/CVE-2026-47751（已解除）

原阻塞记录为"漏洞版归档没有 `restore-config.ts` 模块，仅凭模块不存在不能证明真实 Action
已 checkout 并把配置交给 Claude CLI"。**缺失这一事实为真，但结论下错了**：真正的缺陷在旧
PoC 的结构——它**按文件是否存在分叉**，补丁版导入并执行 `restoreConfigFromBase()`，漏洞版
因为文件不存在就直接返回 `not_run`。于是两个变体从未跑同一条路径，**漏洞对照根本没有执行**。

正确的读法是：**漏洞的表现是文件系统状态，不是调用的返回值**。读 `.mcp.json` 的是 Claude
Code CLI（从工作目录读），不是 Action 源码，所以修复手段是把这些 PR 可控路径从 base 分支
还原。当前 harness 在容器内建真实 git 仓库 + bare `origin`，重建该状态以及把状态变成效果
的那一步，两个变体跑同一条路径，并额外要求阳性对照（审阅版配置确实被还原并执行）。
四场景三轮 **12/12 通过**，状态转为 `passed`。
