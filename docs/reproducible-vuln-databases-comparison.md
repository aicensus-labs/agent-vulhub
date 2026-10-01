# 同类复现数据库对比：agent-vulhub 的位置与优势

盘点日期：2026-09-22。目的：回答三个问题——**有没有跟本仓库同类的复现漏洞数据库？我们跟它们差在哪？我们的优势是什么？**

本文所有对比对象的数据来自其官方仓库/论文的一手说明（README、论文摘要），已逐条核对；本仓库一侧的描述来自 `docs/environment-contract.md`、`AGENTS.md` 与实际环境目录。

## 0. 结论

1. **同类项目分三类，本仓库落在第三类的空白格**：
   - **A. 传统 CVE 可复现数据库**（ARVO、CVE-Factory、OSS-Fuzz 派生）：复现目标是**内存安全崩溃**，判据是 sanitizer / PoC 触发。
   - **B. 基准型环境打包**（CyberGym、SEC-bench、SEC-bench Pro、ExploitGym）：环境是为了**给模型打分**，不是给人用的漏洞库。
   - **C. 故意脆弱靶场**（DVMCP、Vulnerable MCP Servers Lab）：**人造漏洞**，用于教学/培训，不对应真实 CVE 与修复对照。
2. **本仓库的定位是第三类的空白格**：**真实 CVE/GHSA + Agent/MCP 信任边界 + 机制级验证协议 + 修复对照**。目前没有找到第二家同时满足这四点的公开项目。
3. **优势集中在"验证纪律"而非"规模"**：本仓库有 39 个环境、全部 `draft`、0 个 `ready`；ARVO 有 6,100+ 个、CVE-Factory 有 3,000+ 个。**规模上我们是数量级劣势**，优势在于四场景门、机制/端到端分层、证据协议和生命周期。

> **当前工作树状态说明（2026-09-22 实测）**：39 个环境全部 `draft`；`verification.mechanism` 仅 **3 个 `passed`**，**28 个被降级为 `not_run`**（notes 为 "Mechanism evidence predates base image/runtime input changes; pending rebuild and revalidation"），其余 8 个为从未运行或前置条件不足。而已提交的 HEAD 与 `docs/implementation-status.md`（2026-09-17）记录的是 **31 个 passed**。二者不一致的原因是工作树里存在**尚未提交的失效降级**（54 个文件改动），即 base image/runtime 输入变更后按 ADR-0015 规则把既有证据判为失效、等待重建重验。引用本仓库"通过数量"时必须区分这两个状态。
4. **最需要补的不是漏洞数量，是自动化与许可**：CVE-Factory 用多 Agent 把单条 CVE 的复现流程自动化到 90.1% 成功率；本仓库目前是人工逐环境建设。另外仓库**尚未声明开源许可证**（README 已注明），这在对外发布时会成为采用障碍。

## 1. 同类项目逐个说明

### 1.1 ARVO — Atlas of Reproducible Vulnerabilities（最直接的可复现数据库）

- 论文：IEEE EuroS&P 2026；仓库 [n132/ARVO](https://github.com/n132/ARVO)、数据集 [n132/ARVO-Meta](https://github.com/n132/ARVO-Meta)。
- 规模：**6,100+ 个真实漏洞 / 311 个项目**，来源是 OSS-Fuzz。
- 形态：每个漏洞提供 **vulnerable 与 fixed 两个可交互 Docker 镜像**（`n132/arvo:<id>-vul` / `-fix`），镜像内可 `arvo` 复现、`arvo compile` 重新编译。
- 判据：PoC 输入在 vulnerable 版触发 ASAN 报告、在 fixed 版不再触发。
- 成绩：成功复现 **81%**，自动定位补丁准确率 **89.4%**。
- 与本仓库的关系：**判据思路几乎一致**（漏洞版触发、修复版阻断），但对象是 fuzzing 目标的**内存安全崩溃**，不是 Agent/MCP 的信任边界；且它是**数据集**（只读语料），不是带验证纪律与生命周期的**环境仓库**。

### 1.2 CVE-Factory / LiveCVEBench（最同类的工程，Agent 驱动自动化）

- 仓库 [livecvebench/CVE-Factory](https://github.com/livecvebench/CVE-Factory)，论文 arXiv:2602.03012，ICML 2026，**MIT 许可**。
- 定位：多 Agent 系统，**从 CVE 记录端到端自动生成复现环境**——研究细节、生成测试、构建 Docker、验证"可利用且已修复"。
- 产物结构（对齐 Terminal-Bench 标准）：`task.yaml`、`Dockerfile`、`docker-compose.yaml`、`solution.sh`（参考修复）、`test/test_func.py`（功能测试）、`test/test_vuln.py`（漏洞测试）、`run-tests.sh`。
- 判据：**vulnerable 态 = test_func PASS + test_vuln FAIL；fixed 态 = 两者都 PASS**。
- 规模与成绩：554 个 2025 年 CVE 中复现成功 **499 个（90.1%）**；专家复审 471 个成功案例，**312 个（66.2%）完全准确**。公开 1,000+ 任务环境，另有 3,181 个新增环境；训练出 Abacus-cve 模型（Qwen3-32B 微调后在 LiveCVEBench 上 5.29%→35.79%）。
- 与本仓库的关系：**这是最需要认真对标的项目**。它的"功能测试 + 漏洞测试"双测试结构，与本仓库"四场景（漏洞攻击/修复攻击/漏洞正常/修复正常）"是同一思想，但本仓库多出**修复版正常任务**这一对照，并且把**候选 PoC 评测**（`agent_poc` 层）与**机制验证**分离。它的对象仍是通用 CVE，**不做 Agent/MCP 信任边界**。

### 1.3 基准型环境打包

CyberGym（1,507 漏洞 / 188 项目，`repo-vul.tar.gz` + `repo-fix.tar.gz` + ground-truth PoC）、SEC-bench（200 个验证实例，$0.87/实例）、SEC-bench Pro（344 实例，V8/SpiderMonkey/Linux 三镜像）、ExploitGym（898 实例，复用 CyberGym 语料）。详见 `docs/agent-security-benchmarks.md`。

与本仓库的关键差异：**它们的环境是为了给模型打分**（一次性、可丢弃、判据服务于 leaderboard），本仓库的环境是**长期维护的漏洞库条目**（有 metadata、生命周期、可复现证据、维护者审阅）。CyberGym 的语料可以被 ExploitGym 二次利用，说明这类语料确实有复用价值——这也是本仓库的潜在定位。

### 1.4 故意脆弱靶场（Agent/MCP 侧）

| 项目 | 内容 | 与本仓库差异 |
|---|---|---|
| [Damn Vulnerable MCP Server (DVMCP)](https://vwad.owasp.org/app/damn-vulnerable-mcp-server-dvmcp/) | 故意脆弱的 MCP server，10 类挑战 | **人造漏洞**，无 CVE 身份、无修复对照、无版本固定 |
| [Vulnerable MCP Servers Lab](https://vwad.owasp.org/app/vulnerable-mcp-servers-lab/)（Appsecco，277 stars，OWASP VWAD 收录） | 故意脆弱的 MCP server 集合：路径穿越、未沙箱代码执行、间接提示注入（本地/远程）、eval 恶意执行、指令注入、命名空间 typosquatting、过期依赖供应链风险、机密/PII 暴露 | 同上；它的价值是**攻击面枚举**，可作为本仓库选题清单 |
| [F5GovSolutions/agent-security-lab](https://github.com/F5GovSolutions/agent-security-lab)、[keirendev/agent-inject](https://github.com/keirendev/agent-inject)、[dobin/vuln-agent](https://github.com/dobin/vuln-agent) | Agent 工作流攻防教学实验 | 教学导向，非 CVE 复现 |
| [stefanoamorelli/inspect-evals-mcptox](https://github.com/stefanoamorelli/inspect-evals-mcptox) | MCPTox：工具投毒攻击基准（Inspect AI 实现） | 是**攻击基准**，不是漏洞环境库 |

**注意区分**：OWASP VWAD 里这两个是"故意脆弱应用"，**不是**"真实 CVE 的复现环境"。本仓库的 `agent_specificity = "agent_unique"` 标记的是真实 CVE/GHSA，这是本质区别。

## 2. 对比总表

| 维度 | ARVO | CVE-Factory | CyberGym 等基准 | DVMCP / MCP Lab | **agent-vulhub（本仓库）** |
|---|---|---|---|---|---|
| 对象 | OSS-Fuzz 内存安全 bug | 通用 CVE | 通用 CVE | 人造漏洞 | **真实 CVE/GHSA，Agent/MCP 产品** |
| 规模 | 6,100+ / 311 项目 | 3,000+ 任务环境 | 200–1,507 | 10+ 挑战 | **39** |
| 环境生成 | 半自动（源码元数据） | **全自动多 Agent，90.1%** | 半自动/人工 | 人工 | **人工，逐环境建设** |
| 漏洞版+修复版 | 是（两个镜像） | 是 | 是 | 否 | **是（两个固定 commit + 两个镜像）** |
| 判据 | PoC 触发/不触发 | test_func + test_vuln | sanitizer / flag / judge | 无 | **四场景门 + 独立 `verify.py`** |
| 正常任务对照 | 无 | 有（test_func） | 部分 | 无 | **有，且修复版也跑正常任务** |
| 机制/端到端分层 | 无 | 无 | 无 | 无 | **有（`mechanism` 与 `agent_poc` 分离）** |
| Agent-PoC 评测层 | 无 | 训练用（非评测协议） | 是（是其主要目的） | 无 | **有（隐藏 patched、四场景、Adapter 验收）** |
| 供应链固定 | 镜像 | 镜像 | 镜像（CyberGym 有依赖漂移问题） | 无 | **base image digest + 每个输入 URL+SHA256 + 离线构建** |
| 状态生命周期 | 无 | 无 | 无 | 无 | **draft/ready + 三轮验收 + 维护者审阅 + 失效重验** |
| 证据协议 | 崩溃输出 | 测试结果 | leaderboard 分数 | 无 | **facts.json / verdict.json + 哈希 + 跨运行标识** |
| 许可 | 见仓库 | **MIT** | 各论文/仓库 | 各异 | **尚未声明** |

## 3. 我们跟它们不同在哪

1. **目标漏洞类型不同**。ARVO / CVE-Factory / CyberGym 都聚焦**内存安全崩溃**（OSS-Fuzz 谱系）。本仓库聚焦 **Agent/MCP 信任边界**：工具调用的权限语义、MCP server 的认证与来源校验、提示注入导致的越权、Agent 配置放宽、工具输出进入模型上下文。这类漏洞的"效果"往往**不是崩溃**，而是"Agent 被诱导读取了不该读的文件""工具以超出声明的权限执行了操作"——`mcp-filesystem/CVE-2025-53109` 就是典型：**没有 crash，效果是越界读取**。
2. **判据的哲学不同**。别人是"漏洞版崩、修复版不崩"；本仓库是**四场景**，额外要求**修复版下的正常任务仍然成功**（防止"打补丁把功能打死"被误判为修复有效）。CVE-Factory 有 `test_func` 覆盖了一半，但没有"修复版正常任务"这一格。
3. **产物性质不同**。ARVO 是**数据集**（下载即用、只读）；基准是**评分工具**（跑完即弃）；靶场是**教学材料**（人造）。本仓库是**带验证纪律的环境仓库**——有 lifecycle、有 `verified_at`、有可复核 evidence 路径、有晋升与失效规则。
4. **机制验证与模型评测分离**。别人要么只做机制（ARVO），要么只做模型评测（基准）。本仓库明确分成 `mechanism`（维护者 PoC 证明漏洞机制成立）与 `agent_poc`（模型候选在隐藏修复对照中评测），并规定**没有通过机制验收的环境不能凭 Agent 候选晋升**。这个分层在同类项目里没有见到。
5. **对 Agent 是"被测对象"而不是"构建工具"**。CVE-Factory 用 Agent 来**造**环境；基准用 Agent 来**打分**；本仓库把 Agent 同时当**被测对象**（`agent_poc`）和**威胁模型的一部分**（漏洞本身是 Agent 被操纵）。

## 4. 我们的优势

1. **信任边界视角，而不是崩溃视角**。这是最核心的差异化。Agent/MCP 漏洞的根因是**授权与信任传递**，用 crash 判据根本测不到。本仓库的 `diagram.toml` schema 强制表达"攻击者可控输入 → 上游组件 → 被调用的工具 → 被读写的存储 → 受控效果落点"，正好是信任边界语言。
2. **验证纪律最强**。固定 base image digest、每个输入 URL+SHA256、`--network none` 离线构建、四场景独立 Compose project/网络/volume、`cap_drop ALL` + `no-new-privileges` + 资源限制、证据哈希校验、跨运行标识拒绝复用、显式 exception 需两位审阅者。**这套约束比 ARVO 和 CVE-Factory 都严**。
3. **有可陈述的判定语义**。`AGENTS.md` 明确规定：不以进程退出码判定成功、检查 vulnerable/patched/benign 三组对照、机制与端到端结果分离、模拟模型不构成提示注入成功证据。同类项目里 ARVO 只有崩溃输出、CVE-Factory 只有两个测试的 PASS/FAIL。
4. **真实修复对照 + 真实产品源码**。不是最小化复现，而是"完整安装上游版本，允许直接调用内部函数，不能抽取或重写漏洞函数代替产品"。这比人造靶场和最小样例都更接近真实。
5. **可审计的生命周期**。`draft`→`ready` 要求固定构建输入、三轮验收、维护者审阅；发布镜像时要求两版固定 digest。工具链变化会使既有 `ready` 失效。ARVO/CVE-Factory/靶场都没有状态机。
6. **Agent/MCP 覆盖面已成体系**。39 个环境里含 MCP 生态（filesystem、atlassian、gateway、server-git、server-kubernetes、node-code-sandbox、hackmd、ios-simulator）与 Agent 平台（**PraisonAI 20 个**、n8n、Open WebUI、OpenHarness、Chainlit、Flowise、claude-code-action、omnigent、vtcode、factoryfloor、agent-device）。`agent_specificity` 分布为 **36 个 `agent_unique` + 3 个 `agent_related`**。这个密度在公开项目里没有对等物。
7. **选题有筛选原则**。`docs/agentsec-daily-candidates.md` 已明确"仅因为是 Agent/MCP 就标成 agent_unique 的普通 SSRF/路径穿越需要重新判断信任边界"，避免把通用漏洞伪装成 Agent 漏洞。

## 5. 我们缺什么（对标后的差距）

1. **规模**：39 vs ARVO 6,100+ / CVE-Factory 3,000+。差 2 个数量级。
2. **自动化**：CVE-Factory 把复现流程自动化到 90.1%（专家复核后 66.2% 完全准确）。本仓库是人工逐环境建设，`$0.87/实例`（SEC-bench）或全自动流水线这类成本结构我们没有。
3. **零 `ready`**：README 记录 31 个机制验收通过（HEAD 口径），但 **0 个 `ready`**、**0 个已发布 GHCR 镜像**；且当前工作树中 28 个环境的证据已因输入变更被判失效。对外可复现性目前依赖本地构建。
4. **未声明许可证**：CVE-Factory 是 MIT，AI-Infra-Guard 是 Apache-2.0，ARVO 见仓库。本仓库 README 明确"尚未声明开源许可证"，会阻碍外部采用与二次利用。
5. **Agent 生态分类字段为空**：825 条 metadata 的 `agent_security_categories_json` 全空，`owasp_agentic_category` / `owasp_llm_category` 未填（详见 `docs/agent-vuln-sources.md`）。
6. **无 leaderboard / 无公开评测结果**：基准类项目都有对外分数，本仓库的 `agent_poc` 层尚无环境通过 Adapter 验收，因而没有任何模型评测结果可发布。

## 6. 建议

**不要比规模，要比"判定语义 + 信任边界"**。ARVO 和 CVE-Factory 已经把"通用 CVE 大规模可复现"这件事做满了，正面竞争没有意义。本仓库的可防御定位是：

1. **把 Agent/MCP 信任边界做成别人没有的分类体系**：补齐 OWASP Agentic / SkillTrustBench T01–T09 标注，让"为什么这是 Agent 漏洞"可查询、可统计。这是 ARVO/CVE-Factory 完全没有的维度。
2. **把验证协议本身当成可引用的贡献**：四场景门、机制/端到端分离、隐藏 patched、证据哈希与失效重验，这套东西可以写成方法论文档对外发布，比多 100 个环境更有区分度。
3. **借 CVE-Factory 的自动化补规模**：它的产物结构（`test_func.py` / `test_vuln.py` / `solution.sh`）与本仓库四场景高度同构，可考虑把它的生成流水线作为**候选环境的初筛器**，再套本仓库的验证纪律做验收——即"自动生成 + 人工/协议验收"。**已落地**：`python3 -m runner harvest` + `python3 -m runner factory` 实现了候选抽取、staging 草稿、图解渲染与六阶段客观关卡，见 `docs/agentsec-reproduction-factory.md`；自动化只覆盖到 draft，`ready` 仍需人工审阅。
4. **先解决许可证与首个 `ready`**：没有许可证和没有一个可分发镜像，外部无法复用；这两项是发布的前置条件。

## 参考

- ARVO：<https://github.com/n132/ARVO>、数据集 <https://github.com/n132/ARVO-Meta>、论文 IEEE EuroS&P 2026（DOI 10.1109/EuroSP68448.2026.00060）
- CVE-Factory：<https://github.com/livecvebench/CVE-Factory>、论文 arXiv:2602.03012、榜单 <https://livecvebench.github.io/>
- DVMCP：<https://vwad.owasp.org/app/damn-vulnerable-mcp-server-dvmcp/>
- Vulnerable MCP Servers Lab：<https://vwad.owasp.org/app/vulnerable-mcp-servers-lab/>、<https://github.com/appsecco/vulnerable-mcp-servers-lab>
- MCPTox：<https://github.com/stefanoamorelli/inspect-evals-mcptox>
- agent-security-lab：<https://github.com/F5GovSolutions/agent-security-lab>、agent-inject：<https://github.com/keirendev/agent-inject>、vuln-agent：<https://github.com/dobin/vuln-agent>

相关仓库内文档：`docs/agent-security-benchmarks.md`（四个基准详述）、`docs/agent-vuln-sources.md`（漏洞来源清单）、`docs/environment-contract.md`（本仓库验证协议）、`docs/agentsec-daily-candidates.md`（选题与筛选原则）、`docs/agentsec-reproduction-factory.md`（候选到复现环境的自动化流水线）。
