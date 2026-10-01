# Agent/MCP 漏洞来源清单

盘点日期：2026-09-22。目的：为 `agent-vulhub` 找**可用于构建可复现环境的**漏洞来源，尤其是 Agent/MCP 相关。

检索方式说明：本次盘点**无法使用 web 搜索**（web-search 未配置 API key，见文末“方法”一节）。所有结论来自直接访问一手接口：OSV API、NVD REST API、GitHub API 与 GitHub Advisory 网页检索、以及各库的实际数据目录。因此这是一份**可复核的来源清单**，不是穷尽式索引。

## 0. 先看结论

1. **你已有的库在“条目数量”上不缺。** `incoming-agentsec-20260729/agentsec_vulnerabilities.sqlite3` 有 5,038 条 raw_items、4,438 条 vuln_items、825 条 vulnerability_metadata，聚合了 10 个来源（GitHub Global/Unreviewed Advisories、NVD Agent Security CVE Search、CISA KEV、VulDB、ZDI、huntr、Exploit-DB、CERT/CC、Full Disclosure）。
2. **真正的缺口不是“再多一个 CVE 列表”，而是三类互补数据**：
   - **修复对照**（vulnerable/patched commit、affected version range）——决定能不能建环境；
   - **Agent 信任边界分类**（OWASP Agentic / 工具调用语义）——决定条目是不是真的 Agent 漏洞；
   - **可触发输入或 PoC**——决定能不能做四场景对照。
3. **最值得新增的三个来源**：
   - **GitHub Advisory Database**（可网页/API 检索、含 patched version 与 commit 引用）——与你库里的 GitHub 来源同源，但可直接按 `modelcontextprotocol`、`mcp`、`langchain` 等关键词做**定向增量**。
   - **Tencent AI-Infra-Guard 的 `data/vuln` 漏洞库**（Apache-2.0、132 个 AI 组件目录、2000+ CVE 规则、含独立 `data/mcp` 规则集）——目前找到的**最贴近 Agent/AI 生态且许可明确**的结构化库。
   - **OSV API**（按包名/生态查询、聚合 GHSA + CVE + PyPA 等、有稳定 API）——适合把你库里的 `package_name`/`ecosystem` 字段变成可自动增量查询的入口。
4. **需要排除的**：`agentvuln.com`（待售域名，$149,888）、`aivulnerabilitydatabase.com`（不可达）、**AVID 数据库**（`avidml/avid-db` 仅 40 条 vulnerabilities、2023 年后停更，对你无用）。

## 1. Agent/AI 专属漏洞库

| 名称 | 形态与规模（实测） | 许可 | 更新 | 对本仓库的价值 |
|---|---|---|---|---|
| **Tencent AI-Infra-Guard** `data/vuln` | 仓库内结构化漏洞库：**132 个 AI 组件目录**，README 称 **2000+ CVE 规则 / 146+ AI 组件**；另有 `data/mcp`（15 条 MCP 规则：`cors`、`mcp_command_injection`、`mcp_credential_exfiltration`、`mcp_excessive_permissions`、`mcp_hardcoded_secrets`、`mcp_insecure_deserialization` 等）与 `data/agents`、`data/fingerprints`、`data/eval` | **Apache-2.0** | 活跃（2026-09-20 push，v4.6.2） | **高**。组件目录里直接出现 LangFlow、n8n、PraisonAI、vLLM、llama-cpp、MLflow 等，与你的 `environments/` 重合面大；规则可作为“该组件有哪些已公开 CVE”的交叉核对表。注意它是扫描器的规则库，**不提供 vulnerable/patched commit**，仍需回到 advisory 取修复对照 |
| **AVID**（AI Vulnerability Database） | `avidml/avid-db`：`vulnerabilities/` 只有 **40 条**（2022 年 13 + 2023 年 27），`reports/` 有 2025/2026 目录但库本身停止增长；网站 `avidml.org/database` 定义 Report 与 Vulnerability 两类；`api.avidml.org` 返回 **401**（需认证） | 见仓库 LICENSE | **停滞**（2026-03 push 但 vulnerabilities 仅到 2023） | **低**。作为“AI 失败模式分类学”参考可以，作为漏洞来源不可用 |
| **MITRE ATLAS** | `atlas.mitre.org` 可达；面向 AI 系统的对抗战术与技术知识库（类似 ATT&CK） | MITRE 条款 | 活跃 | **中**。用于给漏洞条目做**战术/技术标注**，不做条目来源 |
| **OWASP GenAI Security Project** | `genai.owasp.org`：LLM Top 10（2023/2024/2025）、**Agentic Security** 专项、AI Bill of Materials 等 | CC/OWASP | 活跃 | **中高**。你库里 `vulnerability_metadata` 已有 `owasp_agentic_category` / `owasp_llm_category` 字段但**当前全为空**（825 行 `agent_security_categories_json` 均为 `[]`）——这里是最直接的分类依据来源 |
| **AI Incident Database (AIID)** | `incidentdatabase.ai` 可达；真实世界 AI 事件库，含表格视图与分类法 | 见站点 | 活跃 | **低-中**。是“事件”而非“CVE”，但可用于 Agent 真实事故的案例佐证，不适合建复现环境 |
| **SkillTrustBench**（Tencent） | `matrix.tencent.com/skilltrustbench/`，T01–T09 技能安全风险分类法 | 见站点 | 活跃 | **中**。Agent **Skill** 是新的漏洞面（与 MCP server 并列），这套分类可作为 skill 类环境的判定维度 |

## 2. 通用库里的 Agent 定向检索（补齐你现有来源的增量）

这三个不是“新库”，而是**可执行的新入口**，我已实测可用：

### GitHub Advisory Database

```sh
# 按关键词（每页约 25 条，需翻页）
curl -s "https://github.com/advisories?query=modelcontextprotocol&page=1" \
  | grep -oE "GHSA-[a-z0-9-]+" | sort -u

# 按生态 + 关键词
curl -s "https://github.com/advisories?query=ecosystem%3Anpm+modelcontextprotocol"
```

实测命中：`modelcontextprotocol` **25+ 条**、`mcp` **27 条**（第 2、3 页各约 25 条，说明总量明显更多，必须翻页）、`ecosystem:npm + modelcontextprotocol` **23 条**、`langchain` 25+ 条。

**为什么它最适合你**：advisory 页面直接给出 **affected versions 与 patched version**，且通常链接修复 commit——正是 `docs/environment-contract.md` 要求的“固定源码 + 修复对照”。

### OSV API

```sh
curl -s -X POST https://api.osv.dev/v1/query \
  -d '{"package":{"name":"mcp","ecosystem":"PyPI"}}'
```

实测：`@modelcontextprotocol/sdk`（npm）**3 条**、`mcp`（PyPI）**12 条**、`langchain`（PyPI）**45 条**。返回 GHSA/CVE 别名、affected ranges、references。适合用你库里已有的 `package_name` + `ecosystem` 字段做**批量增量扫描**。

### NVD REST API

```sh
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=model%20context%20protocol&resultsPerPage=20&startIndex=0"
```

实测：关键词 `model context protocol` 共 **133 条**（分页参数 `startIndex` 已验证可用）。你库里已有专门的 “NVD Agent Security CVE Search” 来源（646 条 raw_items / 675 个 distinct vuln_id），这条通路可以用来做增量差分，而不是重建。

## 3. Agent/MCP 安全的策展清单与工具（含规则/语料）

| 名称 | 实测规模 | 内容 | 价值 |
|---|---|---|---|
| `Puliczek/awesome-mcp-security` | **738 stars** | MCP 安全论文（含 *Systematic Analysis of MCP Security*、*MCP Safety Audit*、*Beyond the Protocol* 等）、工具、MCP 安全 server、官方 spec 的安全要求 | **高**。是找“MCP 攻击面论文 + PoC 仓库”的入口，论文里常带具体攻击构造 |
| `slowmist/MCP-Security-Checklist` | **833 stars** | MCP 工具安全清单 | 中。做判定维度参考 |
| `snyk/agent-scan`（原 `invariantlabs-ai/mcp-scan`，301 重定向） | **3,080 stars**，活跃 | 扫描 harness / MCP server / **agent skills** 的 prompt injection 与恶意模式；自带技术报告 `skills-report.pdf` | **中高**。有 prompt injection 风险目录；官方声明 CLI 输出与 issue code **实验性、可能随时变**，不要依赖其字段做生产流程 |
| `NVIDIA/SkillSpector` | **18,113 stars** | Agent skill 安全扫描：漏洞、恶意模式 | 中。skill 面 |
| `cisco-ai-defense/skill-scanner` | **2,544 stars** | Agent skill 扫描 | 中 |
| `Tencent/AI-Infra-Guard` | **6,553 stars** | Agent Scan / MCP Scan / Skill Scan / Jailbreak 评测；自带 **FORGE-Bench、RogueHandoff-20**（agent 失控基准）与 SkillTrustBench | **高**（见 §1） |
| `msoedov/agentic_security` | **2,005 stars** | Agentic LLM 漏洞扫描 / 红队工具 | 中 |
| `splx-ai/agentic-radar` | **1,054 stars** | LLM agentic workflow 安全扫描（2025-11 后未更新） | 中 |
| `affaan-m/agentshield` | **1,214 stars** | agent 配置与 MCP 安全扫描 | 中 |

> 注意：这些是**扫描器/清单**，不是漏洞库。它们的价值在于**规则与攻击语料**——能告诉你“某个 MCP server 的哪类信任边界值得建环境”，但版本与修复对照仍要回到 §2 的三个通路取。

## 4. 基准与数据集（可作为环境/语料来源）

已在 `docs/agent-security-benchmarks.md` 详述，这里只列**可回收为环境来源**的部分：

- **CyberGym**：1,507 个漏洞 / 188 个项目，且**已打包成可复现 Docker 环境**（含 reproducer 与上游补丁）。ExploitGym 的用户态 520 个实例就是**直接复用 CyberGym 语料库**——这证明该语料可二次利用。
- **SEC-bench**：200 个经验证的 C/C++ CVE 实例，构建成本 **$0.87/实例**，含自动化构建流水线。
- **SEC-bench Pro**：344 个实例（V8 103 / SpiderMonkey 104 / Linux 内核 137），每个含 vulnerable/fixed/latest 三镜像。
- **ExploitGym**：898 个实例（用户态 520 / V8 185 / 内核 193）。

这四个都是**传统内存安全类**，不是 Agent/MCP 漏洞；但它们的**环境打包方式**（固定镜像、reproducer、修复对照）与你的 contract 同构，可作为构建流水线的参考。

## 5. 建议的增量路径

1. **先做分类补齐**：你库里 825 条 metadata 的 `agent_security_categories_json` 全为空、`owasp_agentic_category`/`owasp_llm_category` 未填。用 OWASP Agentic Security + SkillTrustBench T01–T09 建立分类，把“仅因为是 Agent/MCP 就标成 agent_unique 的普通 SSRF/路径穿越”筛掉——这与 `docs/agentsec-daily-candidates.md` 里已记录的判定原则一致。
2. **再用三个通路做定向增量**：以库里已有的 `package_name`/`ecosystem` 为输入，跑 OSV 批量查询 + GitHub Advisory 关键词翻页 + NVD 关键词分页差分，只取**带 patched version 或修复 commit** 的条目。
3. **用 AI-Infra-Guard 的 `data/vuln` 做交叉核对**：确认某个组件（如 PraisonAI、n8n、LangFlow、vLLM）的已公开 CVE 是否被你漏收；它的 132 个组件目录可以直接当 checklist。
4. **补 PoC 来源**：`Puliczek/awesome-mcp-security` 的论文列表 + `snyk/agent-scan` / `SkillSpector` 的规则语料，用于确认“该漏洞的触发输入长什么样”，再按 contract 做四场景对照。

## 6. 方法与本轮局限

- **web 搜索不可用**：`web_search` 返回 `DeepSeek search has no API key for "DEEPSEEK_API_KEY"`。因此无法做关键词式全网发现，只能**探测已知候选 + 直接调用一手 API**。这意味着**可能存在本清单未覆盖的来源**（尤其非英语、非 GitHub 托管的库）。
- 所有数量均为**本轮实测**：`curl` 直接调用 OSV / NVD / GitHub API，以及读取仓库 `contents/` 目录；未依赖任何二手描述。
- 本地库分析为**只读**：把 `agentsec_vulnerabilities.sqlite3` 复制到 `/tmp` 后查询，未修改原库，未读取 `.env`，未运行任何 PoC，未启动容器。
- GitHub API 未认证，core 限额 60/小时（本轮用掉 14），因此仓库检索做了抽样而非穷尽。
- 被排除的候选：`agentvuln.com`（域名待售）、`aivulnerabilitydatabase.com`（连接失败）、`aivulndb.github.io`（404）、`agent-vuln/agent-vuln-db`（404）、`microsoft/agent-threat-database`（404）。

## 参考入口

- Tencent AI-Infra-Guard：<https://github.com/Tencent/AI-Infra-Guard>（漏洞库 `data/vuln`、`data/mcp`）
- GitHub Advisory Database：<https://github.com/advisories>
- OSV：<https://osv.dev/> / API `https://api.osv.dev/v1/query`
- NVD API：<https://services.nvd.nist.gov/rest/json/cves/2.0>
- AVID：<https://avidml.org/database/> / 数据仓库 <https://github.com/avidml/avid-db>
- MITRE ATLAS：<https://atlas.mitre.org/>
- OWASP GenAI Security：<https://genai.owasp.org/>
- AI Incident Database：<https://incidentdatabase.ai/>
- awesome-mcp-security：<https://github.com/Puliczek/awesome-mcp-security>
- snyk/agent-scan：<https://github.com/snyk/agent-scan>
- SkillTrustBench：<https://matrix.tencent.com/skilltrustbench/>

相关仓库内文档：`docs/agentsec-daily-candidates.md`（候选与判定原则）、`docs/agent-security-benchmarks.md`（四个基准详述）、`docs/environment-contract.md`（环境收录要求）。
