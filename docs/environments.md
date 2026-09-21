# 环境索引

本页提供面向读者的环境列表；机器可读的唯一索引是 [`environments.toml`](../environments.toml)。当前所有环境的生命周期均为 `draft`，其中 31 个机制验收通过，8 个尚未运行。`passed` 只表示机制层结果，不代表环境已经 `ready`。

| 环境 | 漏洞标识 | 机制状态 |
| --- | --- | --- |
| [agent-device](../environments/agent-device/GHSA-M7Q5-6423-2MWQ/) | `GHSA-M7Q5-6423-2MWQ` | `passed` |
| [chainlit](../environments/chainlit/CVE-2026-45018/) | `CVE-2026-45018` | `passed` |
| [claude-code-action](../environments/claude-code-action/CVE-2026-47751/) | `CVE-2026-47751` | `not_run` |
| [factoryfloor](../environments/factoryfloor/CVE-2026-88063/) | `CVE-2026-88063` | `not_run` |
| [flowise](../environments/flowise/CVE-2026-70477/) | `CVE-2026-70477` | `not_run` |
| [hackmd-mcp](../environments/hackmd-mcp/CVE-2025-59155/) | `CVE-2025-59155` | `passed` |
| [ios-simulator-mcp](../environments/ios-simulator-mcp/CVE-2025-52573/) | `CVE-2025-52573` | `passed` |
| [mcp-atlassian](../environments/mcp-atlassian/GHSA-wm45-qh3g-v83f/) | `GHSA-wm45-qh3g-v83f` | `passed` |
| [mcp-filesystem](../environments/mcp-filesystem/CVE-2025-53109/) | `CVE-2025-53109` | `passed` |
| [mcp-filesystem](../environments/mcp-filesystem/CVE-2025-53110/) | `CVE-2025-53110` | `passed` |
| [mcp-gateway](../environments/mcp-gateway/GHSA-g53w-w6mj-hrpp/) | `GHSA-g53w-w6mj-hrpp` | `not_run` |
| [mcp-server-git](../environments/mcp-server-git/CVE-2025-68143/) | `CVE-2025-68143` | `passed` |
| [mcp-server-kubernetes](../environments/mcp-server-kubernetes/CVE-2026-61459/) | `CVE-2026-61459` | `passed` |
| [n8n](../environments/n8n/CVE-2026-86996/) | `CVE-2026-86996` | `passed` |
| [node-code-sandbox-mcp](../environments/node-code-sandbox-mcp/CVE-2025-53372/) | `CVE-2025-53372` | `passed` |
| [omnigent](../environments/omnigent/CVE-2026-62674/) | `CVE-2026-62674` | `not_run` |
| [open-webui](../environments/open-webui/CVE-2026-87017/) | `CVE-2026-87017` | `passed` |
| [openharness](../environments/openharness/CVE-2026-56696/) | `CVE-2026-56696` | `passed` |
| [vtcode](../environments/vtcode/GHSA-WQGW-CRR5-CR2P/) | `GHSA-WQGW-CRR5-CR2P` | `not_run` |
| [praisonai](../environments/praisonai/CVE-2026-34955/) | `CVE-2026-34955` | `passed` |
| [praisonai](../environments/praisonai/CVE-2026-40149/) | `CVE-2026-40149` | `passed` |
| [praisonai](../environments/praisonai/CVE-2026-40156/) | `CVE-2026-40156` | `passed` |
| [praisonai](../environments/praisonai/CVE-2026-40158/) | `CVE-2026-40158` | `passed` |
| [praisonai](../environments/praisonai/CVE-2026-44334/) | `CVE-2026-44334` | `passed` |
| [praisonai](../environments/praisonai/CVE-2026-44339/) | `CVE-2026-44339` | `passed` |
| [praisonai](../environments/praisonai/CVE-2026-47391/) | `CVE-2026-47391` | `passed` |
| [praisonai](../environments/praisonai/CVE-2026-47395/) | `CVE-2026-47395` | `passed` |
| [praisonai](../environments/praisonai/CVE-2026-55527/) | `CVE-2026-55527` | `passed` |
| [praisonai](../environments/praisonai/CVE-2026-55530/) | `CVE-2026-55530` | `passed` |
| [praisonai](../environments/praisonai/CVE-2026-55532/) | `CVE-2026-55532` | `passed` |
| [praisonai](../environments/praisonai/CVE-2026-55540/) | `CVE-2026-55540` | `passed` |
| [praisonai](../environments/praisonai/CVE-2026-56833/) | `CVE-2026-56833` | `passed` |
| [praisonai](../environments/praisonai/CVE-2026-57117/) | `CVE-2026-57117` | `not_run` |
| [praisonai](../environments/praisonai/CVE-2026-57120/) | `CVE-2026-57120` | `passed` |
| [praisonai](../environments/praisonai/CVE-2026-57125/) | `CVE-2026-57125` | `passed` |
| [praisonai](../environments/praisonai/CVE-2026-57129/) | `CVE-2026-57129` | `passed` |
| [praisonai](../environments/praisonai/CVE-2026-61428/) | `CVE-2026-61428` | `passed` |
| [praisonai](../environments/praisonai/CVE-2026-61439/) | `CVE-2026-61439` | `passed` |
| [praisonai](../environments/praisonai/CVE-2026-61445/) | `CVE-2026-61445` | `not_run` |

每个环境目录中的 `README.zh-cn.md` 说明具体漏洞、版本、运行方式和限制。环境状态以 `metadata.toml` 和执行结果为准；新增或变更环境时请同步更新本页。
