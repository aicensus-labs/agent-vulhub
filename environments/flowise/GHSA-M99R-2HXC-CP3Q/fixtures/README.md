# Fixtures

本目录只放复现 `flowise/GHSA-M99R-2HXC-CP3Q` 机制所需的固定输入，全部为上库合成的
无害数据，不含真实凭据、真实用户数据或宿主路径。`manifest.toml` 的 `[files]` 按相对
路径记录每个 fixture 的 SHA-256（`manifest.toml` 与 `README.md` 除外）。

## 攻击输入

| 文件 | 用途 |
| --- | --- |
| `attack_config.json` | 攻击者提交的 Custom MCP 节点配置：`command` 为白名单内的 `node`，`args[0]` 写成占位符 `__MCP_PAYLOAD_PATH__`，由 `reproduce.py` 替换为 payload 在容器内的双斜杠绝对路径。它绕过 `validateArgsForLocalFileAccess` 的 `/^\/[^/]/` 判定。 |
| `mcp_payload.js` | 攻击者预先落盘在服务器上的 JS。被 `node` 子进程加载后，只把一行执行标记写进继承来的工作目录（`/lab/results/.ghsa-mcp-child-effect.txt`），不做其他动作。 |

## 正常输入

| 文件 | 用途 |
| --- | --- |
| `benign_config.json` | 正常任务配置：同一个 `node` 命令，参数是合法相对路径的 MCP stdio server；漏洞版与修复版都应接受。 |
| `mcp_server.js` | 上面配置加载的合法 MCP stdio server，按行处理 JSON-RPC，支持 `initialize` / `tools/list` / `tools/call`，暴露一个只做回显的工具 `ghsa_echo`，本身不产生任何执行标记。 |

## 简化说明

advisory 的完整链路还包含“先上传 payload、再借 `/api/v1/export-import/chatflow-messages`
取回其服务器绝对路径”这一步。机制复现把它当作已成立前提，直接把 payload 放置在
容器内的 `/lab/fixtures/mcp_payload.js`。图解与 `reproduce.py` 都按这一点书写。
