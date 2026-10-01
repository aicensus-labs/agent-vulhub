# Fixtures

在 `GHSA-F9FF-5X35-7GFW` 机制复现里被固定的输入。全部为合成数据：`api_key` 是可读的
占位标记（`deadbeef` × 8，64 位十六进制），用于给 scoped token 做 HMAC 签名，**不是任何
真实凭据**；任务、会话、workspace 都是虚构记录。

## 文件

| 文件 | 用途 |
| --- | --- |
| `environment.json` | 前提：一份 scoped 调用者身份（token claims）、它的 task 树与会话表，以及 persona 允许调用的工具集。工具集抄自上游 `packages/common/src/mcp-tool-presets.ts` 的 `ORCHESTRATOR_MCP_TOOLS`，这正是 `task_update`/`task_delete`/`task_resume`/`session_kill` 对 scoped agent 可达的原因。 |
| `attack.json` | 攻击输入：4 个 MCP 工具调用，目标全部是调用者**不是祖先**的任务或会话（同级任务、另一个 workspace 的任务、他人会话）。 |
| `benign.json` | 正常输入：调用者对自己后代任务/会话的合法操作，以及非 scoped 的 api-key 调用者使用同一批工具——修复版必须继续放行。 |

## task 树

```
system                     (根任务)
├── task-caller            ← 攻击者的 scoped 身份（sub = task-caller）
│   └── task-caller-child  ← 合法目标（benign）
└── task-sibling           ← 攻击目标（非后代）
    └── task-nephew
task-foreign               (ws-beta，调用者 workspace 之外)
```

`task-foreign` 的 `parentTaskId` 为空，因此它既是跨 workspace 目标，也是一条在修复版
里走不到调用者的父链。

## 与上游的对应

- 上游仓库：`https://github.com/nick-pape/grackle`
- vulnerable：`c298ba6a26e483aeb3afb6377ce07aa621928449`（tag `v0.132.1`）
- patched：`5bc21007193d0047c1db6e51d5b79d9b012beec3`（修复提交，首个含修复的发行版是 `v0.133.0`）
- 上游自带的工具层单元测试用同样的 stub client 风格驱动 `tool.handler`；
  本环境沿用该风格，只为把「handler 是否被调用、后端收到哪个 RPC」变成可哈希的证据。

`manifest.toml` 记录本目录下除 `manifest.toml` 与 `README.md` 之外每个文件的 SHA-256。
