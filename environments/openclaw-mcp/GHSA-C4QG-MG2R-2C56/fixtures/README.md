# Fixtures

Fixed inputs for the mechanism reproduction. All markers are synthetic; no real
credentials, user data, or host paths are present.

| File | Scenario | Purpose |
| --- | --- | --- |
| `attack.json` | `attack` | Connection A queues one async chat task with a marker prompt; connection B, on its own MCP session, enumerates tasks and reads A's task by ID. The controlled gateway echoes the prompt with `OPENCLAW-LAB-ATTACK-REPLY:` so the leaked result is unambiguously A's data. |
| `benign.json` | `benign` | Two independent connections each queue and read their own async chat task. Both must succeed in the vulnerable and the patched revision. |

`manifest.toml` records the SHA-256 of every fixture file except itself and this
README. Regenerate it after editing an input:

```sh
sha256sum fixtures/attack.json fixtures/benign.json
```
