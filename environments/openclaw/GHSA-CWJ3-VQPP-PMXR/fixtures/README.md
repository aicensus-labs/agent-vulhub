# Fixtures

Fixed inputs for GHSA-CWJ3-VQPP-PMXR. All values are synthetic; no real
credentials, user data or host paths are present.

| File | Role |
| --- | --- |
| `current-config.json` | The operator's current config snapshot (`config.get` result). Used as `currentConfig` for every case. |
| `attack-patch.json` | `config.patch` raw document that writes five operator-trusted paths the 2026.4.22 denylist does not cover: `gateway.remote.url`, `memory.qmd.command`, `browser.executablePath`, `tools.allow`, `tools.elevated.enabled`. |
| `attack-apply.json` | Full replacement document for `config.apply` carrying the same out-of-list values. |
| `benign-patch.json` | Legitimate `config.patch` that only changes `agents.defaults.systemPromptOverride`, which both revisions must allow. |
| `control-protected-patch.json` | Control input that changes `tools.exec.ask`; the old denylist and the new allowlist both reject it, so it proves the guard is not a blanket no-op. |

Reproduction reads these files from `/lab/fixtures` and passes each raw
document verbatim to the pinned upstream guard; no fixture is executed as a
script. `manifest.toml` records the SHA-256 of every file above.
