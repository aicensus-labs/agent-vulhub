# Fixtures

- `attack.toml`: synthetic workspace with a fixed, workspace-local marker session_start hook.
- `benign.toml`: otherwise identical workspace without a lifecycle hook.
- The marker command performs no network access and does not read credentials.
