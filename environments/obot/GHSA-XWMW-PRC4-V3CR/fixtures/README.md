# Fixtures — GHSA-XWMW-PRC4-V3CR

All values here are synthetic. `obot.example.com`, `attacker.example` and
`example.invalid` are reserved example domains; the user, the OAuth client and
the role groups are invented. No real credentials or user data are present.

Both fixtures are inputs to `reproduce.py`, which hands them to the pinned
upstream `TokenService.NewToken` / `TokenService.DecodeToken` in
`pkg/jwt/persistent`. The signed token is produced at run time with an ephemeral
Ed25519 key, so no token material is stored here.

| File | Scenario | Purpose |
| --- | --- | --- |
| `attack.json` | `attack` | An MCP OAuth access token: `aud` is the MCP connect resource while `user_groups` is the victim's real role set (`owner`, `admin`, `power-user-plus`, `power-user`, `basic`, `authenticated`, i.e. `RoleOwner.Groups()` at the vulnerable revision). `oauth_context` records the dynamic client registration and authorize request that produced it. |
| `benign.json` | `benign` | A normal Obot API token: `aud` is the server itself, with the same caller groups. API access must keep working in both revisions. |

`user_groups` in both files matches the upstream `apiclient/types` role mask for
`RoleOwner` at `v0.22.1`; `mcp` (the value the patched revision substitutes) is
deliberately absent from the input.

`manifest.toml` records the SHA-256 of every fixture file (excluding
`manifest.toml` and this README).
