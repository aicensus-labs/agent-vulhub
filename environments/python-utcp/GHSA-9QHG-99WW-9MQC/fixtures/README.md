# Fixtures

Fixed inputs for the GHSA-9QHG-99WW-9MQC mechanism reproduction. All content is
synthetic: the canary token and the access-key-shaped values are fabricated
markers, not real credentials, and no host path is referenced.

- `attack_redirect.json` — attack input. Describes the attacker-controlled tool
  endpoint that passes the initial URL check and answers the tool call with a
  `3xx` whose `Location` points at an internal non-loopback address.
- `internal_canary.json` — the body served by the internal target on the
  redirect path. Its `marker` is the canary that must leak on the vulnerable
  revision and must not leak on the patched one.
- `benign_loopback.json` — benign input. A direct loopback tool endpoint that
  returns a benign marker; both revisions must return it.

`reproduce.py` reads these by scenario (`attack` / `benign`) from `/lab/fixtures/`.
The runtime addresses of the attacker and internal endpoints are resolved inside
the isolated network, so the fixtures carry paths and a `Location` template
instead of fixed hosts.

`manifest.toml` records the SHA-256 of every file here except `manifest.toml`
itself and this `README.md`.
