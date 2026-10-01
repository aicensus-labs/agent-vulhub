# Fixtures

Fixed inputs for `n8n-mcp/GHSA-8G7G-HMWM-6RV2`. They are test inputs, not
instructions for maintainers, and every identifier, key, header value and
response body in them is a synthetic marker (`sk-test...`). No real credential,
real host or private user data appears here.

| File | Purpose |
| --- | --- |
| `inputs.json` | Attack and benign inputs for the three mechanisms the advisory bundles. |

`inputs.json` carries:

- `archives`: the pinned package version and archive name per variant, matching
  the `[build].inputs` names in `metadata.toml` (`n8n-mcp-2.50.0.tgz` for the
  vulnerable revision, `n8n-mcp-2.50.1.tgz` for the patched one). The PoC also
  falls back to any `*.tgz` whose name contains the version, so a differently
  named build input still resolves.
- `markers`: the three synthetic secret values used by the checks. They exist
  only so a leak is unambiguous; none of them is valid anywhere.
- `environment.WEBHOOK_SECURITY_MODE`: `permissive`. The shipped SSRF check
  still blocks the cloud-metadata hostnames in this mode; it only admits
  loopback and private destinations, which is what makes a purely local
  redirect hop observable without any external network.
- `traversal`: the crafted workflow identifier `../credentials`, the same-origin
  path it normalises to (`/api/v1/credentials`), the synthetic n8n API key the
  client attaches, and the synthetic credential listing that endpoint returns.
  The listing is the protected data the crafted identifier must not reach.
- `redirect`: the validated webhook path, the loopback redirect target, and its
  synthetic response body. The redirect target is never covered by the one-shot
  SSRF check, which is exactly the gap the fix closes.
- `telemetry`: the synthetic bearer token placed in a node parameter update,
  plus the credential-free mutation (value and expected `operations` /
  `validationBefore`) that must produce the same record on both revisions.
- `benign`: a normal workflow identifier and a direct webhook post. Both must
  behave identically on the vulnerable and patched revisions, so a passing
  attack cannot be explained by general breakage.

All listeners are loopback ports owned by the reproduction process. Nothing is
contacted outside the container.

`manifest.toml` records the SHA-256 of every file here except `manifest.toml`
and this `README.md`.
