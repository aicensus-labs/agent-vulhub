# Fixtures

`reproduce.py` runs the pinned upstream OAuth 2.1 consent and token services
from the two n8n releases this advisory fixes, so most of what lives here is
verbatim upstream code rather than hand-written input.

## Scenario inputs

| File | Purpose |
| --- | --- |
| `attack.json` | A member-level user mints an access token for another user's active MCP Server Trigger resource and invokes it. |
| `benign.json` | The user who does hold `workflow:execute` runs the same consent and token flow against their own workflow. |

Both files are synthetic: the user ids, workflow id, resource URL and callback
are invented, and no real credential or host path appears anywhere. The `access`
rows state the `workflow:execute` facts the pinned authorization decision is
compared against.

## Pinned upstream code

`upstream/2.29.7/` and `upstream/2.29.8/` hold the compiled CommonJS payloads
copied byte-for-byte from the official npm releases of the two pinned revisions:

| Release | Tarball SHA-256 | npm integrity (sha512) |
| --- | --- | --- |
| `n8n@2.29.7` | `cf98d3c9a35e730681b0e4afc881c60e55ecfc96f24aa94b49b458923167b341` | `sha512-rSJEZzcYHjX0FDKuY7MitO8EmagWN0HXcjfUADg115AOuzE7ztycuokOA2d4saehqIa5wPxLykG74YH0u9/rzw==` |
| `n8n@2.29.8` | `c6095893f456ea3e8c72ab7434fdaf5fcf6d29784979dc53107443bf2baf26ce` | `sha512-6qOLCA3g3LoGxxCGb/5DOUrf08fbfl5dlAMkITuhLPG29YKvlaNsO34ApxxLk+P3y10BMWxbyRUWBe+dXtx+JA==` |

Only the import closure of the OAuth authorization entrypoints is copied, and
`reproduce.py` hash-checks every file against `manifest.toml` before executing
any of it. The two releases agree byte-for-byte on most of the closure; the
authorization divergence is entirely in `oauth-consent.service.js`,
`oauth-token.service.js` and the `forbidden.error.js` the patch adds.

The workflow-trigger resolver is not part of the copied closure. It pulls in the
whole webhook, node-type, push and license graph for one descriptor object, so
`harness/runner.js` materialises that descriptor from the scenario facts instead
and records whether the pinned services consult its `authorize` member. Every
authorization decision stays inside the upstream modules.

## Harness

`harness/loader.js` resolves the pinned payloads' imports at run time: anything
inside `upstream/` loads untouched, `@n8n/*` and third-party specifiers resolve
to `harness/shims/`, and any other specifier fails loudly. The shims are
adapters — in-memory repositories, a local HS256 signer with the same shape as
`jsonwebtoken`, and no-op decorator factories — and each one says so at the top
of the file. They contain no part of the vulnerability.

## Manifest

`manifest.toml` lists every file in this directory except itself and this
README, with its SHA-256. Regenerate it after any change with the Generator-side
helper `staging/research/n8n/GHSA-5VFW-JC4P-FJ39/write-manifest.py`, and audit
the vendored payloads against the pinned tarballs with the sibling
`verify-vendor.py`.
