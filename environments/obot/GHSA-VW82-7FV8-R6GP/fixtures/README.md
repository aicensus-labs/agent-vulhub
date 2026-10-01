# fixtures — GHSA-VW82-7FV8-R6GP

Fixed inputs and the driver that calls the pinned upstream authorization code.
Nothing here contains real credentials, real user data or host paths.

## `attack.json`

A catalog MCP server `ms1catalog` in `catalog-a`, owned by `owner-uid`, and one
access control rule that grants that server only to `authorized-uid`. The
attacker is `attacker-uid`: authenticated (`basic`, `authenticated`) but not an
ACR subject. Two cases:

| case | expectation |
| --- | --- |
| `authorized_user_reaches_catalog_server` | allowed (the ACR subject) |
| `unprivileged_user_reaches_catalog_server` | denied (the ACR says no) |

The second case is the bypass. In v0.21.0 `staticRules[anyGroup]` contains the
subtree pattern `/mcp-connect/`, so `Authorizer.Authorize` returns `true` before
`authorizeAPIResources` reaches `checkMCPID`; the UI fallback would allow the
same path as well. In v0.21.1 both escapes are gone and
`UserHasAccessToMCPServerInCatalog` denies `attacker-uid`.

## `benign.json`

The normal task: a Basic user reaches the single-user server instance they own,
the single-user server they own, and a catalog server their ACR grants them.
All three cases must be allowed in both revisions.

## `harness/zz_ghsa_vw82_harness_test.go`

The driver. `reproduce.py` copies it into the pinned tree at
`pkg/api/authz/zz_ghsa_vw82_harness_test.go` and runs
`go test ./pkg/api/authz/ -run TestGeneratorHarness -v`. The driver only uses
APIs that exist in both pinned revisions:

- `clientfake.NewClientBuilder().WithScheme(storagescheme.Scheme).WithObjects(...)`
  holding `v1.MCPServer` / `v1.MCPServerInstance` objects;
- a `k8s.io/client-go/tools/cache` indexer with the `user-ids`,
  `catalog-entry-names`, `server-names` and `selectors` indexers, plus
  `accesscontrolrule.NewAccessControlRuleHelper(indexer, storage)`;
- `NewAuthorizer(storage, storage, false, acrHelper, false)`, the upstream
  constructor, so `apiResources`/`rules`/`uiResources` are built by the pinned
  code instead of being hand-assembled;
- `authorizer.Authorize(req, user)` — the same single decision point the API
  server calls.

It never calls `checkMCPID` directly, so it does not depend on
`system.IsSystemMCPServerID`, `v1.SystemMCPServer` or `GroupAPIKey`
API-resource entries that only exist in v0.21.1. The report it writes
(`authorize-report.json`) is the evidence; the process exits non-zero when a
case does not match its expectation, and a denial is a completed execution, not
a build failure.

The Go test transcript is parsed as a second copy of the same result
(`--- PASS: TestGeneratorHarness/<case>`), so the raw decision and the
per-case verdict can be compared.

## Build-stage expectations

`reproduce.py` needs, inside the image:

- a pinned Go toolchain (>= 1.26.2) with a populated module cache (`GOPROXY=off`
  is set by the script, so the build must pre-download the modules);
- the pinned vulnerable tree (v0.21.0,
  `821a705516116c8035df221611be4a439e238998`) at `/lab/src/vulnerable`;
- the pinned patched tree (v0.21.1,
  `2a2ec3f23ac564b2e2fab6b09fdef4ecd05fd496`) at `/lab/src/patched`;
- `/lab/fixtures/` containing this directory.

The first `go test` of the authz package compiles a large dependency graph; if
the module cache is incomplete the run reports a build error instead of a
verdict.
