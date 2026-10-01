# Fixtures — GHSA-5648-rgj9-v224

Fixed inputs for the mechanism PoC. All values are reserved documentation values;
no real credentials, instance addresses, or host paths appear here.

| File | Purpose |
| --- | --- |
| `cases.json` | The attack document set (`attack_queries`) and the benign document set (`benign_queries`). The attack set holds the leading-comma mutation, the comment-then-comma mutation, the trailing-comma subscription, and a plain mutation as a control. |
| `allowlist-scope.json` | Deployment scope for the allow-list path: allowed project ids, the project id outside the allow-list, and the raw GraphQL endpoint the tool forwards to. |
| `pin.json` | The two pinned upstream revisions: tag, commit, archive URL + SHA-256, and the SHA-256 of `utils/graphql-query.ts` inside each archive. `reproduce.py` refuses to run when the module hash it loads differs. |
| `graphql-driver.mjs` | Node driver run against the pinned checkout. It imports the upstream classifier, calls `graphqlQueryContainsWriteOperation()` on every fixed document, and extracts the `execute_graphql` branch and `rejectIfProjectScopedDeployment` definition from the pinned `index.ts`. It contains no copy of the vulnerable logic. |

`manifest.toml` records the SHA-256 of every file in this directory except itself
and this README.

`pin.json` names the checkout as `/lab/upstream/<variant>`. An image that places
the checkout elsewhere can set `AVH_UPSTREAM_ROOT` to the directory that replaces
`/lab` (the `upstream/<variant>` tail is preserved).
