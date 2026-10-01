# Fixtures

Fixed inputs for the GHSA-W46P-W7W2-FR9G mechanism reproduction. All identities,
credentials and node parameters are synthetic markers; no real credential, user
record or host path appears here.

`reproduce.py` copies the fixture selected by the execution context into the Node
harness. The harness loads the real `AgentRuntimeReconstructionService` and
`resolveNodeTool` from the image's pinned source tree and drives them; these
fixtures only describe the world those upstream classes run against.

## Case inputs

| File | Purpose |
| --- | --- |
| `attack-vulnerable.json` | Project Viewer (`agent:execute`, no `workflow:execute`) plus an agent whose node tool references `n8n-nodes-base.executeCommand` with a project credential the viewer cannot read. It models the 2.29.7 chat controller, which hands only `userId` to the runtime. |
| `attack-patched.json` | Same world and same attacker, but models the 2.29.8 chat controller, which hands the full `user` object down so the new filter can run. |
| `benign.json` | A project member who legitimately holds `workflow:execute` and `credential:read` and whose agent uses `n8n-nodes-base.httpRequest` with a credential it owns. The node tool must keep working in both revisions. |

Field notes shared by the case inputs:

- `marker` is the synthetic value the executor returns, so a run proves which
  node actually reached the executor.
- `credentials[].owner` / `sharedWith` model project credential sharing. The
  attacker fixture marks the credential shared with the project without granting
  the viewer `credential:read`.
- `agent.schema.tools` is the `AgentJsonConfig.tools` list the runtime rebuilds
  from. `type: "custom"` entries stand for n8n-authored tool code and are never
  filtered by either revision.
- `invocation` is the argument the model would emit when it calls the resolved
  node tool, i.e. what the executor receives as `inputData`.

## Harness

| File | Purpose |
| --- | --- |
| `n8n_harness.mjs` | Instantiates the pinned upstream service, runs tool reconstruction, invokes the surviving node tool and records what reached the node executor. |
| `n8n_loader.mjs` | ESM loader that serves the pinned `.ts` files (Node cannot parse n8n's legacy decorators) and the dependency doubles. |
| `n8n_doubles.mjs` | Storage/DI/LangChain doubles: project credential sharing, workflow access, a recording node executor. It reimplements no authorization decision. |

The harness never decides whether the node tool survives: that outcome comes from
the upstream class body of the revision in the image. The recording executor is a
stand-in for `EphemeralNodeExecutor`, which needs a full n8n deployment
(TypeORM, `n8n-core` execution contexts, node type packages) to run.
