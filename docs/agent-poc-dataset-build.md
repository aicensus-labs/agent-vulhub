# Agent-PoC Dataset Build

The runnable scoring set admits only source environments with current mechanism evidence, a reviewed Level 1 description, and an accepted Candidate Adapter. A task package, historical passing report, or successful control run by itself is not a scoring sample.

## Mechanism Rebuild Wave

The pinned wave at `.github/agent-poc-rebuild-wave-20261011.json` contains 275 source environments whose retained three-round mechanism reports passed historically but no longer match current inputs. Each entry includes the input fingerprint from the audited checkout. `python3 -m scripts.rebuild_wave --offset N --limit M` checks the selected slice against the registry and emits the matrix; it refuses unregistered, binary, duplicate, or changed entries. One dispatch can select at most 100 environments.

Run `.github/workflows/reproduce-wave.yml` from the default branch containing the wave manifest and audited environment inputs. Dispatch offsets `0`, `100`, and `200` with limit `100` to cover the wave, waiting for each run to finish before starting the next so total concurrency stays at three jobs. Each job runs on a fresh GitHub-hosted Linux VM, builds from pinned source, runs three rounds of the four-case matrix, and retains its report, case evidence, and logs as a 90-day artifact.

Workflow success only means the jobs completed. Download each artifact and review its complete report, four-case results, source identity, effects, logs, cleanup, and redaction. Only then archive a passing report into its draft environment with `python3 -m runner archive <environment-id> --report <path-to-report.json>`. This records current mechanism evidence without promoting the environment to `ready`.

## Candidate Adapter Admission

After mechanism evidence is current, create or validate the Level 1 task package and finish the environment's candidate adapter. The Adapter is the existing environment harness and verifier path that consumes the candidate and measures product effects; it is not a second runner. Keep two distinct candidate artifacts: one expected to demonstrate the effect, and one that does not trigger it.

Run both controls through the pre-admission command. The negative command exits successfully only when the vulnerability attack fails while patched attack and both benign cases pass; its report outcome remains `failed` because that candidate did not score.

```sh
python3 -m runner agent-task <environment-id> --level 1 --out-dir <task-dir>
python3 -m runner agent-control <environment-id> --role positive --task-dir <task-dir> \
  --candidate <positive-candidate-dir> --images <build.json> --rounds 3
python3 -m runner agent-control <environment-id> --role negative --task-dir <task-dir> \
  --candidate <negative-candidate-dir> --images <build.json> --rounds 3
python3 -m runner agent-control-archive <environment-id> --task-dir <task-dir> \
  --report <positive-report.json>
python3 -m runner agent-control-archive <environment-id> --task-dir <task-dir> \
  --report <negative-report.json>
```

Review both archived reports and every case's independent verifier evidence. Add one review record under the environment's `evidence/` directory. It must contain `Decision: accepted`, `Reviewed: YYYY-MM-DD`, the Level 1 task SHA-256, and the SHA-256 values of both archived control reports and both archive manifests. Then set `verification.agent_poc.adapter_status = "accepted"`, record that same task hash in `verification.agent_poc.task_sha256`, and point `evidence` to the two role-named JSON reports and the review record. Set `verified_at` to the review date and include a concise rationale in `notes`.

The control reports must be distinct artifacts, bind the current environment and runner fingerprints and the same task hash, and include at least three complete rounds. Positive control requires all four cases to pass. Negative control requires only the vulnerable attack case to fail; the patched attack and both benign cases must pass. `runner check` and `agent-evaluate` revalidate each archive manifest, archived case result, verifier context and verdict before admission and execution. Scoring also requires the submitted Level 1 task package's `task_sha256` to match the accepted Adapter exactly; Level 0 and other task packages are rejected.

After `python3 -m runner check` passes, generate the formal runnable manifest:

```sh
python3 -m runner agent-manifest --output results/agent-poc-dataset/manifest.json
```

The command includes only currently accepted samples and binds their task hashes, environment and runner fingerprints, mechanism evidence, and Adapter controls. An empty manifest means the scoring set is still empty. At the start of this wave, 22 Level 1 task packages had been prepared, but none had current mechanism evidence or an accepted Adapter, so there were no formal scoring samples.
