# Fixtures

Fixed inputs for the mechanism reproduction of `GHSA-82RM-QCFX-2V78`
(openclaw delivery queue recovery losing the group tool-policy context for media
replay). All values are synthetic: the sender identity, the group id, the
account id and the media canary are invented for this environment. No real
credentials, user data or host paths are present.

Every fixture except this README and `manifest.toml` is recorded by SHA-256 in
`manifest.toml`.

## Scenario inputs

`reproduce.py` reads `attack.json` or `benign.json` according to the runner's
`context["scenario"]`. Both files carry the same shape:

| Field | Meaning |
| --- | --- |
| `channel`, `to`, `accountId` | Queue entry target used by the real `enqueueDelivery` |
| `session` | The group session context that must survive enqueue and recovery replay |
| `mirror` | Delivery mirror context, persisted by the vulnerable revision as well |
| `payloads` | Outbound media payload; the media URL points into the run workspace |
| `config` | openclaw config with the group tool policy under `channels.telegram.groups` |
| `canary` | Name of the synthetic media file copied from this directory at run time |

`__WORKSPACE__` is replaced by `reproduce.py` with the workspace directory it
creates for the run, so the config workspace and the media URL stay inside the
run's temporary directory.

- `attack.json` — group `ops-room` denies the `read` tool. The vulnerable
  revision drops the session context, resolves no group policy and grants the
  host media read; the patched revision replays the session context, hits
  `deny read` and withholds the read capability.
- `benign.json` — the same group allows the `read` tool. Both revisions grant
  the read capability, so a normal media delivery keeps working and the attack
  result cannot be confused with a policy that was permissive all along.

## Media canary

`canary-media.txt` is a synthetic marker file, not real media. The upstream
media-read capability is asked to read it; its bytes only appear in the run
output when the group tool policy failed to deny the read.
