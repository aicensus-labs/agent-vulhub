# Fixtures — GHSA-GFG9-5357-HV4C

Fixed inputs for the mechanism reproduction of
`openclaw/GHSA-GFG9-5357-HV4C` (webchat audio embedding without local-root
containment). Everything here is synthetic marker content: no real credentials,
no real user data, no host paths.

`reproduce.py` reads exactly one of the two reply files, depending on
`context["scenario"]`, then copies every `materialize[]` entry from this
directory to its target path inside the lab container before it drives the
pinned upstream code. The absolute paths in the JSON files are the container
layout, not host paths.

| Path | Role |
| --- | --- |
| `attack/injected_reply.json` | Attack input: a tool/agent reply whose `mediaUrl` / `mediaUrls` are chosen by the attacker. Both targets sit outside the allowed media root; the second uses a `file:` URL. |
| `attack/voice-memo.mp3` | Out-of-root local audio file (marker `AVH-SYNTHETIC-AUDIO-MARKER voice-memo`), read through a plain absolute path. |
| `attack/meeting-notes.mp3` | Second out-of-root local audio file (marker `AVH-SYNTHETIC-AUDIO-MARKER meeting-notes`), read through a `file:` URL. |
| `benign/legitimate_reply.json` | Benign input: a reply that references audio inside the allowed media root. |
| `benign/greeting.mp3` | In-root audio file (marker `AVH-SYNTHETIC-AUDIO-MARKER greeting`). Both revisions must embed it. |

## Expected observable effects

`reproduce.py` writes `media_blocks.json` (the exact value returned by the
upstream `buildWebchatAudioContentBlocksFromReplyPayloads`) and
`embedded_audio_base64.txt` (one base64 payload per returned audio block) into
the result directory.

- vulnerable + `attack`: two audio blocks; decoding them yields the
  `voice-memo` and `meeting-notes` markers.
- patched + `attack`: zero audio blocks, and the upstream
  `onLocalAudioAccessDenied` callback fires for each rejected path.
- benign (both revisions): exactly one audio block whose decoded content
  carries the `greeting` marker, and no denial.

The audio files are named `*.mp3` because the upstream path gate is an
extension check (`isAudioFileName`); their bytes are text markers, which keeps
the assertion exact without shipping real media.

`manifest.toml` records the SHA-256 of every file in this directory except
`manifest.toml` and `README.md`; it is regenerated after any fixture change.
