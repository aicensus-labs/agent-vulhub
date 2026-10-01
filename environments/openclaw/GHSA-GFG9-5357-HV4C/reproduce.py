"""Mechanism PoC for GHSA-GFG9-5357-HV4C (openclaw webchat audio embedding).

This entrypoint does not reimplement the vulnerability. It drives the pinned
upstream TypeScript module

    <source-root>/src/gateway/server-methods/chat-webchat-media.ts

at the revision baked into the image, using the real
``buildWebchatAudioContentBlocksFromReplyPayloads`` implementation and the
fixed reply payloads from ``/lab/fixtures``.

Image contract (the build recipe must provide all three, all offline):

  * ``/opt/openclaw`` (or ``$OPENCLAW_SOURCE_ROOT``)
        full upstream source tree of exactly one revision. Vulnerable
        ``v2026.4.14`` = 323493fa1b6adc1e10b9954a68d5eaa5a6ef1170; patched
        ``v2026.4.15`` = 041266a6699cac3baef8ef39db41fa26f29f9db3.
  * ``/opt/openclaw-deps/node_modules`` (or ``$OPENCLAW_DEPS_ROOT``)
        the npm packages the upstream module graph resolves: ``chalk`` 5.6.2,
        ``tslog`` 4.10.2, ``file-type`` 22.0.1 and the transitive packages of
        ``file-type`` (strtok3, token-types, uint8array-extras,
        @tokenizer/inflate, @tokenizer/token, @borewit/text-codec, debug, ms,
        ieee754). They are only needed while esbuild resolves the graph.
  * ``/opt/esbuild/bin/esbuild`` (or ``$ESBUILD_BINARY``)
        pinned esbuild binary used to bundle the pinned sources.

Why a bundle step: the upstream module is TypeScript with NodeNext ``.js``
specifiers, so node cannot import it directly. esbuild resolves the real
upstream sources (the vulnerable function body is never copied or rewritten)
and tree-shakes the unused dependencies into a single ESM file that node runs.

Observable effect: ``media_blocks.json`` holds exactly what the upstream
function returned, and ``embedded_audio_base64.txt`` holds the base64 payload
of every returned audio block. The vulnerable revision returns the bytes of a
file that lives outside the allowed media roots; the patched revision returns
no block and reports the denial through ``onLocalAudioAccessDenied``.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from lab_support import parser, read_context, record


FIXTURE_ROOT = Path("/lab/fixtures")
SCENARIO_FIXTURES = {
    "attack": "attack/injected_reply.json",
    "benign": "benign/legitimate_reply.json",
}
UPSTREAM_MODULE = "src/gateway/server-methods/chat-webchat-media.ts"
CONTAINMENT_CALL = "assertLocalMediaAllowed"

SOURCE_ROOTS = (
    os.environ.get("OPENCLAW_SOURCE_ROOT"),
    "/opt/openclaw",
    "/opt/openclaw-src",
    "/lab/upstream",
)
DEPS_ROOTS = (
    os.environ.get("OPENCLAW_DEPS_ROOT"),
    "/opt/openclaw-deps/node_modules",
    "/opt/openclaw/node_modules",
    "/lab/node_modules",
)
ESBUILD_BINARIES = (
    os.environ.get("ESBUILD_BINARY"),
    "/opt/esbuild/bin/esbuild",
    "/opt/openclaw-deps/node_modules/.bin/esbuild",
    "/usr/local/bin/esbuild",
)

DRIVER = """import { readFileSync, writeFileSync } from "node:fs";
import { buildWebchatAudioContentBlocksFromReplyPayloads } from __MODULE__;

const input = JSON.parse(readFileSync(process.env.OPENCLAW_EMBEDDING_INPUT_FILE, "utf8"));
const denied = [];
const options = {
  localRoots: input.allowed_local_roots,
  onLocalAudioAccessDenied: (error) => {
    denied.push(String((error && error.code) || error));
  },
};
const blocks = await buildWebchatAudioContentBlocksFromReplyPayloads(
  input.reply_payloads,
  options,
);
writeFileSync(
  process.env.OPENCLAW_EMBEDDING_RESULT_FILE,
  JSON.stringify({ blocks: blocks ?? [], denied_local_audio_access: denied }),
);
"""


def _first_existing(candidates, predicate):
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if predicate(path):
            return path
    return None


def _locate_source_root():
    return _first_existing(SOURCE_ROOTS, lambda root: (root / UPSTREAM_MODULE).is_file())


def _esbuild_candidates(source_root, deps_root):
    """Prefer an esbuild that ships inside a pinned node_modules tree."""
    candidates = []
    node_modules_dirs = []
    if deps_root:
        node_modules_dirs.append(Path(deps_root))
    if source_root:
        node_modules_dirs.append(Path(source_root) / "node_modules")
    for node_modules in node_modules_dirs:
        candidates.append(node_modules / ".bin" / "esbuild")
        candidates.append(node_modules / "esbuild" / "bin" / "esbuild")
    candidates.extend(Path(item) for item in ESBUILD_BINARIES if item)
    return candidates


def _locate_esbuild(source_root, deps_root):
    """Return the esbuild argv prefix, or None when no usable binary exists."""
    candidates = _esbuild_candidates(source_root, deps_root)
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return [str(candidate)]
    node = shutil.which("node") or "node"
    for candidate in candidates:
        if candidate.is_file():
            return [node, str(candidate)]
    which = shutil.which("esbuild")
    return [which] if which else None


def _locate_deps_root():
    return _first_existing(
        DEPS_ROOTS,
        lambda node_modules: all(
            (node_modules / name).is_dir() for name in ("chalk", "tslog", "file-type")
        ),
    )


def _materialize(fixture):
    """Copy the fixed audio inputs to their absolute lab paths."""
    for entry in fixture.get("materialize", []):
        source = FIXTURE_ROOT / entry["fixture"]
        target = Path(entry["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def _run(command, env, timeout):
    return subprocess.run(
        command, env=env, capture_output=True, text=True, timeout=timeout, check=False
    )


def _blocks_document(result):
    return json.dumps(result, ensure_ascii=False, indent=2) + "\n"


def _base64_payloads(result):
    payloads = []
    for block in result.get("blocks", []):
        source = block.get("source") if isinstance(block, dict) else None
        if isinstance(source, dict) and isinstance(source.get("data"), str):
            payloads.append(source["data"])
    return "\n".join(payloads) + ("\n" if payloads else "")


def main() -> int:
    args = parser(__doc__).parse_args()
    context = read_context(args.context)
    scenario = context["scenario"]
    variant = context["variant"]

    fixture_name = SCENARIO_FIXTURES[scenario]
    fixture = json.loads((FIXTURE_ROOT / fixture_name).read_text(encoding="utf-8"))
    reply_payloads = fixture.get("reply_payloads", [])
    allowed_roots = fixture.get("allowed_local_roots", [])

    observation = {
        "target_ready": False,
        "execution_status": "failed",
        "scenario": scenario,
        "variant": variant,
        "fixture": fixture_name,
        "upstream_module": UPSTREAM_MODULE,
        "upstream_module_sha256": None,
        "upstream_calls_containment_check": None,
        "allowed_local_roots": allowed_roots,
        "reply_payloads": reply_payloads,
        "materialized_paths": [],
        "toolchain": {},
        "audio_content_blocks": 0,
        "media_types": [],
        "denied_local_audio_access": [],
        "error": None,
    }
    effects = {
        "media_blocks.json": _blocks_document(
            {"blocks": [], "denied_local_audio_access": []}
        ),
        "embedded_audio_base64.txt": "",
    }

    work = None
    try:
        source_root = _locate_source_root()
        if source_root is None:
            raise RuntimeError(
                "pinned upstream source not found; expected " + UPSTREAM_MODULE
            )
        module_path = source_root / UPSTREAM_MODULE
        module_text = module_path.read_text(encoding="utf-8", errors="replace")
        calls_containment = CONTAINMENT_CALL in module_text
        observation["upstream_module_sha256"] = hashlib.sha256(
            module_path.read_bytes()
        ).hexdigest()
        observation["upstream_calls_containment_check"] = calls_containment
        expects_containment = variant == "patched"
        if calls_containment is not expects_containment:
            raise RuntimeError(
                "pinned module at %s does not match variant %r "
                "(assertLocalMediaAllowed present=%s)" % (module_path, variant, calls_containment)
            )

        deps_root = _locate_deps_root()
        esbuild = _locate_esbuild(source_root, deps_root)
        if esbuild is None:
            raise RuntimeError("pinned esbuild binary not found")
        node = shutil.which("node") or "/usr/local/bin/node"
        observation["toolchain"] = {
            "source_root": str(source_root),
            "esbuild": " ".join(esbuild),
            "deps_root": str(deps_root) if deps_root else None,
            "node": node,
        }

        _materialize(fixture)
        observation["materialized_paths"] = [
            entry["path"] for entry in fixture.get("materialize", [])
        ]

        work = Path(tempfile.mkdtemp(prefix="openclaw-audio-embedding-"))
        module_path = source_root / UPSTREAM_MODULE
        entry = work / "entry.mjs"
        entry.write_text(
            DRIVER.replace("__MODULE__", json.dumps(str(module_path))), encoding="utf-8"
        )
        bundle = work / "bundle.mjs"
        env = dict(os.environ)
        env["NODE_PATH"] = str(deps_root) if deps_root else ""
        env.setdefault("NO_COLOR", "1")
        build = _run(
            [
                *esbuild,
                str(entry),
                "--bundle",
                "--platform=node",
                "--format=esm",
                "--target=node22",
                "--outfile=" + str(bundle),
                "--log-level=warning",
            ],
            env,
            240,
        )
        if build.returncode != 0 or not bundle.is_file():
            raise RuntimeError(
                "esbuild failed: " + (build.stderr or build.stdout or "")[-2000:]
            )

        input_path = work / "input.json"
        input_path.write_text(
            json.dumps(
                {"reply_payloads": reply_payloads, "allowed_local_roots": allowed_roots}
            ),
            encoding="utf-8",
        )
        result_path = work / "result.json"
        env = dict(os.environ)
        env["OPENCLAW_EMBEDDING_INPUT_FILE"] = str(input_path)
        env["OPENCLAW_EMBEDDING_RESULT_FILE"] = str(result_path)
        run = _run([node, str(bundle)], env, 180)
        if run.returncode != 0 or not result_path.is_file():
            raise RuntimeError(
                "upstream call failed: " + (run.stderr or run.stdout or "")[-2000:]
            )
        result = json.loads(result_path.read_text(encoding="utf-8"))

        blocks = result.get("blocks") if isinstance(result.get("blocks"), list) else []
        denied = (
            result.get("denied_local_audio_access")
            if isinstance(result.get("denied_local_audio_access"), list)
            else []
        )
        observation.update(
            {
                "target_ready": True,
                "execution_status": "completed",
                "audio_content_blocks": len(blocks),
                "media_types": [
                    block.get("source", {}).get("media_type")
                    for block in blocks
                    if isinstance(block, dict)
                ],
                "denied_local_audio_access": denied,
            }
        )
        effects = {
            "media_blocks.json": _blocks_document(
                {"blocks": blocks, "denied_local_audio_access": denied}
            ),
            "embedded_audio_base64.txt": _base64_payloads(result),
        }
    except Exception as error:  # noqa: BLE001 - failure is recorded, never raised as a pass
        observation["error"] = "%s: %s" % (type(error).__name__, error)
    finally:
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)

    return record(context, args.output, observation, effects)


if __name__ == "__main__":
    raise SystemExit(main())
