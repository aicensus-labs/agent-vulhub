# Reviewed, version-pinned, fully offline build recipe for
# openclaw/GHSA-CWJ3-VQPP-PMXR: the gateway config-mutation guard in
# src/agents/tools/gateway-tool.ts used a hand-maintained denylist (2026.4.22)
# and was replaced by a fail-closed allowlist (2026.4.23).
#
# Base image: node:22-bookworm pinned by digest and already present locally. It
# ships Node.js 22 and python3, so the declared python3 harness, the dependency
# unpacker and the fixed-document driver need no system package installed.
# `docker build --network none` is the supported mode: the runner has already
# fetched every metadata.toml input and verified its SHA-256, and nothing here
# resolves, downloads or builds a package.
#
# What is installed:
#   /lab/src                       the pinned upstream commit, extracted from
#                                  the variant's source archive
#   /lab/src/src/agents/tools/gateway-tool.ts
#                                  the reviewed trust boundary, byte-asserted
#                                  against the revision's SHA-256 below
#   /lab/src/node_modules          the complete locked runtime closure from
#                                  pnpm-lock.yaml, unpacked straight from the
#                                  npm tarballs into an npm-shaped tree
#                                  (install-openclaw-deps.py; npm never runs)
#   /lab/reproduce.py, /lab/fixtures, /lab/verify.py
#                                  the fixed attack/benign entrypoints
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG VARIANT
ARG SOURCE_COMMIT
ARG SOURCE_ARCHIVE

WORKDIR /lab
ENV NODE_ENV=production

# inputs/ is populated by `runner build` after SHA-256 verification.
COPY inputs/ /build-inputs/
COPY openclaw-deps.json install-openclaw-deps.py /tmp/recipe/
COPY lab_support.py reproduce.py verify.py end_to_end.py /lab/
COPY fixtures/ /lab/fixtures/

RUN set -eux; \
    test -n "${VARIANT}"; \
    test -f "/build-inputs/${SOURCE_ARCHIVE}"; \
    mkdir -p /lab/src; \
    tar -xzf "/build-inputs/${SOURCE_ARCHIVE}" -C /lab/src --strip-components=1; \
    python3 /tmp/recipe/install-openclaw-deps.py \
        --manifest /tmp/recipe/openclaw-deps.json \
        --inputs /build-inputs \
        --dest /lab/src/node_modules \
        --variant "${VARIANT}"; \
    case "${VARIANT}" in \
      vulnerable) guard_sha256=374c50794112c72a1237427cb4c193468e74d6b96d6c103ffab40f0b7b608e16 ;; \
      patched) guard_sha256=6f33eee61ca985a7230060cf070001a26bb74250609449e745f0fa144fcf2e40 ;; \
      *) echo "unknown variant ${VARIANT}" >&2; exit 1 ;; \
    esac; \
    echo "${guard_sha256}  /lab/src/src/agents/tools/gateway-tool.ts" | sha256sum -c -; \
    test -f /lab/src/src/config/io.ts; \
    test -f /lab/src/src/config/merge-patch.ts; \
    test -f /lab/src/node_modules/tsx/dist/cli.mjs; \
    test -f /lab/src/node_modules/typebox/package.json; \
    grep -q assertGatewayConfigMutationAllowedForTest /lab/src/src/agents/tools/gateway-tool.ts; \
    node /lab/src/node_modules/tsx/dist/cli.mjs --version; \
    rm -rf /build-inputs /tmp/recipe

# The mechanism entrypoint loads the pinned modules through tsx, which the
# runner discovers at /lab/src/node_modules/tsx/dist/cli.mjs.
ENV AVH_OPENCLAW_SOURCE=/lab/src
