# Offline, revision-pinned recipe for openclaw / GHSA-82RM-QCFX-2V78
# (delivery queue recovery could lose group tool-policy context for media replay).
#
# Both variants install the published npm release of `openclaw` for the selected
# revision, together with its COMPLETE runtime dependency closure, from the
# SHA-256-pinned tarballs under inputs/.  Nothing is fetched during the build:
# the closure is replayed from an npm cache that is populated from those local
# tarballs only, and `npm ci --offline` resolves purely from the shipped
# package-lock.json (lockfileVersion 3, integrity-checked).
#
#   vulnerable = openclaw@2026.4.10 (tag v2026.4.10 ->
#                                    44e5b62c27e088128e32e209c146de346c3ea7e6)
#   patched    = openclaw@2026.4.14 (contains fix commit
#                                    48aae82bbc19ba8b0741e61a08063eb0d1df464e / PR #66025,
#                                    which persists `session` in the write-ahead queue entry
#                                    and replays it on restart recovery)
#
# 2026.4.14 is the first release whose dependency closure pulls
# @whiskeysockets/baileys -> libsignal from a git+https spec.  That one git
# dependency is vendored as the pinned upstream codeload tarball (commit
# bcea72df9ec34d9d9140ab30619cf479c7c144c7) and wired in through an npm
# `overrides` entry, so `npm ci --offline` stays fully offline.
#
# The base image is Debian bookworm (glibc 2.36) with python3, which is the
# declared runtime harness.  Node.js 24.21.0 is installed from a pinned upstream
# tarball because `openclaw` declares `engines.node >= 22.14.0`.
ARG BASE_IMAGE

# ---------------------------------------------------------------------------
# Stage 1: build /lab, including the complete node_modules closure.
# ---------------------------------------------------------------------------
FROM ${BASE_IMAGE} AS builder

ARG VARIANT
ARG SOURCE_COMMIT
ARG SOURCE_ARCHIVE

ENV DEBIAN_FRONTEND=noninteractive \
    npm_config_update_notifier=false \
    npm_config_audit=false \
    npm_config_fund=false

WORKDIR /lab

# Node.js runtime + npm, unpacked from the pinned upstream tarball.
COPY inputs/node-v24.21.0-linux-x64.tar.gz /tmp/node.tar.gz
RUN set -eux; \
    mkdir -p /opt/node; \
    tar -xzf /tmp/node.tar.gz -C /opt/node --strip-components=1; \
    rm -f /tmp/node.tar.gz; \
    ln -sf /opt/node/bin/node /usr/local/bin/node; \
    ln -sf /opt/node/bin/npm /usr/local/bin/npm; \
    ln -sf /opt/node/bin/npx /usr/local/bin/npx; \
    node --version; \
    npm --version; \
    python3 --version

# inputs/ is populated by `runner build` after SHA-256 verification: the two
# openclaw release tarballs, the Node.js tarball, the vendored libsignal git
# snapshot, and every npm package in the union of the 2026.4.10 and 2026.4.14
# dependency closures.  It is copied under /lab/inputs because the 2026.4.14
# lockfile refers to the vendored libsignal tarball by that relative path.
COPY inputs/ /lab/inputs/

COPY npm/package-lock.2026.4.10.json /lab/npm/package-lock.2026.4.10.json
COPY npm/package-lock.2026.4.14.json /lab/npm/package-lock.2026.4.14.json

# Install the pinned revision and prove that the image really carries the
# variant-specific dist: the hashed chunk filenames are derived from the content
# of the module that holds the delivery queue / recovery / media-policy helpers.
RUN set -eux; \
    case "${VARIANT}" in \
      vulnerable) want=2026.4.10; lock=/lab/npm/package-lock.2026.4.10.json; chunk=delivery-queue-wYNXw79t.js; other=delivery-queue-cUZQxuAc.js ;; \
      patched)    want=2026.4.14; lock=/lab/npm/package-lock.2026.4.14.json; chunk=delivery-queue-cUZQxuAc.js; other=delivery-queue-wYNXw79t.js ;; \
      *) echo "unsupported VARIANT: ${VARIANT}" >&2; exit 2 ;; \
    esac; \
    test -n "${SOURCE_COMMIT}"; \
    test -f "${lock}"; \
    cp "${lock}" /lab/package-lock.json; \
    if [ "${VARIANT}" = "patched" ]; then \
      printf '{"name":"lab","version":"1.0.0","private":true,"dependencies":{"openclaw":"%s"},"overrides":{"libsignal":"file:inputs/libsignal-node-bcea72df9ec34d9d9140ab30619cf479c7c144c7.tar.gz"}}\n' "${want}" > /lab/package.json; \
    else \
      printf '{"name":"lab","version":"1.0.0","private":true,"dependencies":{"openclaw":"%s"}}\n' "${want}" > /lab/package.json; \
    fi; \
    npm cache add --cache /npm-cache /lab/inputs/*.tgz; \
    npm ci --offline --no-audit --no-fund --ignore-scripts --cache /npm-cache; \
    rm -rf /npm-cache /root/.npm /lab/inputs; \
    test "$(node -p "require('/lab/node_modules/openclaw/package.json').version")" = "${want}"; \
    test -f "/lab/node_modules/openclaw/dist/${chunk}"; \
    test ! -f "/lab/node_modules/openclaw/dist/${other}"; \
    grep -rlq "recoverPendingDeliveries" /lab/node_modules/openclaw/dist; \
    grep -rlq "resolveAgentScopedOutboundMediaAccess" /lab/node_modules/openclaw/dist; \
    node -e "require('sharp'); require('zod'); require('ws'); console.log('closure-import-ok');"; \
    if [ "${VARIANT}" = "patched" ]; then test -f /lab/node_modules/libsignal/package.json; fi; \
    mkdir -p /lab/results

# ---------------------------------------------------------------------------
# Stage 2: runtime image.  Only the installed closure and the lab scripts are
# copied over, so the multi-hundred-megabyte input layer never reaches the
# final image.
# ---------------------------------------------------------------------------
FROM ${BASE_IMAGE}

ARG VARIANT
ARG SOURCE_COMMIT
ARG SOURCE_ARCHIVE

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0 \
    NODE_PATH=/lab/node_modules:/usr/local/lib/node_modules \
    npm_config_update_notifier=false \
    npm_config_audit=false \
    npm_config_fund=false

COPY inputs/node-v24.21.0-linux-x64.tar.gz /tmp/node.tar.gz
RUN set -eux; \
    mkdir -p /opt/node; \
    tar -xzf /tmp/node.tar.gz -C /opt/node --strip-components=1; \
    rm -f /tmp/node.tar.gz; \
    ln -sf /opt/node/bin/node /usr/local/bin/node; \
    ln -sf /opt/node/bin/npm /usr/local/bin/npm; \
    ln -sf /opt/node/bin/npx /usr/local/bin/npx; \
    node --version; \
    python3 --version

WORKDIR /lab

COPY --from=builder /lab /lab

COPY lab_support.py reproduce.py verify.py end_to_end.py /lab/
COPY fixtures/ /lab/fixtures/

# `openclaw` must resolve from every plausible entry point: /lab/node_modules
# (standard resolution for /lab/*.mjs), the global module root (NODE_PATH for
# CommonJS), and the /lab/openclaw path some probes use directly.
RUN set -eux; \
    case "${VARIANT}" in \
      vulnerable) chunk=delivery-queue-wYNXw79t.js ;; \
      patched)    chunk=delivery-queue-cUZQxuAc.js ;; \
      *) echo "unsupported VARIANT: ${VARIANT}" >&2; exit 2 ;; \
    esac; \
    mkdir -p /usr/local/lib/node_modules; \
    ln -sfn /lab/node_modules/openclaw /usr/local/lib/node_modules/openclaw; \
    ln -sfn /lab/node_modules/openclaw /lab/openclaw; \
    mkdir -p /lab/results; \
    test -n "${SOURCE_COMMIT}"; \
    test -f "/lab/node_modules/openclaw/package.json"; \
    test -f "/lab/node_modules/openclaw/dist/${chunk}"; \
    python3 -c "import json; assert json.load(open('/lab/node_modules/openclaw/package.json'))['name'] == 'openclaw'"; \
    node --version; \
    python3 --version
