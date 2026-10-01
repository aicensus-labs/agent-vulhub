# Offline, version-pinned recipe for grackle/GHSA-F9FF-5X35-7GFW (MCP tool-layer
# fail-open authorization: a scoped agent reaches task/session mutations that
# belong to another task subtree or session, CWE-639/CWE-862).
#
# Base image: node@sha256:363e... (node:22-bookworm, already present locally).
# It provides Node.js 22, which satisfies the pinned package's
# engines.node ">=22.0.0 <24.0.0", plus npm, tar and python3, so the same image
# also serves runtime.harness = "python3".
#
# The build context receives, under inputs/, the two upstream release tarballs
# (@grackle-ai/mcp 0.132.1 = vulnerable, 0.133.0 = patched) plus the complete
# locked runtime closure for linux/amd64/glibc (122 upstream tarballs, every
# entry of package-lock.{vulnerable,patched}.json, with the four @grackle-ai/*
# packages vendored at both versions). Nothing is fetched during the build:
# `npm cache add` seeds the npm cache from the vendored tarballs and
# `npm ci --offline` reifies the locked tree under /lab/app.
#
# The vulnerable revision's own code is what reproduce.py loads; this recipe
# only installs it, never patches or rewrites it.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG VARIANT
ARG SOURCE_COMMIT
ARG SOURCE_ARCHIVE

ENV npm_config_cache=/npm-cache \
    npm_config_offline=true \
    npm_config_audit=false \
    npm_config_fund=false \
    npm_config_update_notifier=false

WORKDIR /lab
COPY inputs/ /inputs/
COPY package.vulnerable.json package.patched.json /lab/
COPY package-lock.vulnerable.json package-lock.patched.json /lab/
COPY reproduce.py verify.py end_to_end.py /lab/
COPY fixtures/ /lab/fixtures/
COPY lab_support.py /lab/

RUN set -eux; \
    test -n "${SOURCE_COMMIT}"; \
    case "${VARIANT}" in \
      vulnerable) expected="0.132.1" ;; \
      patched) expected="0.133.0" ;; \
      *) echo "unknown variant: ${VARIANT}" >&2; exit 1 ;; \
    esac; \
    test -f "/inputs/${SOURCE_ARCHIVE}"; \
    got="$(tar -xzOf "/inputs/${SOURCE_ARCHIVE}" package/package.json | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.stdout.write(String(JSON.parse(s).version)))')"; \
    test "${got}" = "${expected}"; \
    mkdir -p /lab/app /lab/results; \
    cp "/lab/package.${VARIANT}.json" /lab/app/package.json; \
    cp "/lab/package-lock.${VARIANT}.json" /lab/app/package-lock.json; \
    npm cache add --offline /inputs/*.tgz > /dev/null; \
    cd /lab/app; \
    npm ci --offline --ignore-scripts --no-audit --no-fund; \
    test -s /lab/app/node_modules/@grackle-ai/mcp/dist/index.js; \
    node --check /lab/app/node_modules/@grackle-ai/mcp/dist/index.js; \
    node -e "import('@grackle-ai/mcp').then(() => console.log('offline closure imports'))"; \
    printf '%s\n' "${SOURCE_COMMIT}" > /lab/SOURCE_COMMIT; \
    printf '%s\n' "${VARIANT}" > /lab/VARIANT; \
    rm -rf /npm-cache/_logs /inputs
