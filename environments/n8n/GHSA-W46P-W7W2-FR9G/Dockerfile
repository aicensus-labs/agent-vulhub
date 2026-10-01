# Reviewed, version-pinned, network-disabled build recipe for
# n8n/GHSA-W46P-W7W2-FR9G.
#
# BASE_IMAGE is the locally cached node:22-bookworm pinned by manifest digest. It
# supplies the Node 22 runtime the mechanism reproduction drives (module.registerHooks
# plus --experimental-transform-types) and python3 for the lab scripts.
#
# VARIANT selects the pinned upstream worktree through SOURCE_ARCHIVE:
#   * vulnerable -> n8n 2.29.7 (commit 60109bba8cae51bdb60615a41552cebf397b7438), whose
#     runtime reconstruction resolves the agent's node tool refs without consulting the
#     caller's scopes, so the node tool reaches EphemeralNodeExecutor.executeInline;
#   * patched    -> n8n 2.29.8 (commit 7786117e976664b67288f13d6cfcd1fcf1b1289b), which
#     routes the same refs through filterToolsForUser (workflow:execute plus
#     credential:read) before reconstruction, so no node tool is produced.
#
# The full pinned monorepo (including pnpm-lock.yaml and every workspace package) is
# unpacked from the SHA-256-verified GitHub tag archive in inputs/, so no build step
# contacts a network and no package manager runs. No registry tarball is unpacked: the
# reproduction loads only the two pinned TypeScript modules under
# packages/cli/src/modules/agents and its import-hook loader resolves every bare
# specifier those modules request to an in-process double, so the runtime dependency
# closure actually installed is the base image's Node runtime.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG VARIANT
ARG SOURCE_COMMIT
ARG SOURCE_ARCHIVE

ENV NODE_ENV=production \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /lab

# inputs/ is populated by runner build after SHA-256 verification.
COPY inputs/ /inputs/
COPY reproduce.py verify.py end_to_end.py lab_support.py /lab/
COPY fixtures/ /lab/fixtures/

# Install the pinned upstream source. --strip-components=1 drops the
# n8n-n8n-<version>/ prefix so the tree lands at /lab/app exactly as the
# reproduction expects (N8N_SOURCE_ROOT=/lab/app).
RUN set -eux; \
    mkdir -p /lab/app; \
    tar -xzf "/inputs/${SOURCE_ARCHIVE}" -C /lab/app --strip-components=1; \
    test -f /lab/app/packages/cli/src/modules/agents/agent-runtime-reconstruction.service.ts; \
    test -f /lab/app/packages/cli/src/modules/agents/tools/node-tool-factory.ts; \
    test -f /lab/app/pnpm-lock.yaml

# Fail the build when the wrong release is baked in or the runtime cannot drive the
# pinned sources. The expected digests are the upstream
# agent-runtime-reconstruction.service.ts bytes of each tag; node-tool-factory.ts is
# byte-identical in both releases and is checked once.
RUN set -eux; \
    node --version; \
    python3 --version; \
    node -e "const { registerHooks } = require('node:module'); if (typeof registerHooks !== 'function') { throw new Error('node lacks module.registerHooks'); }"; \
    node -e "const fs = require('fs'); const crypto = require('crypto'); \
const root = '/lab/app/packages/cli/src/modules/agents'; \
const expected = { vulnerable: '9010d3a439664970af58465a527f9b7c8f72b413944860d06e13381ea08c31bf', \
                   patched: 'dd188f670587ac858e3fa6d194fe53f6de40b83eac734d4862710f4b6587e829' }['${VARIANT}']; \
if (!expected) { throw new Error('unknown VARIANT ${VARIANT}'); } \
const digest = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); \
const service = root + '/agent-runtime-reconstruction.service.ts'; \
const actual = digest(service); \
if (actual !== expected) { throw new Error('agent-runtime-reconstruction.service.ts is ' + actual + ', expected ' + expected); } \
const factory = digest(root + '/tools/node-tool-factory.ts'); \
if (factory !== '77a5ef160462e4cfe11c1bee508408e1bd59a4aac2b5a5f655571f950334ab09') { throw new Error('node-tool-factory.ts is ' + factory); } \
const guarded = fs.readFileSync(service, 'utf8').includes('filterToolsForUser'); \
if (guarded !== ('${VARIANT}' === 'patched')) { throw new Error('${VARIANT} filterToolsForUser=' + guarded); } \
if (!/^[0-9a-f]{40}$/.test('${SOURCE_COMMIT}')) { throw new Error('bad source commit ${SOURCE_COMMIT}'); } \
console.log('${VARIANT} n8n source ' + '${SOURCE_COMMIT}' + ' installed offline at /lab/app');"
