# Reviewed, version-pinned, network-disabled build recipe for
# n8n/GHSA-5VFW-JC4P-FJ39.
#
# BASE_IMAGE is the locally cached node:22-bookworm pinned by manifest digest; it
# provides the node interpreter the harness drives plus python3 for the lab
# scripts. VARIANT selects the pinned upstream release through SOURCE_ARCHIVE
# (n8n 2.29.7 vulnerable / n8n 2.29.8 patched). The release tarball and the
# hash-pinned loader shim closure are taken from the SHA-256-verified inputs in
# inputs/, so no build step contacts a registry.
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
COPY reproduce.py verify.py end_to_end.py lab_support.py build_check.js /lab/
COPY fixtures/ /lab/fixtures/

# Install the pinned upstream release. Every npm tarball carries a single
# top-level "package/" directory, so unpacking it into vendor/ is the whole
# install: no package manager, no registry metadata, no network. The exercised
# entrypoints import only the Node standard library and the 14 loader adapters
# under fixtures/harness/shims, which fixtures/manifest.toml hash-pins; loader.js
# refuses every other specifier, so no registry package is reachable or needed.
RUN set -eux; \
    mkdir -p /lab/vendor/upstream; \
    tar -xzf "/inputs/${SOURCE_ARCHIVE}" -C /lab/vendor/upstream --strip-components=1; \
    test -f /lab/vendor/upstream/package.json; \
    test -f /lab/vendor/upstream/dist/modules/oauth-server/oauth-consent.service.js; \
    test -f /lab/vendor/upstream/dist/modules/oauth-server/oauth-token.service.js

# Prove the pinned revision, the byte-for-byte provenance of every vendored
# upstream file against that release, the shim-closure pin, and the side of the
# fix - including one network-free run of the attack scenario per variant.
RUN set -eux; \
    python3 --version; \
    node --version; \
    VARIANT="${VARIANT}" node /lab/build_check.js
