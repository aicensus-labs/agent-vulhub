# Reviewed, version-pinned, fully offline build recipe for GHSA-C4QG-MG2R-2C56.
#
# The single pinned base image (node:22-bookworm with a digest) is already present
# on this host. It ships node 22 (the upstream engine requirement is >=20) and
# python3, which is the declared harness for reproduce.py/verify.py.
#
# Nothing is fetched while building: every file the recipe consumes is a
# SHA-256-verified input that `runner build` copies into /inputs, and the image
# is assembled with `docker build --network none`.
#
# VARIANT selects the pinned upstream release:
#   vulnerable = openclaw-mcp 1.6.0 (a07a30826ab1ff5cceb43f047699008dcaf70238)
#   patched    = openclaw-mcp 1.7.0 (751d58a4d6947809e18d968d92604e50398ee98c)
#
# Both npm releases ship the prebuilt dist/index.js entrypoint. Its bare imports
# (@modelcontextprotocol/sdk/... and yargs/...) are resolved from the complete
# locked dependency closure that offline-deps.tsv materialises under
# /lab/app/node_modules, so no package manager and no network are involved.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG VARIANT
ARG SOURCE_COMMIT
ARG SOURCE_ARCHIVE

ENV LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /lab

# Hash-verified inputs and the locked layout ("<tarball>\t<node_modules path>").
COPY inputs/ /inputs/
COPY offline-deps.tsv /lab/offline-deps.tsv

# Lab harness, copied verbatim from the environment directory by the runner.
COPY reproduce.py verify.py end_to_end.py /lab/
COPY lab_support.py /lab/
COPY fixtures/ /lab/fixtures/

# 1. Unpack the pinned upstream release for this variant into /lab/app, so that
#    /lab/app/dist/index.js is the entrypoint reproduce.py looks for.
RUN set -eux; \
    case "${VARIANT}" in \
        vulnerable) want="a07a30826ab1ff5cceb43f047699008dcaf70238" ;; \
        patched) want="751d58a4d6947809e18d968d92604e50398ee98c" ;; \
        *) echo "unknown variant: ${VARIANT}" >&2; exit 2 ;; \
    esac; \
    [ "${SOURCE_COMMIT}" = "${want}" ]; \
    test -f "/inputs/${SOURCE_ARCHIVE}"; \
    mkdir -p /lab/app; \
    tar -xzf "/inputs/${SOURCE_ARCHIVE}" -C /lab/app --strip-components=1; \
    test -f /lab/app/package.json; \
    test -f /lab/app/dist/index.js

# 2. Materialise the complete locked dependency closure by extracting each
#    vendored npm tarball at the exact node_modules path the lockfile records.
#    No package manager runs, so no registry access and no lifecycle script can
#    reach the network. The final checks fail closed if a runtime import target
#    is missing.
RUN set -eux; \
    while read -r tarball destination; do \
        [ -n "${tarball}" ] || continue; \
        test -f "/inputs/${tarball}"; \
        mkdir -p "/lab/app/${destination}"; \
        tar -xzf "/inputs/${tarball}" -C "/lab/app/${destination}" --strip-components=1; \
    done < /lab/offline-deps.tsv; \
    test -f /lab/app/node_modules/@modelcontextprotocol/sdk/dist/esm/server/index.js; \
    test -f /lab/app/node_modules/@modelcontextprotocol/sdk/dist/esm/server/streamableHttp.js; \
    test -f /lab/app/node_modules/@modelcontextprotocol/sdk/dist/esm/server/express.js; \
    test -f /lab/app/node_modules/@modelcontextprotocol/sdk/dist/esm/client/index.js; \
    test -f /lab/app/node_modules/@modelcontextprotocol/sdk/dist/esm/client/streamableHttp.js; \
    test -f /lab/app/node_modules/yargs/helpers/package.json

# 3. Record the revision and fail closed if the harness entry points are missing.
RUN set -eux; \
    printf '%s\n' "${SOURCE_COMMIT}" > /lab/app/SOURCE_COMMIT; \
    test -f /lab/reproduce.py; \
    test -f /lab/verify.py; \
    test -f /lab/lab_support.py; \
    test -d /lab/fixtures; \
    node --version; \
    python3 --version
