# Reviewed, version-pinned, network-disabled build recipe for
# n8n-mcp/GHSA-8G7G-HMWM-6RV2.
#
# BASE_IMAGE is the locally cached node:22-bookworm pinned by manifest digest; it
# provides the node interpreter the harness drives plus python3 for the lab
# scripts. VARIANT selects the pinned upstream release through SOURCE_ARCHIVE
# (2.50.0 vulnerable / 2.50.1 patched). Both source archives and the complete
# locked runtime dependency closure arrive as SHA-256-verified npm tarballs in
# inputs/, so no build step contacts a registry.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG VARIANT
ARG SOURCE_COMMIT
ARG SOURCE_ARCHIVE

ENV NODE_ENV=production \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NODE_PATH=/lab/vendor/node_modules \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /lab

# inputs/ is populated by runner build after SHA-256 verification.
COPY inputs/ /inputs/
COPY reproduce.py verify.py end_to_end.py lab_support.py /lab/
COPY fixtures/ /lab/fixtures/
COPY build-check.cjs /lab/build-check.cjs

# Every npm tarball carries a single top-level "package/" directory. Unpacking it
# straight into its node_modules path is the whole install: no package manager,
# no registry metadata, no network. /lab/vendor/node_modules is one of the
# conventional roots the reproduction searches via lab_root()/*/node_modules.
RUN set -eux; \
    install_pkg() { \
        destination="/lab/vendor/node_modules/$1"; \
        mkdir -p "$destination"; \
        tar -xzf "/inputs/$2" -C "$destination" --strip-components=1; \
    }; \
    install_pkg "axios" "axios-1.20.0.tgz"; \
    install_pkg "zod" "zod-3.25.76.tgz"; \
    install_pkg "follow-redirects" "follow-redirects-1.16.0.tgz"; \
    install_pkg "form-data" "form-data-4.0.6.tgz"; \
    install_pkg "proxy-from-env" "proxy-from-env-2.1.0.tgz"; \
    install_pkg "agent-base" "agent-base-6.0.2.tgz"; \
    install_pkg "https-proxy-agent" "https-proxy-agent-5.0.1.tgz"; \
    install_pkg "debug" "debug-4.4.3.tgz"; \
    install_pkg "ms" "ms-2.1.3.tgz"; \
    install_pkg "asynckit" "asynckit-0.4.0.tgz"; \
    install_pkg "combined-stream" "combined-stream-1.0.8.tgz"; \
    install_pkg "delayed-stream" "delayed-stream-1.0.0.tgz"; \
    install_pkg "mime-types" "mime-types-2.1.35.tgz"; \
    install_pkg "mime-db" "mime-db-1.52.0.tgz"; \
    install_pkg "es-set-tostringtag" "es-set-tostringtag-2.1.0.tgz"; \
    install_pkg "es-errors" "es-errors-1.3.0.tgz"; \
    install_pkg "es-object-atoms" "es-object-atoms-1.1.2.tgz"; \
    install_pkg "es-define-property" "es-define-property-1.0.1.tgz"; \
    install_pkg "hasown" "hasown-2.0.4.tgz"; \
    install_pkg "function-bind" "function-bind-1.1.2.tgz"; \
    install_pkg "has-symbols" "has-symbols-1.1.0.tgz"; \
    install_pkg "has-tostringtag" "has-tostringtag-1.0.2.tgz"; \
    install_pkg "get-intrinsic" "get-intrinsic-1.3.0.tgz"; \
    install_pkg "get-proto" "get-proto-1.0.1.tgz"; \
    install_pkg "gopd" "gopd-1.2.0.tgz"; \
    install_pkg "call-bind-apply-helpers" "call-bind-apply-helpers-1.0.2.tgz"; \
    install_pkg "dunder-proto" "dunder-proto-1.0.1.tgz"; \
    install_pkg "math-intrinsics" "math-intrinsics-1.1.0.tgz"; \
    test -f /lab/vendor/node_modules/axios/package.json; \
    test -f /lab/vendor/node_modules/zod/package.json

# Install the pinned upstream source for the selected variant and refuse to
# produce an image for the wrong release or the wrong side of the fix.
RUN set -eux; \
    python3 --version; \
    node --version; \
    mkdir -p /lab/upstream; \
    tar -xzf "/inputs/${SOURCE_ARCHIVE}" -C /lab/upstream; \
    test -f /lab/upstream/package/package.json; \
    node /lab/build-check.cjs "${VARIANT}"
