# Reviewed, version-pinned, fully offline build recipe for
# flowise/GHSA-M99R-2HXC-CP3Q (Flowise MCP security bypass -> RCE).
#
# The runner already downloaded every entry of metadata.toml [build].inputs and
# verified its SHA-256 before this build starts, so the recipe never touches the
# network: `docker build --network none` is the supported mode.
#
# Two things are installed:
#   /lab/source   the upstream Flowise source tree at the pinned commit
#                 (packages/components/nodes/tools/MCP/core.ts is the vulnerable
#                 gate; 3.1.2 is the fix), extracted from the variant archive;
#   /lab/mcp      the *published* flowise-components build for the variant plus
#                 the complete locked npm closure of its MCP runtime, unpacked
#                 from the pinned registry tarballs into the exact node_modules
#                 paths of mcp-package-lock.json (no npm resolution, no registry).
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG VARIANT
ARG SOURCE_COMMIT
ARG SOURCE_ARCHIVE

LABEL org.opencontainers.image.title="agent-vulhub flowise/GHSA-M99R-2HXC-CP3Q"
LABEL org.opencontainers.image.source="https://github.com/FlowiseAI/Flowise"
LABEL org.opencontainers.image.revision=$SOURCE_COMMIT

WORKDIR /lab

# inputs/ is populated by `runner build` after SHA-256 verification.
COPY inputs/ /inputs/
COPY mcp-package.json /tmp/mcp/package.json
COPY mcp-package-lock.json /tmp/mcp/package-lock.json
COPY mcp-deps-manifest.json /tmp/mcp/mcp-deps-manifest.json
COPY install-mcp-deps.py /tmp/mcp/install-mcp-deps.py
COPY lab_support.py reproduce.py verify.py end_to_end.py /lab/
COPY fixtures/ /lab/fixtures/

RUN set -eux; \
    mkdir -p /lab/source /lab/mcp; \
    tar -xzf "/inputs/${SOURCE_ARCHIVE}" -C /lab/source --strip-components=1; \
    test -f /lab/source/packages/components/nodes/tools/MCP/core.ts; \
    case "${VARIANT}" in \
        vulnerable) cp "/inputs/flowise-components-vulnerable.tgz" /tmp/flowise-components.tgz ;; \
        patched)    cp "/inputs/flowise-components-patched.tgz"    /tmp/flowise-components.tgz ;; \
        *) echo "unknown VARIANT: ${VARIANT}" >&2; exit 1 ;; \
    esac; \
    python3 /tmp/mcp/install-mcp-deps.py \
        --manifest /tmp/mcp/mcp-deps-manifest.json \
        --inputs /inputs \
        --dest /lab/mcp \
        --package-tarball /tmp/flowise-components.tgz \
        --package-dir node_modules/flowise-components; \
    rm -rf /tmp/mcp /tmp/flowise-components.tgz; \
    node -e "const m = require('/lab/mcp/node_modules/flowise-components/dist/nodes/tools/MCP/core.js'); \
        if (typeof m.validateMCPServerConfig !== 'function') { throw new Error('MCP gate missing'); } \
        if (typeof m.MCPToolkit !== 'function') { throw new Error('MCPToolkit missing'); }"; \
    python3 -c "import json,pathlib; json.loads(pathlib.Path('/lab/mcp/node_modules/flowise-components/package.json').read_text())"

CMD ["python3", "/lab/reproduce.py", "--help"]
