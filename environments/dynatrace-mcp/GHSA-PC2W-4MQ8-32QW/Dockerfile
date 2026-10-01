# Reviewed, version-pinned, network-free build recipe.
#
# Upstream release @dynatrace-oss/dynatrace-mcp-server ships as one esbuild
# CommonJS bundle (package/index.js) that already contains the MCP SDK, the
# Dynatrace platform client and ajv. Its only runtime dependency is open@8.4.2,
# whose complete transitive closure is define-lazy-prop, is-docker and is-wsl.
# Both the variant bundle and that closure are extracted from the SHA-256
# verified files in inputs/, so this recipe performs no registry access, no
# package-manager resolution and no lifecycle script execution.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG VARIANT
ARG SOURCE_COMMIT
ARG SOURCE_ARCHIVE

ENV NODE_ENV=production \
    DT_MCP_DISABLE_TELEMETRY=true

WORKDIR /lab

# Populated by runner build after SHA-256 verification of every metadata input.
COPY inputs/ /inputs/

RUN set -eux; \
    case "${VARIANT}" in \
        vulnerable) want="1.8.6" ;; \
        patched)    want="1.8.7" ;; \
        *) echo "unknown VARIANT: ${VARIANT}" >&2; exit 2 ;; \
    esac; \
    root="/usr/local/lib/node_modules/@dynatrace-oss/dynatrace-mcp-server"; \
    mkdir -p "${root}/node_modules"; \
    tar -xzf "/inputs/${SOURCE_ARCHIVE}" -C "${root}" --strip-components=1; \
    got="$(node -p "require('${root}/package.json').version")"; \
    test "${got}" = "${want}" || { echo "variant/archive mismatch: ${got} != ${want}" >&2; exit 3; }; \
    for spec in open:8.4.2 define-lazy-prop:2.0.0 is-docker:2.2.1 is-wsl:2.2.0; do \
        name="${spec%%:*}"; version="${spec##*:}"; \
        tmp="$(mktemp -d)"; \
        tar -xzf "/inputs/${name}-${version}.tgz" -C "${tmp}"; \
        mv "${tmp}/package" "${root}/node_modules/${name}"; \
        rm -rf "${tmp}"; \
    done; \
    ln -sf "${root}/index.js" /usr/local/bin/mcp-server-dynatrace; \
    node -e "if (typeof require('${root}/node_modules/open') !== 'function') { process.exit(1) }"; \
    test -f "${root}/ui/execute-dql/index.html"; \
    rm -rf /inputs

# Harness and fixtures for the /lab reproduction stage.  lab_support.py is placed
# in the build context by runner build (it is runner tooling, not registry data).
COPY lab_support.py reproduce.py verify.py end_to_end.py /lab/
COPY fixtures/ /lab/fixtures/

# The harness only speaks to the installed bundle over stdio; nothing listens.
CMD ["python3", "/lab/reproduce.py"]
