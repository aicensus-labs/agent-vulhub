# Pinned, fully offline build recipe for gitlab-mcp (GHSA-5648-RGJ9-V224).
#
# Two upstream revisions are built from the same closure, selected by VARIANT:
#   vulnerable = tag v2.1.28 (commit 139a479147a52f65d47e8fee142214c4d5392468):
#       utils/graphql-query.ts classifies write operations with the regex
#       /(?:^|[};]\s*)(mutation|subscription)\b/, which does not accept a comma as
#       the (GraphQL-insignificant) separator before the operation keyword, so
#       ",mutation { ... }" is misclassified as read-only. index.ts's
#       execute_graphql branch also never calls rejectIfProjectScopedDeployment().
#   patched    = tag v2.1.30 (commit cff3ebeec272d7cc609d9b3cab57f52cb15fae96):
#       the same module is a brace-depth state machine that only accepts an operation
#       keyword at a document position, and the execute_graphql branch rejects
#       project-scoped deployments outright.
#
# Every artifact lives in metadata.toml build.inputs and is SHA-256 verified by the
# runner before the build starts. The locked dependency closure of this environment is
# empty: the execution path loads exactly one upstream file (utils/graphql-query.ts),
# which imports nothing and needs only Node's type stripping; the Python entrypoint
# uses the CPython standard library. Nothing is fetched, and `docker build` is invoked
# with --network none, so the build never touches the network.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG VARIANT
ARG SOURCE_COMMIT
ARG SOURCE_ARCHIVE

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NO_COLOR=1 \
    NODE_NO_WARNINGS=1

WORKDIR /lab

# inputs/ is populated by `runner build` after SHA-256 verification; lab_support.py is
# the runner-provided helper copied into the build context.
COPY inputs/ /inputs/
COPY reproduce.py verify.py end_to_end.py /lab/
COPY lab_support.py /lab/
COPY fixtures/ /lab/fixtures/

# Install the VARIANT's upstream source at /lab/upstream/<variant>, which is the
# repo_dir that fixtures/pin.json records. Build-time assertions pin the revision by
# upstream package version and by the SHA-256 of the module the mechanism calls, so a
# mislabelled archive fails the build instead of silently swapping revisions.
RUN set -eux; \
    test -n "${SOURCE_COMMIT}"; \
    test -n "${SOURCE_ARCHIVE}"; \
    target="/lab/upstream/${VARIANT}"; \
    mkdir -p "${target}"; \
    tar -xzf "/inputs/${SOURCE_ARCHIVE}" --strip-components=1 -C "${target}"; \
    case "${VARIANT}" in \
      vulnerable) \
        grep -q '"version": "2.1.28"' "${target}/package.json"; \
        printf '%s  %s\n' "0ee49475446ca2eb4add393eca0014ad04e526281bd3d3171c538f04729e47e7" \
          "${target}/utils/graphql-query.ts" | sha256sum -c - ;; \
      patched) \
        grep -q '"version": "2.1.30"' "${target}/package.json"; \
        printf '%s  %s\n' "4fc7128c866cf4fb24fb3a723853a25c2582f4437bb4c3ae3533a9a191a7b6e5" \
          "${target}/utils/graphql-query.ts" | sha256sum -c - ;; \
      *) echo "unknown VARIANT: ${VARIANT}" >&2; exit 1 ;; \
    esac; \
    test -f "${target}/index.ts"; \
    node_version="$(node --version)"; \
    case "${node_version}" in \
      v22.*|v23.*|v24.*) ;; \
      *) echo "Node ${node_version} cannot strip TypeScript types" >&2; exit 1 ;; \
    esac; \
    node --experimental-strip-types --disable-warning=ExperimentalWarning \
      -e "const{pathToFileURL}=require('node:url');import(pathToFileURL(process.argv[1]).href).then((m)=>{if(typeof m.graphqlQueryContainsWriteOperation!=='function'){throw new Error('pinned module exports no graphqlQueryContainsWriteOperation')}console.log('classifier export ok')})" \
      "${target}/utils/graphql-query.ts"; \
    mkdir -p /lab/results
