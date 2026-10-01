# GHSA-VW82-7FV8-R6GP -- Obot authorization bypass in /mcp-connect/{id}.
#
# One variant per invocation. The runner passes VARIANT / SOURCE_COMMIT /
# SOURCE_ARCHIVE for the vulnerable (v0.21.0) or patched (v0.21.1) revision;
# everything else is identical, so the two images differ only by the pinned
# upstream tree they carry.
#
# Every byte is supplied by inputs/, so this recipe builds with --network none:
#   * go1.26.2.linux-amd64.tar.gz  pinned toolchain (go.mod declares go 1.26.2,
#     and reproduce.py exports GOTOOLCHAIN=local)
#   * obot-go-mod-cache.tar.gz     the locked module closure for
#     ./pkg/api/authz/ (module zips plus the .mod files of the whole module
#     graph), extracted straight into GOMODCACHE
#   * obot-<tag>-source.tar.gz     the pinned upstream tree
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG VARIANT
ARG SOURCE_COMMIT
ARG SOURCE_ARCHIVE

ENV PATH=/usr/local/go/bin:${PATH} \
    GOPATH=/go \
    GOMODCACHE=/go/pkg/mod \
    GOCACHE=/root/.cache/go-build \
    GOFLAGS=-mod=mod \
    GOPROXY=off \
    GOSUMDB=off \
    GOTOOLCHAIN=local \
    CGO_ENABLED=0

WORKDIR /lab
COPY inputs/ /inputs/
COPY reproduce.py verify.py end_to_end.py lab_support.py /lab/
COPY fixtures/ /lab/fixtures/

# Install the pinned toolchain, unpack the offline module closure, unpack the
# pinned upstream tree at /lab/src/${VARIANT}, then prove the closure is
# complete by compiling the harness test that reproduce.py runs later.
RUN set -eux; \
    tar -C /usr/local -xzf /inputs/go1.26.2.linux-amd64.tar.gz; \
    mkdir -p "${GOMODCACHE}"; \
    tar -C "${GOMODCACHE}" -xzf /inputs/obot-go-mod-cache.tar.gz; \
    test "$(tar -tzf "/inputs/${SOURCE_ARCHIVE}" | sed -n '1p')" = "obot-${SOURCE_COMMIT}/"; \
    mkdir -p "/lab/src/${VARIANT}"; \
    tar -xzf "/inputs/${SOURCE_ARCHIVE}" --strip-components=1 -C "/lab/src/${VARIANT}"; \
    test -f "/lab/src/${VARIANT}/go.mod"; \
    cp /lab/fixtures/harness/zz_ghsa_vw82_harness_test.go "/lab/src/${VARIANT}/pkg/api/authz/"; \
    cd "/lab/src/${VARIANT}"; \
    go version; \
    go test -c -o /tmp/authz.test ./pkg/api/authz/; \
    rm -f "/lab/src/${VARIANT}/pkg/api/authz/zz_ghsa_vw82_harness_test.go" /tmp/authz.test

WORKDIR /lab
