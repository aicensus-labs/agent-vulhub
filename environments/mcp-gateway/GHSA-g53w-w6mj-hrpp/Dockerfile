ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG VARIANT
ARG SOURCE_COMMIT
ARG SOURCE_ARCHIVE
# inputs/ is populated by runner build after SHA-256 verification.
# Install the complete upstream source and locked dependencies with no network.
WORKDIR /lab
COPY inputs/ /inputs/
COPY reproduce.py verify.py end_to_end.py /lab/
COPY fixtures/ /lab/fixtures/
COPY lab_support.py /lab/
COPY lab/ /lab/lab/

# The pinned Go toolchain and the per-variant vendored module tree are build
# inputs, so the image needs no network and the base image stays unchanged.
RUN test -n "${SOURCE_COMMIT}" \
    && case "$(tar -tzf "/inputs/${SOURCE_ARCHIVE}" | sed -n '1p')" in "mcp-gateway-${SOURCE_COMMIT}/"*) ;; *) echo 'source archive/commit mismatch' >&2; exit 1 ;; esac \
    && tar -xzf /inputs/go1.25.9.linux-amd64.tar.gz -C /usr/local \
    && mkdir -p /lab/app \
    && tar -xzf "/inputs/${SOURCE_ARCHIVE}" --strip-components=1 -C /lab/app \
    && case "${VARIANT}" in \
         vulnerable) tar -xzf /inputs/mcp-gateway-vendor-vulnerable.tar.gz -C /lab/app ;; \
         patched)    tar -xzf /inputs/mcp-gateway-vendor-patched.tar.gz -C /lab/app ;; \
         *) echo 'unknown variant' >&2; exit 1 ;; \
       esac \
    && cp /lab/lab/lab_mechanism_test.go /lab/app/internal/mcp-router/ \
    && case "${VARIANT}" in \
         vulnerable) cp /lab/lab/lab_build_vulnerable.go /lab/app/internal/mcp-router/ ;; \
         patched)    cp /lab/lab/lab_build_patched.go /lab/app/internal/mcp-router/ ;; \
       esac \
    && cd /lab/app \
    && GOFLAGS=-mod=vendor GOPROXY=off CGO_ENABLED=0 /usr/local/go/bin/go test \
         -c -o /lab/router-mechanism.test ./internal/mcp-router/ \
    && mkdir -p /lab/results \
    && test -x /lab/router-mechanism.test
