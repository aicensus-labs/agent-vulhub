ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG VARIANT
ARG SOURCE_COMMIT
ARG SOURCE_ARCHIVE
# inputs/ is populated by runner build after SHA-256 verification.
WORKDIR /lab
COPY inputs/ /inputs/
COPY reproduce.py verify.py end_to_end.py /lab/
COPY fixtures/ /lab/fixtures/
RUN test -n "${SOURCE_COMMIT}" \
    && case "$(tar -tzf "/inputs/${SOURCE_ARCHIVE}" | sed -n '1p')" in "VTCode-${SOURCE_COMMIT}/"*) ;; *) echo 'source archive/commit mismatch' >&2; exit 1 ;; esac \
    && mkdir -p /lab/app \
    && tar -xzf "/inputs/${SOURCE_ARCHIVE}" --strip-components=1 -C /lab/app \
    && if [ "${VARIANT}" = "vulnerable" ]; then tar -xzf /inputs/vtcode-vulnerable-cargo-vendor.tar.gz -C /lab/app; else tar -xzf /inputs/vtcode-patched-cargo-vendor.tar.gz -C /lab/app; fi \
    && cd /lab/app \
    && cargo build --locked --offline \
    && mkdir -p /lab/results \
    && test -x /lab/app/target/debug/vtcode
