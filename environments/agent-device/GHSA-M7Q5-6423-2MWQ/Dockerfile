# Replace with the reviewed, version-pinned build recipe for this environment.
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
    && case "$(tar -tzf "/inputs/${SOURCE_ARCHIVE}" | sed -n '1p')" in "agent-device-${SOURCE_COMMIT}/"*) ;; *) echo 'source archive/commit mismatch' >&2; exit 1 ;; esac \
    && mkdir -p /lab/app \
    && tar -xzf "/inputs/${SOURCE_ARCHIVE}" --strip-components=1 -C /lab/app \
    && if [ "${VARIANT}" = "vulnerable" ]; then tar -xzf /inputs/agent-device-vulnerable-node-deps.tar.gz -C /lab/app; else tar -xzf /inputs/agent-device-patched-node-deps.tar.gz -C /lab/app; fi \
    && cd /lab/app \
    && ./node_modules/.bin/tsdown \
    && mkdir -p /lab/results \
    && test -x /lab/app/bin/agent-device.mjs
