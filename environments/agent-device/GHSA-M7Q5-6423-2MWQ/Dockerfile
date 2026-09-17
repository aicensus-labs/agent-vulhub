# Replace with the reviewed, version-pinned build recipe for this environment.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG VARIANT
ARG SOURCE_COMMIT
ARG SOURCE_ARCHIVE
ENV PATH="/opt/node/bin:${PATH}"
# inputs/ is populated by runner build after SHA-256 verification.
WORKDIR /lab
COPY inputs/ /inputs/
COPY reproduce.py verify.py end_to_end.py /lab/
COPY fixtures/ /lab/fixtures/
COPY lab_support.py /lab/
RUN test -n "${SOURCE_COMMIT}" \
    && case "$(tar -tzf "/inputs/${SOURCE_ARCHIVE}" | sed -n '1p')" in "agent-device-${SOURCE_COMMIT}/"*) ;; *) echo 'source archive/commit mismatch' >&2; exit 1 ;; esac \
    && mkdir -p /lab/app /opt/node \
    && tar -xJf /inputs/node-v22.14.0-linux-x64.tar.xz --strip-components=1 -C /opt/node \
    && tar -xzf "/inputs/${SOURCE_ARCHIVE}" --strip-components=1 -C /lab/app \
    && if [ "${VARIANT}" = "vulnerable" ]; then tar -xzf /inputs/agent-device-vulnerable-node-deps.tar.gz -C /lab/app; else tar -xzf /inputs/agent-device-patched-node-deps.tar.gz -C /lab/app; fi \
    && cd /lab/app \
    && NODE_OPTIONS=--experimental-strip-types ./node_modules/.bin/tsdown --config-loader native \
    && mkdir -p /lab/results \
    && test -x /lab/app/bin/agent-device.mjs
