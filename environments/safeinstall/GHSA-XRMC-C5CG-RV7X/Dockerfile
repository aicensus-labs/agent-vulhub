# Reviewed, version-pinned, network-free recipe for GHSA-XRMC-C5CG-RV7X.
# The base image carries a digest and is served from the local image store.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG VARIANT
ARG SOURCE_COMMIT
ARG SOURCE_ARCHIVE

ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /lab

# inputs/ is populated by `runner build` after SHA-256 verification, so this
# recipe never fetches anything and never installs packages from the network.
COPY inputs/ /inputs/
# Flat locked production closure: "<archive filename><TAB><node_modules path>".
COPY deps.tsv /lab/deps.tsv
COPY lab_support.py /lab/lab_support.py
COPY reproduce.py verify.py end_to_end.py /lab/
COPY fixtures/ /lab/fixtures/

# Unpack the pinned upstream source snapshot, the pinned compiled release
# artifact selected by SOURCE_ARCHIVE and every locked runtime dependency.
RUN set -eu; \
    mkdir -p /lab/source /lab/upstream/node_modules/safeinstall-cli; \
    while IFS="$(printf '\t')" read -r archive target; do \
        [ -n "$archive" ] || continue; \
        mkdir -p "/lab/upstream/node_modules/$target"; \
        tar -xzf "/inputs/$archive" -C "/lab/upstream/node_modules/$target" --strip-components=1; \
    done < /lab/deps.tsv; \
    tar -xzf "/inputs/$SOURCE_ARCHIVE" -C /lab/upstream/node_modules/safeinstall-cli --strip-components=1; \
    for snapshot in /inputs/safeinstall-src-*.tar.gz; do \
        tar -xzf "$snapshot" -C /lab/source; \
    done; \
    rm -f /lab/deps.tsv; \
    test -d /lab/upstream/node_modules/safeinstall-cli/dist; \
    test -d "/lab/source/SafeInstall-$SOURCE_COMMIT"; \
    case "$VARIANT" in \
        vulnerable) expected_version=0.10.1 ;; \
        patched) expected_version=0.10.2 ;; \
        *) echo "unsupported variant: $VARIANT" >&2; exit 2 ;; \
    esac; \
    test "$(node -p 'require("/lab/upstream/node_modules/safeinstall-cli/package.json").version')" = "$expected_version"; \
    node -e "const m = require('/lab/upstream/node_modules/safeinstall-cli/dist/guard-commands.js'); if (typeof m.analyzeShellCommand !== 'function') { throw new Error('missing analyzeShellCommand'); }"; \
    node -e "require('/lab/upstream/node_modules/safeinstall-cli/dist/specs.js');"
