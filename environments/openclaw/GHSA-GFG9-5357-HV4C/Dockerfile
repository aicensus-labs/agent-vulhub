# Offline, version-pinned build recipe for GHSA-GFG9-5357-HV4C (OpenClaw webchat
# audio embedding reads local files without local-root containment).
#
# The runner supplies BASE_IMAGE (a locally present, digest-pinned image), VARIANT,
# SOURCE_COMMIT and SOURCE_ARCHIVE. Everything else is copied from inputs/, which the
# runner verifies against the metadata.toml SHA-256 values before the build starts, and
# the build itself runs with --network none: no step below reaches a repository.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG VARIANT
ARG SOURCE_COMMIT
ARG SOURCE_ARCHIVE

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    TZ=UTC

# --- Node.js 22 runtime, unpacked from the vendored official archive ---------
# The base image supplies python3 (runtime.harness = python3); upstream pins
# engines.node >= 22.14.0, so the pinned Node.js 22 tarball provides node + npm.
COPY inputs/node-v22.23.3-linux-x64.tar.gz /tmp/node.tar.gz
RUN tar -xzf /tmp/node.tar.gz -C /usr/local --strip-components=1 \
 && rm -f /tmp/node.tar.gz \
 && node --version \
 && npm --version

# --- Locked npm dependency closure for the pinned module graph ---------------
# The upstream module reaches src/media/mime.ts (file-type) and src/plugin-sdk/*,
# which pull chalk 5.6.2 and tslog 4.10.2. Versions are the pnpm-lock.yaml pins of
# openclaw v2026.4.14; esbuild resolves them through NODE_PATH at run time, so the
# packages are unpacked into an isolated node_modules tree and never installed.
COPY inputs/chalk-5.6.2.tgz inputs/tslog-4.10.2.tgz inputs/file-type-22.0.1.tgz \
     inputs/strtok3-10.3.5.tgz inputs/token-types-6.1.2.tgz inputs/uint8array-extras-1.5.0.tgz \
     inputs/tokenizer-inflate-0.4.1.tgz inputs/tokenizer-token-0.3.0.tgz \
     inputs/borewit-text-codec-0.2.2.tgz inputs/debug-4.4.3.tgz inputs/ms-2.1.3.tgz \
     inputs/ieee754-1.2.1.tgz /tmp/npm/
RUN set -eux; \
    root=/opt/openclaw-deps/node_modules; \
    mkdir -p "$root/@tokenizer" "$root/@borewit"; \
    unpack() { mkdir -p "$2"; tar -xzf "/tmp/npm/$1" -C "$2" --strip-components=1; }; \
    unpack chalk-5.6.2.tgz "$root/chalk"; \
    unpack tslog-4.10.2.tgz "$root/tslog"; \
    unpack file-type-22.0.1.tgz "$root/file-type"; \
    unpack strtok3-10.3.5.tgz "$root/strtok3"; \
    unpack token-types-6.1.2.tgz "$root/token-types"; \
    unpack uint8array-extras-1.5.0.tgz "$root/uint8array-extras"; \
    unpack tokenizer-inflate-0.4.1.tgz "$root/@tokenizer/inflate"; \
    unpack tokenizer-token-0.3.0.tgz "$root/@tokenizer/token"; \
    unpack borewit-text-codec-0.2.2.tgz "$root/@borewit/text-codec"; \
    unpack debug-4.4.3.tgz "$root/debug"; \
    unpack ms-2.1.3.tgz "$root/ms"; \
    unpack ieee754-1.2.1.tgz "$root/ieee754"; \
    rm -rf /tmp/npm; \
    test -f "$root/chalk/package.json"; \
    test -f "$root/tslog/package.json"; \
    test -f "$root/file-type/package.json"; \
    test -f "$root/strtok3/package.json"; \
    test -f "$root/token-types/package.json"; \
    test -f "$root/uint8array-extras/package.json"; \
    test -f "$root/@tokenizer/inflate/package.json"; \
    test -f "$root/@tokenizer/token/package.json"; \
    test -f "$root/@borewit/text-codec/package.json"; \
    test -f "$root/debug/package.json"; \
    test -f "$root/ms/package.json"; \
    test -f "$root/ieee754/package.json"

# --- Pinned esbuild binary ---------------------------------------------------
# reproduce.py bundles the pinned TypeScript module (.js NodeNext specifiers) into one
# ESM file; the native linux-x64 binary is taken straight from the pinned npm tarball
# rather than through esbuild's postinstall download.
COPY inputs/esbuild-linux-x64-0.27.7.tgz /tmp/esbuild.tgz
RUN mkdir -p /opt/esbuild \
 && tar -xzf /tmp/esbuild.tgz -C /opt/esbuild --strip-components=1 \
 && rm -f /tmp/esbuild.tgz \
 && chmod +x /opt/esbuild/bin/esbuild \
 && /opt/esbuild/bin/esbuild --version

# --- Pinned upstream OpenClaw source tree for this variant -------------------
# vulnerable = v2026.4.14 (323493fa...), patched = v2026.4.15 (041266a6...).
COPY inputs/${SOURCE_ARCHIVE} /tmp/source.tar.gz
RUN set -eux; \
    mkdir -p /opt/openclaw; \
    tar -xzf /tmp/source.tar.gz -C /opt/openclaw --strip-components=1; \
    rm -f /tmp/source.tar.gz; \
    module=/opt/openclaw/src/gateway/server-methods/chat-webchat-media.ts; \
    test -f "$module"; \
    case "${VARIANT}" in \
      vulnerable) grep -q 'buildWebchatAudioContentBlocksFromReplyPayloads' "$module"; \
                  ! grep -q 'assertLocalMediaAllowed' "$module" ;; \
      patched)    grep -q 'assertLocalMediaAllowed' "$module" ;; \
      *)          echo "unknown VARIANT ${VARIANT}" >&2; exit 2 ;; \
    esac; \
    echo "${SOURCE_COMMIT}" > /opt/openclaw/COMMIT

# --- Lab harness -------------------------------------------------------------
WORKDIR /lab
COPY reproduce.py verify.py end_to_end.py lab_support.py /lab/
COPY fixtures/ /lab/fixtures/

# reproduce.py resolves the pinned tree, the dependency closure and the bundler from
# these variables first.
ENV OPENCLAW_SOURCE_ROOT=/opt/openclaw \
    OPENCLAW_DEPS_ROOT=/opt/openclaw-deps/node_modules \
    ESBUILD_BINARY=/opt/esbuild/bin/esbuild
