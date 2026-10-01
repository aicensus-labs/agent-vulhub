# Pinned, fully offline build for the Obot MCP OAuth token service
# (GHSA-XWMW-PRC4-V3CR).  `runner build` selects the upstream revision through
# SOURCE_ARCHIVE / SOURCE_COMMIT; both archives are GitHub tarballs of
# github.com/obot-platform/obot (vulnerable v0.22.1, patched v0.23.0).
#
# The stage is built with `--network none`.  The base image is an official Go
# image that is already present locally and also ships Debian python3 for the
# lab harness; the pinned go1.26.6 toolchain and the complete locked Go module
# closure arrive as SHA-256-pinned build inputs and are served to the go command
# through a local file:// GOPROXY, so no apt/go/npm network access is required.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG VARIANT
ARG SOURCE_COMMIT
ARG SOURCE_ARCHIVE

ENV DEBIAN_FRONTEND=noninteractive \
    GOTOOLCHAIN=local \
    CGO_ENABLED=1 \
    GOPATH=/go \
    GOCACHE=/root/.cache/go-build \
    GOPROXY=file:///proxy \
    GOSUMDB=off \
    GOFLAGS=-mod=mod

# inputs/ is populated by `runner build` after SHA-256 verification.
COPY inputs/ /inputs/
COPY go-proxy.map /tmp/go-proxy.map
# Lab harness (python3 is provided by the pinned base image).
COPY lab_support.py reproduce.py verify.py end_to_end.py /lab/
COPY fixtures/ /lab/fixtures/

# Pinned Go toolchain: both pinned go.mod revisions declare go >= 1.26.2, so the
# toolchain bundled with the base image is replaced by this exact release.
RUN rm -rf /usr/local/go \
 && tar -C /usr/local -xzf /inputs/go1.26.6.linux-amd64.tar.gz \
 && go version

# Rebuild a file:// GOPROXY from the pinned module closure (go.mod + module zip).
RUN mkdir -p /proxy \
 && while read -r input module file; do \
      mkdir -p "/proxy/$module/@v"; \
      cp "/inputs/$input" "/proxy/$module/@v/$file"; \
    done < /tmp/go-proxy.map \
 && rm -f /tmp/go-proxy.map

# Install the pinned upstream source selected by the variant.  reproduce.py
# probes /lab/upstream first and uses AVH_SOURCE_COMMIT to confirm the revision.
RUN test "$SOURCE_ARCHIVE" = "obot-$SOURCE_COMMIT.tar.gz" \
 && mkdir -p /lab/upstream \
 && tar -C /lab/upstream --strip-components=1 -xzf "/inputs/$SOURCE_ARCHIVE" \
 && printf '%s\n' "$SOURCE_COMMIT" > /lab/upstream/AVH_SOURCE_COMMIT
WORKDIR /lab/upstream

# Compile the affected package and its test binary with no network, so an
# incomplete dependency closure fails the image build instead of the run.
RUN go build ./pkg/jwt/persistent/ \
 && go test -c -o /dev/null ./pkg/jwt/persistent/

ENTRYPOINT []
WORKDIR /lab
