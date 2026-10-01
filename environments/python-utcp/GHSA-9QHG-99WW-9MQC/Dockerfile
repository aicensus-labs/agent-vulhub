# Pinned, network-free build recipe for GHSA-9QHG-99WW-9MQC (utcp-http redirect SSRF).
#
# The base image and every build input are pinned in metadata.toml. `runner build`
# copies the verified inputs into inputs/ (each SHA-256 checked first) and then runs
# `docker build --network none`, so nothing below may reach the network.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG VARIANT
ARG SOURCE_COMMIT
ARG SOURCE_ARCHIVE

ENV PIP_NO_INDEX=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /lab

# inputs/ is populated by runner build after SHA-256 verification.
COPY inputs/ /inputs/
COPY lab_support.py reproduce.py verify.py end_to_end.py requirements.lock /lab/
COPY fixtures/ /lab/fixtures/

# Offline install of the complete locked closure from the vendored wheels, then the
# upstream source for the selected variant: utcp core plus the utcp-http plugin, both
# taken from the pinned source archive (${SOURCE_ARCHIVE}).
RUN set -eux; \
    mkdir -p /wheels /opt/utcp-src; \
    cp /inputs/*.whl /wheels/; \
    tar -xzf "/inputs/${SOURCE_ARCHIVE}" -C /opt/utcp-src --strip-components=1; \
    python3 -m pip install --no-index --find-links=/wheels setuptools wheel; \
    python3 -m pip install --no-index --find-links=/wheels -r /lab/requirements.lock; \
    python3 -m pip install --no-index --no-build-isolation --no-deps \
        /opt/utcp-src/core \
        /opt/utcp-src/plugins/communication_protocols/http; \
    python3 -c "from utcp_http.http_call_template import HttpCallTemplate; from utcp_http.http_communication_protocol import HttpCommunicationProtocol; print('utcp-http ready', HttpCallTemplate.__name__, HttpCommunicationProtocol.__name__)"; \
    rm -rf /wheels /opt/utcp-src
