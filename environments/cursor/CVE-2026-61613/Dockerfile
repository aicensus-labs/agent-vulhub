# Replace with the reviewed, version-pinned build recipe for this environment.
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
RUN echo 'Environment recipe is not implemented' >&2; exit 2
