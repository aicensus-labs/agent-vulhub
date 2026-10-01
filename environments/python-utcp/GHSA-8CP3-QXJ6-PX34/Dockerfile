# Offline, version-pinned recipe for GHSA-8CP3-QXJ6-PX34.
#
# utcp-http's OpenAPI converter copies the untrusted document's
# ``clientCredentials.tokenUrl`` verbatim into the generated ``OAuth2Auth``, and
# ``HttpCommunicationProtocol._handle_oauth2`` POSTs ``client_id``/``client_secret``
# to that URL.  1.1.3 never applies the already-present ``ensure_secure_url`` guard,
# so a spec pointing the token endpoint at a non-loopback plaintext-HTTP address
# exfiltrates the credentials; 1.1.4 calls the guard both at the conversion site
# ("OAuth2 tokenUrl in OpenAPI spec") and at the token sink ("OAuth2 token URL").
#
# Base image: python:3.11-slim pinned by digest and verified present locally
# (linux/amd64).  It provides the interpreter the declared runtime harness
# ("python3") needs; both upstream packages declare requires-python >=3.10.
#
# ``runner build`` places every SHA-256-verified build input into inputs/: the two
# upstream sdists at the pinned revisions named by vulnerable/patched.archive, the
# shared utcp 1.1.2 core, and the complete dependency closure of utcp-http
# 1.1.3/1.1.4 resolved for CPython 3.11 / manylinux x86_64, plus the offline build
# tooling.  docker build runs with --network none and every pip invocation uses
# --no-index, so nothing is fetched at build time.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG VARIANT
ARG SOURCE_COMMIT
ARG SOURCE_ARCHIVE

WORKDIR /lab
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# inputs/ is populated by `runner build` after SHA-256 verification.
COPY inputs/ /inputs/
COPY lab_support.py reproduce.py verify.py end_to_end.py /lab/
COPY fixtures/ /lab/fixtures/

# Refuse to build a variant whose archive is not the revision it pins.
RUN set -eux; \
    case "${VARIANT}:${SOURCE_ARCHIVE}" in \
      "vulnerable:utcp_http-1.1.3.tar.gz") \
        want="244df66da6be64bcda2702a8d198b685f52ea46a"; \
        want_sha="748353b9b42012f928a1aa2c0e05d6555c53492a7b880d34c30708b3e8fe9d1d";; \
      "patched:utcp_http-1.1.4.tar.gz") \
        want="fc3268e2a62e1181f91a63faf0a9bcee7639db29"; \
        want_sha="889942f31f5419b2d8456ff3b6c56ead67000818f125fac04fbd99e98344b2c3";; \
      *) echo "unexpected variant/archive pair: ${VARIANT}/${SOURCE_ARCHIVE}" >&2; exit 2;; \
    esac; \
    test "${SOURCE_COMMIT}" = "${want}"; \
    test -f "/inputs/${SOURCE_ARCHIVE}"; \
    echo "${want_sha}  /inputs/${SOURCE_ARCHIVE}" | sha256sum -c -

# 1/4 Offline build tooling: the sdists use the setuptools PEP 517 backend.
RUN set -eux; \
    python3 -m pip install --no-index --find-links=/inputs --no-deps \
        "packaging==26.3" "setuptools==84.0.0" "wheel==0.48.0"

# 2/4 The complete locked dependency closure of the selected variant (utcp-http
#     1.1.3/1.1.4 + utcp 1.1.2 and their transitive requirements, resolved for
#     CPython 3.11 / manylinux x86_64; the variants differ only in the utcp-http
#     sdist installed in step 3).
RUN set -eux; \
    pkgs="annotated-types==0.8.0 aiohappyeyeballs==2.7.1 aiohttp==3.14.3 \
      aiosignal==1.4.0 attrs==26.1.0 authlib==1.8.0 cffi==2.1.1 \
      cryptography==50.0.1 frozenlist==1.8.0 idna==3.20 joserfc==1.7.5 \
      multidict==6.9.1 propcache==0.5.4 pycparser==3.0 pydantic==2.13.5 \
      pydantic-core==2.46.5 python-dotenv==1.2.3 pyyaml==6.0.3 tomli==2.4.1 \
      typing-extensions==4.16.0 typing-inspection==0.4.4 yarl==1.25.1"; \
    python3 -m pip install --no-index --find-links=/inputs --no-deps ${pkgs}; \
    python3 -m pip check

# 3/4 The pinned upstream source: the shared utcp 1.1.2 core, then the variant sdist.
RUN set -eux; \
    python3 -m pip install --no-index --find-links=/inputs --no-deps --no-build-isolation \
        "/inputs/utcp-1.1.2.tar.gz"; \
    python3 -m pip install --no-index --find-links=/inputs --no-deps --no-build-isolation \
        "/inputs/${SOURCE_ARCHIVE}"

# 4/4 Prove the installed revision and that the mechanism modules import.
RUN set -eux; \
    expected="1.1.3"; \
    if [ "${VARIANT}" = "patched" ]; then expected="1.1.4"; fi; \
    actual="$(python3 -c 'import importlib.metadata as md; print(md.version("utcp-http"))')"; \
    test "${actual}" = "${expected}"; \
    python3 -c 'import importlib.metadata as md; print("utcp", md.version("utcp"))'; \
    python3 -c 'import utcp_http.http_call_template, utcp_http.http_communication_protocol, utcp_http.openapi_converter; print("utcp_http mechanism imports ok")'
