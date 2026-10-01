ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG VARIANT
ARG SOURCE_COMMIT
ARG SOURCE_ARCHIVE
# The Rust toolchain is a pinned build input rather than a base-image change:
# the public base image ships no cargo, and switching base images would cost the
# Python 3 that runtime.harness needs. Crates are vendored and SHA-256 pinned, so
# the build stays fully offline.
#
# The mechanism is exercised through the crate's own test harness. Upstream's fix
# added crates/codegen/vtcode-core/src/hooks/lifecycle/tests/workspace_hook_approval.rs
# and mounted it with `mod workspace_hook_approval;`. This lab mounts its own
# module the same way and drives the real LifecycleHookEngine, because that is
# where the approval gate lives and it is reachable without any TUI.
WORKDIR /lab
COPY inputs/ /inputs/
COPY reproduce.py verify.py end_to_end.py /lab/
COPY fixtures/ /lab/fixtures/
COPY lab/ /lab/lab/
RUN test -n "${SOURCE_COMMIT}" \
    && case "$(tar -tzf "/inputs/${SOURCE_ARCHIVE}" | sed -n '1p')" in "VTCode-${SOURCE_COMMIT}/"*) ;; *) echo 'source archive/commit mismatch' >&2; exit 1 ;; esac \
    && mkdir -p /lab/app /lab/results /lab/rust-dist \
    && tar -xJf /inputs/rust-1.93.0-x86_64-unknown-linux-gnu.tar.xz -C /lab/rust-dist --strip-components=1 \
    && /lab/rust-dist/install.sh --prefix=/opt/rust --without=rust-docs \
    && tar -xzf "/inputs/${SOURCE_ARCHIVE}" --strip-components=1 -C /lab/app \
    && if [ "${VARIANT}" = "vulnerable" ]; then tar -xzf /inputs/vtcode-vulnerable-cargo-vendor.tar.gz -C /lab/app; else tar -xzf /inputs/vtcode-patched-cargo-vendor.tar.gz -C /lab/app; fi \
    && /opt/rust/bin/rustc --version \
    && /opt/rust/bin/cargo --version \
    && mkdir -p /lab/app/.cargo \
    && printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "vendor"\n\n[net]\noffline = true\n' > /lab/app/.cargo/config.toml \
    && TESTS=/lab/app/crates/codegen/vtcode-core/src/hooks/lifecycle/tests \
    && test -d "${TESTS}" \
    && cp /lab/lab/workspace_hook_approval.rs "${TESTS}/" \
    && if [ "${VARIANT}" = "vulnerable" ]; then cp /lab/lab/VariantVulnerable.rs "${TESTS}/variant.rs"; else cp /lab/lab/VariantPatched.rs "${TESTS}/variant.rs"; fi \
    && if ! grep -q '^mod workspace_hook_approval;$' /lab/app/crates/codegen/vtcode-core/src/hooks/lifecycle/tests.rs; then echo 'mod workspace_hook_approval;' >> /lab/app/crates/codegen/vtcode-core/src/hooks/lifecycle/tests.rs; fi \
    && cd /lab/app \
    && (ulimit -n 65536 2>/dev/null || true) \
    && CARGO_HOME=/lab/cargo-home PATH=/opt/rust/bin:$PATH CARGO_BUILD_JOBS=8 \
       cargo test --locked --offline -p vtcode-core --no-run \
    && CARGO_HOME=/lab/cargo-home PATH=/opt/rust/bin:$PATH \
       cargo test --locked --offline -p vtcode-core lab_workspace_hook_approval -- --list
