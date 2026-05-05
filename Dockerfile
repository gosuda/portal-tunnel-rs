# Phase 7 U8.11 — multi-stage Rust builder for portal-relay + portal-demo.
#
# Stage 1: official Rust image at the workspace MSRV (rust-toolchain.toml
# pins 1.95). Builds with `--release --bin portal-relay` and `--release
# --bin portal-demo` against the workspace Cargo.lock. The frontend
# bundle lives at crates/portal-relay-bin/assets/ and is embedded into
# the binary at compile time via rust-embed; **no Node toolchain enters
# the build image**.
#
# Stage 2: gcr.io/distroless/cc-debian12:nonroot — NOT distroless/static.
# aws-lc-rs links libc through the cc-crate, so the runtime needs
# libc + libgcc + libssl-equivalent system libraries. The cc variant
# carries those; the static variant would fail to link. Per Phase 7
# U8.7 dep-spawning-audit (commit af3ae66) the chosen runtime base is
# documented as the right balance between attack surface and runtime
# correctness.
#
# nonroot user (uid/gid 65532 on the distroless image) means the
# binary cannot bind privileged ports (<1024) by default. Operators
# expose API_PORT / SNI_PORT / WIREGUARD_PORT at >=1024 via
# docker-compose port-mapping (the docker-compose.yml that lands
# alongside this Dockerfile in the same U8.11 commit translates the
# inside-container ports to the operator-chosen public ports).
#
# Runtime selection
# -----------------
# The image ships both `portal-relay` (the primary, ship-critical
# binary) and `portal-demo` (an auxiliary smoke / load-generator).
# `ENTRYPOINT` is set to `portal-relay` so `docker run gosuda/portal-tunnel-rs:dev`
# defaults to the relay; running the demo requires an explicit
# `--entrypoint` override, NOT a positional arg.
#
# Build:
#     docker build -t gosuda/portal-tunnel-rs:dev .
#
# Smoke (per plan U8.11 §Verification):
#     # primary: portal-relay help via the default entrypoint
#     docker run --rm gosuda/portal-tunnel-rs:dev --help
#     docker run --rm gosuda/portal-tunnel-rs:dev serve --help
#     # auxiliary: portal-demo via explicit --entrypoint override
#     docker run --rm --entrypoint /app/portal-demo gosuda/portal-tunnel-rs:dev --help
#
# Operators who want a symmetric two-binary image (one container per
# binary) can either build two images with different ENTRYPOINTs or
# wrap the override in a docker-compose service block — the U8.11
# docker-compose.yml takes the latter approach.

# ---------------------------------------------------------------------------
# Stage 1: builder
# ---------------------------------------------------------------------------
FROM rust:1.95-bookworm AS builder

WORKDIR /workspace

# Install the C toolchain that aws-lc-rs's cc-crate consumes.
# rust:1.95-bookworm already ships gcc/cc + make; cmake is needed for
# aws-lc-rs's dependency build (see ADR-0002's cmake carve-out).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        cmake \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy the workspace manifest first so dep resolution can be cached.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .cargo/ ./.cargo/

# Copy every member crate's manifest. Source files come in the next
# layer so a source-only edit does not invalidate the dep cache.
COPY crates/portal-wire/Cargo.toml crates/portal-wire/Cargo.toml
COPY crates/portal-crypto/Cargo.toml crates/portal-crypto/Cargo.toml
COPY crates/portal-net/Cargo.toml crates/portal-net/Cargo.toml
COPY crates/portal-acme/Cargo.toml crates/portal-acme/Cargo.toml
COPY crates/portal-relay/Cargo.toml crates/portal-relay/Cargo.toml
COPY crates/portal-sdk/Cargo.toml crates/portal-sdk/Cargo.toml
COPY crates/portal-relay-bin/Cargo.toml crates/portal-relay-bin/Cargo.toml
COPY crates/portal-cli/Cargo.toml crates/portal-cli/Cargo.toml
COPY crates/portal-demo/Cargo.toml crates/portal-demo/Cargo.toml
COPY xtask/Cargo.toml xtask/Cargo.toml

# Source code — invalidates only on real source change, not on dep
# version bumps.
COPY crates/ crates/
COPY xtask/ xtask/

# Release build of the two ship-critical binaries. Locked builds use
# the committed Cargo.lock so the runtime image's behaviour is
# deterministic across CI / local / operator builds.
RUN cargo build --release --locked --bin portal-relay --bin portal-demo

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot

# Default workdir matches the operator-typical /var/lib/portal layout
# without forcing a path the binary itself cares about.
WORKDIR /app

# Copy the two release binaries to PATH-discoverable names. The
# install.sh script (committed at workspace root in 364a420) places
# the binary as `portal`; the Docker image keeps the `portal-relay` /
# `portal-demo` names because docker-compose dispatches by service.
COPY --from=builder /workspace/target/release/portal-relay /app/portal-relay
COPY --from=builder /workspace/target/release/portal-demo /app/portal-demo

# Default command: print help. docker-compose.yml overrides with the
# `serve` subcommand and the operator-supplied env-var-driven
# configuration surface (PORTAL_URL, BOOTSTRAPS, DISCOVERY, etc. —
# documented in the U8.11 docker-compose.yml lands in the same
# commit).
ENTRYPOINT ["/app/portal-relay"]
CMD ["--help"]
