# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM rust:1-slim-bookworm AS build

# Build-only dependencies used to cross-compile and grant the non-root runtime
# binary access to port 443.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc-aarch64-linux-gnu \
        gcc-x86-64-linux-gnu \
        libc6-dev-amd64-cross \
        libc6-dev-arm64-cross \
        libcap2-bin \
        linux-libc-dev-amd64-cross \
        linux-libc-dev-arm64-cross \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
ARG TARGETARCH
RUN --mount=type=cache,id=portal-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=portal-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=portal-cargo-target-${TARGETARCH},target=/src/target,sharing=locked \
    set -eux; \
    case "$TARGETARCH" in \
        amd64) \
            rust_target=x86_64-unknown-linux-gnu; \
            export CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc; \
            export AR_x86_64_unknown_linux_gnu=x86_64-linux-gnu-ar; \
            export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc; \
            ;; \
        arm64) \
            rust_target=aarch64-unknown-linux-gnu; \
            export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc; \
            export AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar; \
            export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc; \
            ;; \
        *) \
            echo "unsupported TARGETARCH: $TARGETARCH" >&2; \
            exit 1; \
            ;; \
    esac; \
    rustup target add "$rust_target"; \
    cargo build --release --locked --target "$rust_target" --bin portal-relay; \
    cp "/src/target/$rust_target/release/portal-relay" /usr/local/bin/portal-relay; \
    setcap cap_net_bind_service=+ep /usr/local/bin/portal-relay; \
    mkdir -p /portal-certs

# The glibc Rust binary needs libgcc_s, which distroless/base does not include.
FROM --platform=$TARGETPLATFORM gcr.io/distroless/cc-debian12:nonroot

COPY --from=build --chown=65532:65532 /portal-certs /portal-certs
COPY --from=build --chown=65532:65532 /usr/local/bin/portal-relay /usr/local/bin/portal-relay

ENV PORTAL_URL=https://localhost:4017 \
    IDENTITY_PATH=/portal-certs \
    API_PORT=4017 \
    SNI_PORT=443 \
    WIREGUARD_PORT=51820 \
    MIN_PORT=0 \
    MAX_PORT=0 \
    UDP_ENABLED=false \
    TCP_ENABLED=false \
    DISCOVERY=false \
    LANDING_PAGE_ENABLED=true \
    BOOTSTRAPS= \
    RUST_LOG=info

VOLUME ["/portal-certs"]
EXPOSE 4017/tcp 443/tcp 443/udp 51820/udp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/portal-relay"]
