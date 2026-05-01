FROM rust:1-slim-bookworm AS build

# Build-only dependency used to grant the non-root runtime binary access to port 443.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked --bin portal-relay \
    && setcap cap_net_bind_service=+ep /src/target/release/portal-relay \
    && mkdir -p /portal-certs

# The glibc Rust binary needs libgcc_s, which distroless/base does not include.
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=build --chown=65532:65532 /portal-certs /portal-certs
COPY --from=build --chown=65532:65532 /src/target/release/portal-relay /usr/local/bin/portal-relay

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
