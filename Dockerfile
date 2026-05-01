FROM rust:1-slim-bookworm AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked --bin portal-relay

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /nonexistent --shell /usr/sbin/nologin portal \
    && mkdir -p /portal-certs \
    && chown portal:portal /portal-certs
COPY --from=build /src/target/release/portal-relay /usr/local/bin/portal-relay
RUN setcap cap_net_bind_service=+ep /usr/local/bin/portal-relay

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
USER portal
ENTRYPOINT ["/usr/local/bin/portal-relay"]
