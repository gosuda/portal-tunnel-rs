# Deployment Notes

`portal-relay` is the Rust relay binary. It accepts the same core listener and
transport environment variables as the Go relay for the implemented surface.

## Required Runtime State

Mount persistent storage at `IDENTITY_PATH`. The default Docker Compose file
uses a named volume at `/portal-certs` so the non-root `portal` user can write
relay state without host UID/GID setup. If you replace it with a bind mount,
make sure the mounted directory is writable by the container user. The relay
stores:

- `identity.json`
- `admin_settings.json`
- `fullchain.pem`
- `privatekey.pem`

If TLS files are absent, the current Rust relay creates a local self-signed
certificate. Managed ACME DNS-01 providers are not implemented yet. The Rust
relay recognizes the Go relay's managed ACME/ENS environment variable names, but
fails fast when they are set instead of silently ignoring them.

## Optional Frontend And Install Surface

Set `FRONTEND_DIST` to a built frontend dist directory when the relay should
serve the web UI. The directory may either contain `portal.html` directly or an
`app/portal.html` tree matching the Go relay build output. When configured, the
Rust relay serves `/`, `/app`, `/app/*`, `/assets/*`, favicon assets, and
`/tunnel/status` after fixed API paths.

When `FRONTEND_DIST` is not configured, `LANDING_PAGE_ENABLED=true` serves a
built-in HTML landing page at `/` and `/app`, with the currently public tunnels
listed from relay state. If the flag is disabled, `/` keeps returning the small
JSON relay status response. Docker images and the default Compose file enable
the built-in landing page by default.

`LANDING_PAGE_ENABLED=true` only sets the default landing-page flag when no saved
admin setting exists. Saved `admin_settings.json` values still take precedence.
If a reused production volume already saved the flag as disabled, enable it via
the admin API/UI or edit the saved setting before restarting.

The relay install endpoints are always available:

- `/install.sh`
- `/install.ps1`
- `/install/bin/<platform>`
- `/install/bin/<platform>.sha256`

Supported platform slugs match the Go relay: `linux-amd64`, `linux-arm64`,
`darwin-amd64`, `darwin-arm64`, `windows-amd64`, and `windows-arm64`. The Rust
relay does not embed release binaries, so `/install/bin/*` redirects to the
official GitHub latest release asset.

Thumbnail generation via `HEADLESS_SHELL_URL` is not implemented yet. Setting it
currently fails fast during config normalization.

## Docker Compose

```bash
PORTAL_URL=https://relay.example.com \
API_PORT=4017 \
SNI_PORT=443 \
docker compose up --build
```

Enable discovery polling and self-announce with comma-separated bootstrap relay
API URLs:

```bash
DISCOVERY=true \
WIREGUARD_PORT=51820 \
BOOTSTRAPS=https://relay-a.example.com,https://relay-b.example.com \
docker compose up --build
```

When discovery is enabled, the Rust relay starts the experimental userspace
WireGuard overlay runtime and binds `WIREGUARD_PORT/udp`. Publish that UDP port
when the relay should participate in a mesh. The Docker Compose file includes a
commented mapping for this port.

Enable optional transports by setting a lease port range and publishing the
matching port mappings in `docker-compose.yml`.

```bash
MIN_PORT=40000
MAX_PORT=40009
UDP_ENABLED=true
TCP_ENABLED=true
```

`SNI_PORT/udp` is used for the QUIC datagram backhaul when UDP is enabled.

The container grants `portal-relay` `cap_net_bind_service` so it can run as the
non-root `portal` user while still binding container port `443`.

## Logging

The relay uses structured `tracing` logs and honors `RUST_LOG`. The Docker image
defaults to `info`; the Compose file defaults to:

```bash
RUST_LOG=portal_relay=debug,tokio_wireguard=info,info
```

For a live canary, follow logs with:

```bash
docker compose logs -f --tail=200 portal-relay
```

Useful events include runtime configuration, listener readiness, discovery
refresh stats, overlay peer add/update/remove, HopMux outbound session failures,
and next-hop timeout warnings. Access tokens, admin secrets, private keys, and
hop tokens are not logged.

## Local Verification Scripts

The repository includes Docker-based checks for hosts that do not have Rust
installed locally:

```bash
./scripts/dev-rust-ci.sh
./scripts/track0-runtime-smoke.sh
./scripts/go-client-http-smoke.sh
./scripts/v218-release-http-smoke.sh
./scripts/v218-release-tcp-smoke.sh
./scripts/v218-release-udp-smoke.sh
./scripts/v218-release-lifecycle-smoke.sh
./scripts/v218-jwt-verify-compat.sh
./scripts/v218-api-shape-compare.sh
```

`go-client-http-smoke.sh` starts the Rust relay, runs the existing Go CLI against
it, and verifies HTTPS SNI passthrough to a local HTTP upstream.

The `v218-*` scripts exercise the official v2.1.8 release binary against the
Rust relay after verifying release checksums. They cover HTTP, raw TCP, UDP,
renew/unregister lifecycle, Go-issued JWT verification, and selected
Go-vs-Rust API/discovery response shapes.

## Current Mesh/Overlay Caveat

The relay can generate/persist WireGuard identity material, validate/store
signed `/sdk/hop` route records, prepare WireGuard peer config, keep runtime
bridge metrics for discovery descriptors, and start an experimental
`tokio-wireguard` userspace overlay runtime when discovery is enabled. HopMux
framing and next-hop bridge code are wired into that runtime.

This is not yet a production-supported mesh mode. The overlay data path still
needs local relay-pair smoke coverage, peer churn testing, NAT/keepalive
validation, MTU validation, and Go v2.1.8 relay mesh interop before multi-hop is
considered compatible.
