# Portal Tunnel Existing System Analysis

This document analyzes the current Go implementation in `../portal-tunnel` from
the perspective of rewriting the relay server in Rust while keeping existing
Portal SDK and CLI clients compatible.

## Executive Summary

The relay server is the compatibility boundary. Existing clients expect a relay
that exposes the same HTTPS control plane, the same reverse-session wire markers,
the same keyless TLS signing endpoint, and the same SNI-based stream behavior.

The smallest useful Rust milestone is not feature parity with the full relay.
It is a relay that can accept an unchanged Go SDK/CLI client, register a lease,
hold `/sdk/connect` reverse sessions, route a public TLS connection by SNI, write
the `0x02` activation marker, and bridge bytes without terminating tenant TLS.

The implementation should be split into these compatibility levels:

| Level | Scope | Existing clients supported |
| --- | --- | --- |
| L1 | Health, `/sdk/domain`, API envelope | Relay compatibility probing |
| L2 | SIWE challenge, register, renew, unregister, ES256K lease JWT | Lease lifecycle |
| L3 | `/sdk/connect` HTTP/1.1 raw upgrade, keepalive marker, stream queue | Reverse sessions |
| L4 | SNI listener, one-level wildcard lookup, root-host API fallback, TLS passthrough bridge | HTTPS tunnel traffic |
| L5 | `/v1/sign` keyless signing over relay certificate key | Tenant TLS handshake |
| L6 | Dedicated raw TCP port leases | Non-TLS TCP exposure |
| L7 | UDP ingress plus QUIC DATAGRAM backhaul | UDP exposure |
| L8 | Discovery, signed relay descriptors, WireGuard overlay, multi-hop | Relay mesh |
| L9 | Admin UI/API, ACME DNS automation, thumbnails, install endpoints | Operational parity |

For a Rust rewrite, L1-L5 are the minimum required for normal `portal expose`
HTTPS traffic. L6-L9 can be added after the core contract is stable.

## Repository Layout

The current Go project is organized around a few clear ownership boundaries:

| Path | Role |
| --- | --- |
| `cmd/relay-server` | Relay binary, CLI flags, env config, frontend/admin wiring |
| `portal` | Relay runtime: API server, SNI ingress, lease registry, policy, ACME, discovery |
| `portal/transport` | Reverse stream, raw TCP port, UDP/QUIC datagram, port allocator |
| `portal/auth` | SIWE challenge verification, ES256K lease JWT, relay descriptor signatures, hop routes |
| `portal/keyless` | `/v1/sign` keyless signer and SDK-side tenant TLS helper |
| `portal/discovery` | Relay set, descriptor polling, announce policy |
| `portal/overlay` | WireGuard overlay and hop mux for multi-hop forwarding |
| `portal/policy` | Approval, ban/deny, IP filtering, BPS throttling, proxy trust |
| `sdk` | Existing client implementation that the Rust relay must remain compatible with |
| `types` | Shared public wire types, API paths, error codes, version constants, marker bytes |
| `utils` | Shared normalization, JSON API helpers, TLS/client helpers, identity/crypto helpers |

The Rust rewrite should treat `types` and `sdk` behavior as the source of truth.
Most relay-internal package shapes do not need to be preserved, but their public
effects do.

## Process and Listener Model

The Go relay starts from `cmd/relay-server/main.go`, builds a
`portal.ServerConfig`, creates `portal.NewServer`, wraps it with `Frontend`, and
runs `server.Start`.

At runtime the relay owns these network surfaces:

| Surface | Default | Protocol | Purpose |
| --- | --- | --- | --- |
| API listener | `:4017` | HTTPS HTTP/1.1 | Admin/frontend, `/sdk/*`, `/v1/sign`, discovery |
| SNI listener | `:443` | raw TCP/TLS peek | Public tenant ingress and root-host API fallback |
| QUIC backhaul | same address as SNI UDP, when enabled | QUIC + DATAGRAM | Internal UDP tunnel from relay to SDK |
| Lease TCP ports | configured `MIN_PORT..MAX_PORT`, when enabled | raw TCP | Non-TLS TCP exposure |
| WireGuard overlay | `:51820/udp`, when discovery/overlay is enabled | WireGuard | Relay-to-relay discovery and multi-hop |

Important listener invariants:

- API TLS disables HTTP/2 because `/sdk/connect` depends on HTTP/1.1 hijacking.
- Public stream ingress is TLS-only at the outer client connection, but tenant
  TLS is not terminated by the relay.
- Root-host SNI falls back to the API listener by opening a local TCP connection
  to the API server and bridging bytes.
- UDP exposure is raw UDP publicly, carried internally over QUIC DATAGRAM.

## Shared Wire Constants

The most important stable constants are in `types/types.go` and `types/paths.go`.

| Constant | Value | Meaning |
| --- | --- | --- |
| `SDKVersion` | `"6"` | Client/relay SDK protocol compatibility value |
| `DiscoveryVersion` | `"7"` | Relay discovery descriptor compatibility value |
| `HeaderAccessToken` | `X-Portal-Access-Token` | Reverse-session auth header |
| `MarkerKeepalive` | `0x00` | Idle reverse-session keepalive |
| `MarkerRawStart` | `0x01` | Activate reverse session as raw TCP |
| `MarkerTLSStart` | `0x02` | Activate reverse session as tenant TLS passthrough |

All control-plane JSON responses use:

```json
{
  "ok": true,
  "data": {}
}
```

or:

```json
{
  "ok": false,
  "error": {
    "code": "invalid_request",
    "message": "..."
  }
}
```

The Go SDK decodes all `/sdk/*` responses through this envelope. Returning raw
JSON without the envelope will be interpreted as incompatible.

## Control Plane API

The relay API handler routes fixed paths before falling through to frontend or
admin handlers.

| Path | Method | Contract |
| --- | --- | --- |
| `/healthz` | GET | Envelope data `{ "status": "ok" }` |
| `/sdk/domain` | GET | Envelope `DomainResponse`; CORS `*`; `protocol_version` must equal `SDKVersion` |
| `/sdk/register/challenge` | POST | Creates SIWE challenge from desired lease request |
| `/sdk/register` | POST | Verifies SIWE response, creates lease, returns access token and routing info |
| `/sdk/renew` | POST | Verifies access token, extends TTL, returns refreshed token |
| `/sdk/unregister` | POST | Verifies access token, removes lease and active sessions |
| `/sdk/connect` | GET | HTTP/1.1 only; validates token; hijacks to raw reverse session |
| `/sdk/hop` | POST/DELETE | Multi-hop route sync, requires overlay support |
| `/discovery` | GET | Signed relay descriptor set, only when discovery enabled |
| `/discovery/announce` | POST | Accepts signed relay descriptor, only when discovery enabled |
| `/v1/sign` | POST | Keyless TLS digest signing endpoint |

Method mismatches return envelope error `method_not_allowed`. Invalid JSON uses
`invalid_json`. Most API body size limits are small and explicit:

- Control-plane JSON: `4 MiB`
- Admin JSON: `64 KiB`
- Keyless sign JSON: `4 KiB`
- QUIC backhaul control JSON: `4 KiB`

## Identity, Registration, and Lease Tokens

### Identity

A tenant identity is:

```json
{
  "name": "demo",
  "address": "0x..."
}
```

`Identity.Key()` is:

```text
lowercase(name) + ":" + lowercase(address)
```

The relay normalizes:

- `name` as a single DNS label.
- `address` as an EVM address.
- Lease hostname as `<normalized-name>.<portal-root-host>`.

For example, `Demo-App` under `portal.example.com` becomes
`demo-app.portal.example.com`.

### Register Challenge

`POST /sdk/register/challenge` accepts `RegisterChallengeRequest`:

```json
{
  "identity": { "name": "demo", "address": "0x..." },
  "metadata": {},
  "ttl": 30,
  "udp_enabled": false,
  "tcp_enabled": false,
  "hop_token": ""
}
```

The relay creates a SIWE message with:

- Statement: `Register a portal lease`
- Chain ID: `1`
- URI: request scheme/host plus `/sdk/register`
- Nonce: SIWE-generated nonce
- Request ID: generated `rch_...`
- Expiration: default challenge TTL, 2 minutes

Pending challenges are stored in the same lease registry as temporary
`leaseRecord` entries. The relay limits pending challenges per source IP to 32.

### Register

`POST /sdk/register` accepts:

```json
{
  "challenge_id": "rch_...",
  "siwe_message": "...",
  "siwe_signature": "0x...",
  "reported_ip": "..."
}
```

The relay:

1. Finds and consumes the matching challenge.
2. Verifies the SIWE signature against the challenge domain, nonce, and current time.
3. Creates or replaces the lease for the same identity key.
4. Rejects hostname conflicts from different identity keys.
5. Issues an ES256K JWT access token.
6. Starts optional UDP/TCP lease runtimes.

Default lease TTL is 30 seconds unless the request provides `ttl`.

### Lease Access Token

The access token is a JWT signed with secp256k1:

- JWS algorithm: `ES256K`
- Type: `JWT`
- Issuer: normalized relay `PORTAL_URL`
- Audience: `portal-sdk`
- Subject: `Identity.Key()`
- Claims include normalized `identity`
- `iat`, `nbf`, `exp` are set from the requested TTL
- JWS `kid` is the relay identity address

The Go implementation uses `go-jose` with a custom opaque signer/verifier that
signs the JWS payload using secp256k1 over SHA-256 and stores a raw 64-byte
signature. A Rust implementation must reproduce this exactly enough for Go SDK
tokens to verify against the relay public key and for the Rust relay to verify
its own issued tokens.

## Lease Registry

The lease registry is the central state owner. It holds:

- Active public leases.
- Pending register challenges.
- Multi-hop route entries.
- Reverse stream queues.
- Optional UDP and TCP per-lease runtimes.
- Policy state for approval, ban, IP filtering, and BPS limits.

Important defaults:

| Setting | Value |
| --- | --- |
| Lease TTL | `30s` |
| Register challenge TTL | `2m` |
| Pending challenges per IP | `32` |
| Reverse ready queue limit | `8` |
| Idle reverse keepalive interval | `15s` |
| Claim timeout | `10s` |
| Port reservation grace | `5m` |
| Registry janitor interval | `5s` |

Lease cleanup closes ready reverse sessions, UDP runtimes, TCP listeners, and
releases reserved ports.

The port allocator has sticky reservation behavior: when a lease releases a port,
that port is reserved for the same lease name for 5 minutes before returning to
the general pool.

## Reverse Session Protocol

`/sdk/connect` is the core relay-client stream protocol.

Client behavior:

1. SDK opens a TLS connection to the relay API host.
2. SDK writes an HTTP/1.1 `GET /sdk/connect` request.
3. SDK sends `X-Portal-Access-Token`.
4. Relay returns:

```http
HTTP/1.1 200 OK
Content-Length: 0
Connection: keep-alive

```

5. After the blank line, the same TCP/TLS connection becomes a raw reverse
   session.
6. While idle, relay writes `0x00` keepalive bytes every 15 seconds.
7. When public traffic claims the session, relay stops keepalives and writes:
   - `0x02` for TLS passthrough.
   - `0x01` for raw TCP port forwarding.
8. Relay and SDK then bridge application bytes.

If `/sdk/connect` is attempted over HTTP/2 or another major version, the relay
returns status `505` with error code `http11_only`.

The ready queue is per lease. If more than 8 reverse sessions are offered, the
new session is closed and not queued.

## Public Stream Ingress

The SNI listener accepts raw TCP connections and peeks the TLS ClientHello. It
does not terminate tenant TLS for lease traffic.

Routing order:

1. Exact hostname match.
2. Single-label wildcard match.
3. Exact root host fallback to API listener.
4. Otherwise close the connection.

Wildcard behavior is one label deep only. `*.example.com` matches
`app.example.com`, not `deep.app.example.com`. The root host is never matched by
the wildcard route.

For a normal lease:

1. Public client connects to the SNI listener.
2. Relay peeks ClientHello SNI.
3. Relay looks up the lease record.
4. Relay checks policy: not banned, not denied, approved if manual mode.
5. Relay waits up to 10 seconds for a ready reverse session.
6. Relay writes `0x02` to the claimed reverse session.
7. Relay bridges public connection and reverse session bidirectionally.

The bridge uses half-close when supported, counts active connections, and counts
TCP bytes for discovery/admin telemetry.

## Keyless TLS

Portal's trust model depends on tenant TLS terminating at the SDK side, not the
relay side. The SDK still needs certificate signatures for relay-hosted domains,
so the relay exposes a keyless signing endpoint at `/v1/sign`.

Keyless request:

```json
{
  "key_id": "relay-cert",
  "algorithm": "ECDSA_SHA256",
  "digest": "base64 bytes in JSON",
  "timestamp_unix": 1710000000,
  "nonce": "..."
}
```

Keyless response:

```json
{
  "key_id": "relay-cert",
  "algorithm": "ECDSA_SHA256",
  "signature": "base64 bytes in JSON"
}
```

Error response:

```json
{
  "error": "message"
}
```

This endpoint intentionally does not use `APIEnvelope`; it follows the
`github.com/gosuda/keyless_tls/relay/signrpc` JSON shape.

Important details:

- Key ID is `relay-cert`.
- Allowed timestamp skew is 30 seconds.
- Content type, when present, must start with `application/json`.
- Supported algorithms include ECDSA SHA-256/384/512 and RSA PKCS#1/PSS variants.
- Current relay certificate/private key material is also used for API TLS.
- SDK fetches the relay certificate chain from the relay endpoint and verifies
  that it covers the tenant hostname before using the remote signer.

The first Rust-compatible implementation can support only the algorithm emitted
by the current SDK for the relay certificate type, but the endpoint shape must be
kept exact.

## Raw TCP Port Transport

Raw TCP port support is optional and enabled only when:

- Server config has `TCP_ENABLED=true`.
- `MIN_PORT` and `MAX_PORT` are valid.
- Runtime admin policy enables TCP port leases.
- Capacity limits allow the lease.

Registration with `tcp_enabled=true` allocates a dedicated TCP port and returns:

```json
{
  "tcp_enabled": true,
  "tcp_addr": "root-host:port"
}
```

The relay starts one TCP listener per TCP-enabled lease. When an external TCP
client connects:

1. Relay claims a reverse session from the same lease.
2. Relay writes `0x01`.
3. Relay bridges raw bytes.

No tenant TLS handshake is performed for this path.

## UDP and QUIC Datagram Transport

UDP support is optional and enabled only when:

- Server config has `UDP_ENABLED=true`.
- `MIN_PORT` and `MAX_PORT` are valid.
- Runtime admin policy enables UDP leases.
- Capacity limits allow the lease.
- QUIC backhaul listener successfully starts.

Registration with `udp_enabled=true` allocates a UDP port and returns:

```json
{
  "udp_enabled": true,
  "udp_addr": "root-host:port",
  "sni_port": 443
}
```

The SDK dials QUIC to the relay host on `sni_port` with:

- ALPN: `portal-tunnel`
- TLS 1.3 minimum
- QUIC DATAGRAM enabled
- Keepalive period: 15 seconds
- Max idle timeout: 60 seconds

The first QUIC stream is a JSON control message:

```json
{
  "access_token": "..."
}
```

Accepted response:

```json
{
  "ok": true
}
```

Rejected response:

```json
{
  "ok": false,
  "error": "unauthorized"
}
```

QUIC DATAGRAM frames are encoded as:

```text
[flow_id uvarint][payload bytes]
```

The relay creates flow IDs for public UDP client addresses. A flow expires after
30 seconds idle. Public UDP packets larger than the default 1350-byte buffer are
not supported by the current relay path.

## Discovery and Multi-Hop

Discovery and multi-hop are not required for the first Rust milestone, but they
are part of full relay compatibility.

Discovery:

- `/discovery` returns `DiscoveryResponse` with `protocol_version = "7"`,
  `generated_at`, and a list of signed relay descriptors.
- `/discovery/announce` accepts only signed relay descriptors.
- Relay descriptors are normalized and signed over deterministic canonical JSON.
- Descriptor signature is recoverable secp256k1 over SHA-256, base64 encoded.
- The recovered signing address must match descriptor `address`.
- Local/loopback self-announces are rejected.
- Relay set capacity is capped at 1024 announced relays.

Multi-hop:

- SDK builds signed hop routes and syncs them through `/sdk/hop`.
- Hop route signatures are secp256k1 DER signatures over canonical route bytes.
- The first hop matches public hostname; middle hops match hop tokens.
- WireGuard overlay plus `HopMux` carries relay-to-relay streams.
- If a record has a next hop, ingress opens an overlay stream instead of
  claiming a local SDK reverse session.

For Rust, this should be a separate phase after direct relay behavior is stable.

## Admin, Frontend, and Policy

The admin/frontend layer is mounted behind the same API listener and is mostly
operational rather than core protocol.

Admin paths include:

- `/admin`
- `/admin/login`
- `/admin/logout`
- `/admin/auth/status`
- `/admin/snapshot`
- `/admin/settings/approval-mode`
- `/admin/settings/landing-page`
- `/admin/settings/udp`
- `/admin/settings/tcp-port`
- `/admin/leases/...`
- `/admin/ips/...`

Admin auth:

- Secret key is stored in relay identity state.
- Login creates a random session token.
- Cookie name is `portal_admin`.
- Session TTL is 24 hours.
- Cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, path `/admin`.

Policy effects:

- Approval mode is `auto` by default.
- Manual mode requires explicit approval before routing.
- Identities can be banned or denied.
- IPs can be banned.
- Per-identity BPS throttling can limit bridge copy chunks.
- UDP/TCP port features can be disabled or capped at runtime.

Full Rust parity will eventually need these APIs because existing frontend code
expects them, but the tunnel data path does not.

## TLS, Certificates, and Persistent State

Relay state lives under `IDENTITY_PATH`, treated as a directory for the relay:

- `identity.json`
- `admin_settings.json`
- `fullchain.pem`
- `privatekey.pem`

Identity resolution:

- If relay identity does not exist, it is generated.
- Relay identity name is the normalized portal root host.
- Relay identity includes secp256k1 private/public key, EVM address, admin
  secret, and optional WireGuard keys.

TLS material:

- Localhost uses development/local ACME path.
- Non-localhost can use manual `fullchain.pem` and `privatekey.pem`.
- Managed ACME supports Cloudflare, Google Cloud DNS, and Route53.
- API TLS and QUIC backhaul require the relay certificate/private key.
- HTTP/2 is disabled on API TLS by setting only `http/1.1` next protocols.

For early Rust work, manual cert loading plus generated local development
material is enough. Managed ACME can be deferred.

## Configuration Surface

The relay binary accepts flags and equivalent environment variables:

| Flag | Env | Default | Meaning |
| --- | --- | --- | --- |
| `--portal-url` | `PORTAL_URL` | `https://localhost:4017` | Public relay URL |
| `--identity-path` | `IDENTITY_PATH` | `./.portal-certs` | Relay state directory |
| `--bootstraps` | `BOOTSTRAPS` | empty | Discovery bootstrap relays |
| `--discovery` | `DISCOVERY` | `false` in binary, `true` in compose | Enable discovery |
| `--wireguard-port` | `WIREGUARD_PORT` | `51820` | Overlay UDP port |
| `--api-port` | `API_PORT` | `4017` | API HTTPS port |
| `--sni-port` | `SNI_PORT` | `443` | Public SNI TCP port |
| `--trust-proxy-headers` | `TRUST_PROXY_HEADERS` | `false` | Honor forwarded IP headers |
| `--trusted-proxy-cidrs` | `TRUSTED_PROXY_CIDRS` | empty | Forwarded-header trusted proxies |
| `--udp-enabled` | `UDP_ENABLED` | `false` | Enable UDP lease transport |
| `--tcp-enabled` | `TCP_ENABLED` | `false` | Enable raw TCP port leases |
| `--min-port` | `MIN_PORT` | `0` | Lease port range start |
| `--max-port` | `MAX_PORT` | `0` | Lease port range end |
| `--landing-page-enabled` | `LANDING_PAGE_ENABLED` | `false` | Default landing page visibility |
| `--headless-shell-url` | `HEADLESS_SHELL_URL` | empty | Thumbnail generation |
| `--acme-dns-provider` | `ACME_DNS_PROVIDER` | empty | Managed DNS provider |
| `--ens-gasless-enabled` | `ENS_GASLESS_ENABLED` | `false` | ENS DNSSEC/TXT automation |

Rust should preserve the externally documented flags/env vars even if some
advanced values are initially parsed but unsupported.

## Compatibility Hazards

These areas are likely to cause subtle incompatibilities:

1. **ES256K JWT shape**
   The Go relay uses `go-jose` with a custom raw secp256k1 signer. Rust must
   match JWS signing input, header fields, raw signature format, and claim
   validation expectations.

2. **SIWE verification**
   Domain, URI, nonce, issued/expiry times, and Ethereum personal-sign semantics
   must match what the Go SDK signs.

3. **HTTP/1.1 reverse-session transition**
   `/sdk/connect` must write exactly a valid HTTP/1.1 success response and then
   leave the underlying stream open for marker bytes. Framework abstractions can
   make this harder than direct hyper connection handling.

4. **TLS ClientHello peek**
   The SNI listener must read enough ClientHello bytes to inspect SNI while still
   replaying those bytes to the bridged tenant TLS session.

5. **Keyless TLS endpoint**
   `/v1/sign` is not API-enveloped. It uses a separate JSON shape with base64
   byte slices. Accidentally wrapping it will break tenant TLS.

6. **API TLS ALPN**
   Existing SDK expects HTTP/1.1 semantics for reverse connect. Enabling HTTP/2
   by default can break compatibility.

7. **Hostname normalization**
   Lease names, root host extraction, wildcard behavior, and SNI normalization
   must match exactly enough that the same registered name routes to the same
   public hostname.

8. **Short TTLs**
   Default lease TTL is only 30 seconds. Renewal behavior and janitor timing
   must be correct or clients will churn.

9. **Proxy trust**
   Admin policy and challenge limits use extracted client IP. Rust must keep the
   default conservative behavior and only trust forwarded headers from configured
   proxy ranges.

## Recommended Rust Module Shape

The Rust codebase does not need to mirror Go package names exactly. A practical
shape would be:

```text
portal-tunnel-rs/
  crates/
    portal-relay/
      src/
        main.rs
        config.rs
        api/
          mod.rs
          envelope.rs
          sdk.rs
          keyless.rs
        auth/
          identity.rs
          siwe.rs
          lease_token.rs
        relay/
          server.rs
          leases.rs
          stream.rs
          sni.rs
          bridge.rs
        transport/
          tcp_port.rs
          datagram.rs
          quic.rs
        policy/
          mod.rs
        state/
          identity.rs
          tls_material.rs
```

Keep stable wire structs close to the API layer and write serialization tests
against captured Go JSON fixtures. Avoid starting with discovery, admin UI, or
ACME because they add volume without proving the core compatibility contract.

## Verification Strategy

The rewrite should be driven by compatibility tests rather than unit tests alone.

Recommended test layers:

1. **Golden JSON tests**
   Compare Rust serialization/deserialization for `APIEnvelope`, register
   request/response, renew, unregister, discovery, datagram frames, and keyless
   sign requests.

2. **Crypto interoperability tests**
   Generate identities and tokens in Go, verify in Rust; generate in Rust, verify
   in Go. Do the same for SIWE challenge messages and relay descriptors.

3. **Reverse-session integration test**
   Use the existing Go SDK against Rust relay:
   - Register lease.
   - Open `/sdk/connect`.
   - Connect public TLS client to SNI listener.
   - Assert Rust writes `0x02` and bridges bytes.

4. **End-to-end CLI test**
   Run existing `portal expose` against Rust relay and make an HTTPS request to
   the public lease hostname.

5. **Optional transport tests**
   Add raw TCP port and UDP QUIC DATAGRAM tests after HTTPS tunnel behavior is
   stable.

## Porting Roadmap

### Phase 0: Contract Fixtures

- Extract representative Go JSON fixtures.
- Add crypto fixtures for identities, SIWE messages, JWTs, and keyless sign
  requests.
- Document expected status codes and error codes for each `/sdk/*` path.

### Phase 1: Minimal API Server

- Implement config parsing.
- Load or create relay identity.
- Load manual/local TLS material.
- Serve HTTPS HTTP/1.1 only.
- Implement API envelope helpers.
- Implement `/healthz` and `/sdk/domain`.

### Phase 2: Lease Lifecycle

- Implement identity normalization.
- Implement SIWE challenge creation and verification.
- Implement lease registry.
- Implement ES256K JWT issuance and validation.
- Implement register, renew, unregister.

### Phase 3: Reverse Stream and SNI

- Implement `/sdk/connect` raw stream handling.
- Implement ready queue, keepalive, claim with marker.
- Implement SNI ClientHello peek with byte replay.
- Implement root-host API fallback.
- Implement bridge with half-close.

### Phase 4: Keyless TLS

- Implement `/v1/sign`.
- Verify Go SDK tenant TLS can complete using Rust relay signatures.
- Add algorithm coverage as needed by loaded certificate key type.

### Phase 5: Optional Direct Transports

- Implement raw TCP port leasing.
- Implement UDP lease ports.
- Implement QUIC backhaul and DATAGRAM framing.

### Phase 6: Operational Parity

- Implement admin policy APIs.
- Implement discovery and relay descriptors.
- Implement WireGuard overlay and multi-hop.
- Implement managed ACME and frontend serving.

## Open Questions

- Should Rust initially reuse the Go relay `identity.json` format byte-for-byte,
  or migrate with a compatibility reader? Reuse is preferable for drop-in
  replacement.
- Which Rust HTTP stack should own `/sdk/connect`? The framework must expose the
  underlying upgraded stream reliably for HTTP/1.1.
- Which SIWE and secp256k1 crates best match Go behavior for personal-sign,
  recoverable signatures, and DER/raw signature formats?
- Should the first Rust relay target only manual/local certificates, with ACME
  delegated to deployment tooling until core compatibility is proven?
- Should admin/frontend be implemented in Rust or served by a compatibility shim
  after the protocol relay is complete?

## Source Map

Primary files reviewed:

- `../portal-tunnel/docs/src/routes/architecture/+page.md`
- `../portal-tunnel/cmd/relay-server/main.go`
- `../portal-tunnel/cmd/relay-server/admin.go`
- `../portal-tunnel/cmd/relay-server/frontend.go`
- `../portal-tunnel/portal/server.go`
- `../portal-tunnel/portal/api_server.go`
- `../portal-tunnel/portal/lease.go`
- `../portal-tunnel/portal/proxy.go`
- `../portal-tunnel/portal/auth/register_challenge.go`
- `../portal-tunnel/portal/auth/lease_token.go`
- `../portal-tunnel/portal/auth/relay_descriptor.go`
- `../portal-tunnel/portal/auth/hop_route.go`
- `../portal-tunnel/portal/keyless/signer.go`
- `../portal-tunnel/portal/keyless/client.go`
- `../portal-tunnel/portal/transport/stream_relay.go`
- `../portal-tunnel/portal/transport/stream_client.go`
- `../portal-tunnel/portal/transport/tcp_port_relay.go`
- `../portal-tunnel/portal/transport/datagram_relay.go`
- `../portal-tunnel/portal/transport/datagram_session.go`
- `../portal-tunnel/portal/transport/quic_backhaul.go`
- `../portal-tunnel/types/api.go`
- `../portal-tunnel/types/types.go`
- `../portal-tunnel/types/paths.go`
- `../portal-tunnel/types/error.go`
- `../portal-tunnel/utils/api.go`
- `../portal-tunnel/utils/identity.go`
