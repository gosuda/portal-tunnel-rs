# Portal greenfield wire protocol

<!-- Last verified against crates/portal-wire commit: 9baefdcca30191645b6e89ba941c1dfa436024bf -->

**Status:** active (ADR-0001).

This document is the normative specification for the Rust reference implementation. Go `gosuda/portal-tunnel` v2.1.8 is a behavioral reference only; bytes on the wire are **not** compatible with Go marker-byte framing or ES256K JWT envelopes.

---

## ALPN and versioning

- **QUIC ALPN:** `portal/2` (bytes `b"portal/2"`). The `2` is the **protocol generation**, not the HTTP API path revision.
- **HTTP API:** All endpoints are under `/v1/` except `/healthz` and `/metrics` (unversioned observability).

---

## Framing: QUIC streams

Every multiplexed logical connection uses a **server-initiated** bidirectional QUIC stream. The first bytes on the stream are:

1. **Channel tag** — `u8` (see table below).
2. **Length** — `u32` big-endian payload length in bytes (does not include the tag or length fields).
3. **Payload** — opaque bytes interpreted per channel, capped by **SEC-014** limits.

### Channel tags

| Value | Name        | Meaning |
|------:|-------------|---------|
| `0x00` | *(illegal)* | **Reserved.** Peers MUST NOT send. Decoders return `LegacyKeepaliveByte` (Go drift detector vs `MarkerKeepalive`). |
| `0x01` | `Control`   | Control-plane messages; first frame may carry `RoutedHostname` (R13). |
| `0x02` | `TcpProxy`  | TCP port relay payload sub-framing (raw vs TLS — discriminant in payload). |
| `0x03` | `UdpDatagram` | UDP flow payload (`DatagramFrame`). |
| `0x04` | `HopRoute`  | Multi-hop overlay reservation (Phase 6b); v0.1 may parse-only. |

Unknown `u8` values: decode error `UnknownChannelTag`.

---

## SEC-014 size budgets (postcard / frame)

Hard caps for decoders (amplification defense):

| Surface | Max bytes |
|---------|----------:|
| `Control` payload | 8 KiB (`8192`) |
| `HopRoute` payload | 4 KiB (`4096`) |
| `UdpDatagram` payload | 64 KiB (`65536`) |
| `TcpProxy` frame | 16 KiB (`16384`) |
| `ReputationDelta` postcard | 1 KiB (`1024`) |
| `LeaseToken` postcard | 512 |
| `RelayDescriptor` canonical encoding | 4 KiB (`4096`) |

---

## Domain separators (SEC-007)

Signing inputs for postcard-canonical blobs and envelopes are prefixed with exactly one of:

1. `b"portal-tunnel/relay-descriptor/v1"`
2. `b"portal-tunnel/hop-route/v1"`
3. `b"portal-tunnel/lease-token/v1"`
4. `b"portal-tunnel/keyless-request/v1"`
5. `b"portal-tunnel/reputation-delta/v1"`
6. `b"portal-tunnel/binding-attestation/v1"`

Cross-protocol confusion MUST be rejected by domain-separated signing in `portal-crypto` (Phase 2).

---

## Envelope and claims (SEC-001)

**`Envelope` (postcard):**

```rust
// Conceptual shape — see `portal_wire::envelope`
struct Envelope {
    payload: Bytes,          // opaque to wire layer
    sig: [u8; 64],           // ed25519 over signing_input
    claims: Claims,
}
```

**Signing input** (passed to Phase 2 signer):

`postcard::serialize( (domain_separator, payload, claims) )` — exact tuple order is normative; see `Envelope::signing_input`.

**`Claims`:**

- `nonce: [u8; 16]` — replay window identifier.
- `not_before`, `not_after` — validity window (`jiff::Timestamp`, serde-compatible for tooling).
- `audience` — sealed enum: which trust surface receives this (`RelayApiAdmin`, `RelayApiSdk`, `RelayApiDiscovery`, `Keyless`, `HopForward`, `QuicBackhaul`).
- `purpose` — sealed enum: operation binding (`Register`, `Renew`, `Unregister`, `HopAttest`, `KeylessSign`, `DiscoveryAnnounce`, `LeaseAccess`).

Wrong audience or purpose for a handler: verification fails closed.

---

## HTTP response wrapper

JSON bodies use:

- Success: `{ "data": <T> }`
- Failure: `{ "error": { "code": string, "message": string } }`

RFC 7807 Problem Details are intentionally **not** used (OpenAPI / handler ergonomics).

---

## Path and header constants

- **Signed envelope header:** `X-Portal-Envelope` (replaces Go `X-Portal-Access-Token` naming in admin/SDK paths that carried JWT).

Versioned paths (non-exhaustive; OpenAPI is canonical in Phase 5):

- `/healthz`, `/metrics`
- `/v1/sdk/*`, `/v1/admin/*`, `/discovery`, …

---

## `RelayDescriptor` (R12)

- **Identity:** 32-byte ed25519 public key (raw).
- **Addresses:** `addresses_v4: Vec<SocketAddrV4>` and `addresses_v6: Vec<SocketAddrV6>` — separate lists; no mixed `SocketAddr` vec at the wire layer.
- **Canonical bytes:** postcard-tagged struct prefixed with relay-descriptor domain separator for signing; max 4 KiB.

---

## `LeaseToken` (SEC-003)

Postcard struct MUST include **`relay_pubkey`** (32 bytes) so a token minted by relay A cannot be replayed at relay B. Verifier checks pubkey equality before policy.

---

## `RoutedHostname` and SEC-015 (ECH-aware routing)

- **Carriage:** first `Control` frame payload on a QUIC stream includes optional `RoutedHostname` (compact string) when the client is ECH-aware.
- **Policy:** tenant TLS routing compares `routed_hostname` to presented cert identity; mismatch fails closed before keyless signing (full tree in Phase 5 / Phase 6b plans).

---

## MITM probe label (SEC-013)

TLS exporter / EKM label bytes (exact):

`b"portal-tunnel/mitm-probe/v2"`

Constant name in code: `MITM_PROBE_LABEL`. Version `v2` tracks protocol generation with ALPN `portal/2`.

---

## `ReputationDelta` (R10 v0.2 reservation)

Wire type includes `identity_pubkey`, `score_delta`, `decay_window`, `reason_code: u16`, `signed_by_relay_pubkey`. **v0.1:** type + codec + limit exist; **no emission** on the wire — CI grep gate forbids v0.1 callers in `portal-relay`, `portal-net`, `portal-sdk`.

---

## SIWE attestation field (SEC-002)

`RegisterRequest` JSON includes reserved `siwe_attestation` / binding fields per OpenAPI; parsing and `SIWE → ed25519` binding verification live in `portal-crypto`.

---

## `DatagramFrame`

`flow_id: u32` (fixed width for v1; varint reserved for future), `payload: Bytes`, capped at **UDP_DATAGRAM_MAX**.

---

## Codec split

- **Inner binary:** `postcard` for `Envelope`, tokens, descriptors, hop routes, reputation delta.
- **Outer HTTP JSON:** `serde_json` for API DTOs in `portal_wire::api` (utoipa-friendly).

---

## Drift gate

CI SHALL fail if this file’s “Last verified” commit SHA does not match `git log -1 --format=%H -- crates/portal-wire` on mainline branches.
