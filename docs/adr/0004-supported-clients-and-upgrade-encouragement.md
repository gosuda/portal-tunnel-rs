# ADR-0004: Supported clients and upgrade-encouragement matrix

- Status: accepted
- Date: 2026-05-04
- Deciders: portal-tunnel-rs maintainers
- Related: ADR-0001 (greenfield wire), ADR-0003 (registry-fork posture); R13
  (modern transport security baseline) in the roadmap plan

## Context and problem statement

ADR-0001 commits to a greenfield wire and modern transport security defaults
(R13: TLS 1.3 + AEAD-only + Ed25519/ECDSA-P256/RSA, optional X25519+ML-KEM-768
hybrid PQ KEX, ECH-aware tenant TLS routing). Naive interpretation of "modern
defaults" is **legacy-deprecate**: refuse TLS 1.2, refuse RSA, refuse plaintext
SNI, refuse IPv4-only listeners. That posture breaks every public-internet
client whose stack lags the modern register — corporate proxies on TLS 1.2,
embedded clients without ML-KEM, IPv4-only home networks, ECH-unaware ALPN
negotiation.

The opposite mistake — "permanent backward compat" — locks the project into
the weakest client's capability budget forever. Neither extreme is workable.

The Rust port adopts an **upgrade-encouragement** posture that names every
supported-but-disfavored capability, the upgrade signal we emit per surface,
and the v1.0 sunset criterion that retires the capability. Pattern follows
[OpenLEADR](https://github.com/OpenLEADR/openleadr-rs)'s
compatibility-statement model and Mozilla's ADR template.

## Decision

The matrix below is the v0.1 contract. Each row names a capability, the
preserved-with-encouragement form, the upgrade signaling mechanism per surface,
and the sunset criterion. Sunset triggers a v1.0+ ADR amendment that removes
the capability; until then, the capability is supported.

| Capability | Preserved form | Upgrade signal | Sunset criterion |
|---|---|---|---|
| **TLS 1.2** on relay HTTPS | accepted; ChaCha20-Poly1305 / AES-GCM only (RFC 7905, RFC 5288) | `tracing` event `tls.handshake.version_downgrade` per connection; HSTS preload header on the response; ALPN `h2` ordered before `http/1.1` | TLS 1.2 acceptance removed when `tls.handshake.version_downgrade` rate < 0.5% across the relay fleet for 30 days; RFC 8996 §3 confirms TLS 1.2 acceptance does not enable known TLS-version-rollback attacks against TLS 1.3-capable peers as long as our cipher allowlist excludes CBC + RC4 + 3DES (which it does) |
| **RSA signatures** on tenant cert | accepted (RSA-PSS only, ≥2048 bits); ECDSA-P256 and Ed25519 preferred via TLS signature_algorithms ordering | `tracing` event `tls.handshake.signature_alg=rsa` per connection; ACME issuance defaults to ECDSA-P256 — operator chooses to ack RSA explicitly | RSA acceptance removed when `tls.handshake.signature_alg=rsa` rate < 1% across the tenant fleet for 30 days |
| **X25519 alone (no ML-KEM hybrid)** on QUIC + relay HTTPS | accepted; rustls 0.23.22 `prefer-post-quantum` orders X25519+ML-KEM-768 first when both peers offer it | `tracing` event `tls.handshake.kex=x25519` per connection; client documentation says "ML-KEM hybrid is the default; X25519-alone is for legacy clients" | X25519-alone acceptance removed when client-side ML-KEM-768 adoption crosses ~50% (project: 2028+); aligned with Cloudflare and Google rollout telemetry |
| **ECH disabled (plaintext SNI fallback)** on tenant TLS | accepted; relay reads `routed_hostname` from greenfield wire if present, else falls back to ClientHello SNI | client documentation says "ECH-aware mode is the default; SNI fallback is for ECH-unaware clients"; `tracing` event `tls.routing.sni_fallback=true` per connection | SNI fallback removed when ECH crosses ~50% client-side adoption (project: 2028+); tracked against Cloudflare/Mozilla telemetry |
| **IPv4-only listeners** on every public listener | rejected by default (R12 dual-stack mandatory); v4-only requires explicit `dual_stack: false` config flag with operator acknowledgment | startup log line `WARN listener.dual_stack=false; v6 clients will not reach this relay`; admin dashboard surfaces the flag prominently | v4-only operator opt-in remains a supported config indefinitely; no sunset (operator constraint, not protocol constraint) |
| **Server-side ECH on relay HTTPS API surface** | NOT supported in v0.1 (rustls server-side ECH not yet released; tracked in [rustls/rustls#1980](https://github.com/rustls/rustls/issues/1980), PR #2993 in flight as of March 2026); relay uses ECH GREASE only | none required (capability simply not advertised) | "supported in v0.2" once rustls server-side ECH lands; promotion to mandatory once tenant-side adoption justifies it |

### Cryptographic-class assertion (TLS 1.2 acceptance)

TLS 1.2 acceptance under the cipher allowlist above does **NOT** enable known
TLS-version-rollback attacks against TLS 1.3-capable peers. Reasoning:

- RFC 8996 §3 documents that TLS 1.0/1.1 are deprecated due to weak cipher
  suites and downgrade vulnerabilities (FREAK, POODLE, BEAST). Our TLS 1.2
  configuration excludes CBC, RC4, 3DES, and export ciphers — i.e., the
  cipher classes those attacks exploited.
- TLS 1.3 includes a `downgrade_protection` mechanism (RFC 8446 §4.1.3) that
  signals downgrade attempts to TLS 1.2-capable peers via the last 8 bytes of
  `ServerHello.Random`. rustls 0.23 implements this. A TLS 1.3-capable
  client offered TLS 1.2 by a downgrading proxy will detect the downgrade and
  fail closed.
- Therefore, TLS 1.2 acceptance is bounded to peers that genuinely lack TLS
  1.3 — typically corporate proxies and embedded clients — and does not
  expose TLS 1.3-capable peers to a downgrade primitive.

The same reasoning is recorded in v0.1 release notes alongside the upgrade
matrix.

## Consequences

### Positive

- The public-internet client base does not break on the Rust port's launch.
- Every disfavored capability has a named upgrade signal and a sunset
  criterion. No capability is silently permanent.
- The v0.1 → v1.0 transition has a documented capability-removal pipeline
  driven by client-side telemetry, not by maintainer fiat.
- Cryptographic-class reasoning is in writing (TLS 1.2 §3 of this ADR), so
  future security reviews can verify the bound holds.

### Negative — accepted

- We carry the operational cost of supporting a wider capability range than
  a pure greenfield posture would require.
- Telemetry-driven sunset is dependent on operators emitting the `tracing`
  events upward. v0.2 may need to add an opt-in metrics export of the
  downgrade events to make the sunset criterion observable at the project
  level.

## Considered alternatives

### A. Legacy-deprecate — refuse everything below the modern baseline

Rejected as user-hostile per §`Context and problem statement`.

### B. Permanent backward compat — never sunset

Rejected. Locks the project into the weakest client's capability budget
forever. Defeats the "modern reference implementation" claim.

### C. Upgrade-encouragement matrix — selected

Per the table above. The pattern is well-established in the Rust ecosystem
([OpenLEADR](https://github.com/OpenLEADR/openleadr-rs) for energy-grid
protocol compat statements; Mozilla's MADR template for capability lifecycle
ADRs).

## References

- ADR-0001 (greenfield wire) — sets the baseline this ADR softens for the
  public-internet client base
- ADR-0003 (registry-fork) — handles the Go v2.1.8 deployment side; this
  ADR handles the public-internet client side
- Roadmap plan: §R13 (modern transport security baseline), §`Resolved During
  Planning` → "ECH scope?"
- Pattern source: [OpenLEADR/openleadr-rs](https://github.com/OpenLEADR/openleadr-rs)
  README "Compatibility" section
- TLS 1.2 cryptographic-class reasoning: RFC 8996 §3, RFC 8446 §4.1.3
