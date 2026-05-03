# ADR-0001: Greenfield wire — drop Go v2.1.8 byte-compat

- Status: accepted
- Date: 2026-05-04
- Deciders: portal-tunnel-rs maintainers
- Supersedes: the wire-compat pin in the previous `AGENTS.md` (commit `2ae93be`)
- Related: ADR-0002 (register that selects greenfield-friendly crates), ADR-0003
  (registry-fork posture for the v2.1.8 user base), ADR-0004 (upgrade-encouragement
  matrix that bounds what greenfield removes for the public-internet client base)

## Context and problem statement

The previous `AGENTS.md` pinned `gosuda/portal-tunnel` Go tag `v2.1.8` as the
single source of truth for the relay-server wire and API. Every Rust commit was
constrained to interoperate byte-for-byte with `quic-go`, `hashicorp/yamux`,
`decred/secp256k1` ES256K JWTs, and `gosuda/keyless_tls`. Each constraint costs
something concrete in the Rust port:

- **`quic-go` framing parity** forces us to mirror its specific stream multiplexing
  conventions instead of adopting `quinn`'s native typed stream-id register.
- **`yamux` retention** keeps a TCP-fallback multiplexer alive purely for byte
  compat — `quinn` already streams natively and the fallback is unused on the
  primary path.
- **ES256K JWT** forces a hand-rolled `decred/secp256k1` JOSE verifier on top of
  the protocol's actual identity, and pulls a JWS dependency that does not exist
  natively in the modern Rust ecosystem.
- **`keyless_tls` line-protocol** locks the keyless oracle to a wire shape that
  is older than `rustls::sign::SigningKey` and predates async-bridged signing.

The user has explicitly elected to drop the wire pin. Go is reference behavior
only (R3); no Rust port artifact ever needs to interoperate with a deployed
v2.1.8 binary on the protocol surface. ADR-0003 covers what that means for the
v2.1.8 *user base* (registry-fork strategy, parallel maintenance posture).

## Decision

The Rust port owns a **greenfield wire** documented in `docs/wire-protocol.md`
(Phase 1 deliverable). The Go upstream is a behavioral specification — it
defines what each user-visible CLI/admin-API path must produce for equivalent
inputs (R3) — but the on-the-wire bytes are unconstrained. The greenfield
commitments captured at roadmap level:

- **Transport**: QUIC-only relay backhaul via `quinn 0.11`. ALPN identifier
  `portal/2`. `yamux` is dropped entirely.
- **Framing**: per-stream typed prefix (`Channel::Control`, `Channel::TcpProxy`,
  `Channel::UdpDatagram`, `Channel::HopRoute`); 1-byte tag + length-prefixed
  payload, parsed by `winnow` codecs. Replaces the v2.1.8 marker bytes
  (`KEEPALIVE` `0x00`, `RAW_TCP` `0x01`, `TLS_ACTIVATE` `0x02`).
- **Identity**: ed25519 (`ed25519-dalek`) for the protocol-internal relay
  identity; secp256k1 (`k256`) only where the Ethereum ecosystem demands it
  (SIWE message signing). Both private keys wrapped in `secrecy::SecretBox`.
- **API auth**: ed25519-signed `postcard`-encoded `Envelope { payload, sig,
  claims }` replaces the ES256K JWT entirely. Claim set is specified in the
  Phase 1 wire-protocol spec (SEC-001 — `nonce`, `not_before`, `not_after`,
  `audience`, `purpose`).
- **HTTP response wrapper**: `{"data": T}` on 2xx, `{"error": {code, message}}`
  on 4xx/5xx; HTTP status is the success/failure discriminator. Replaces the
  v2.1.8 `{ok, data?, error?}` envelope shape. `utoipa` generates the spec.
- **Versioning**: HTTP path prefix `/v1/` carried on every endpoint except
  `/healthz` and `/metrics` (operational, unversioned by convention).
- **Inner binary codec**: `postcard`. Outer HTTP body codec: `serde_json`.

ADR-0001 takes effect from commit `0001-greenfield-wire`. Any deliberate wire
change after Phase 1 ships requires its own ADR; once Phase 1's
`docs/wire-protocol.md` lands, that document is the editable source of truth for
the wire bytes and ADRs amend it rather than re-litigating individual fields.

## Consequences

### Positive

- The Rust port shape is the new normative reference for any future Portal
  client or server. No byte-level compatibility budget consumed for legacy
  carry-over.
- Modern Rust idioms apply throughout: native async-fn-in-trait (edition 2024)
  in place of `async-trait`, sealed `#[non_exhaustive]` enums, `winnow` parser
  combinators, `postcard` deterministic binary codec.
- Type-level R2 trust-boundary enforcement becomes possible — the v2.1.8 wire
  reused JWT bytes across every trust surface; greenfield lets us scope each
  trust boundary to its own `SecretBox<KeyType>` newtype with a domain
  separator.

### Negative — accepted

- **Existing Go v2.1.8 deployments cannot interoperate with the Rust port.**
  CI never runs against a Go binary; behavioral parity is verified by the
  Phase 7 trace-replay harness, not by wire-level interop tests. The
  v2.1.8 user-base migration posture is captured in ADR-0003.
- **No interop test catches a regression before user-visible breakage.** This is
  the inherent cost of a greenfield port. Mitigations: behavioral-trace harness
  in Phase 7 replays curated Go-reference scenarios; ADR-0003 commits to either
  a deprecation timeline or explicit indefinite parallel maintenance for v2.1.8
  deployments so the migration discontinuity is named, not hidden.

## Considered alternatives

### A. Wire-compat parity — port byte-for-byte, no changes

Status quo of the previous `AGENTS.md`. Pros: existing Go users transparently
upgrade to the Rust binary. Cons: every constraint above stays; modern Rust
idioms are gated behind preserving v2.1.8 framing; ES256K JWTs remain a
maintenance burden; QUIC stream-id native register is unusable. The user
explicitly rejected this path in the planning round.

### B. Wire-compat with idiomatic internals — keep the bytes, modernize the implementation

The middle path. Pros: deployed v2.1.8 clients still work; internal Rust code
uses `winnow`, `postcard`, etc. behind a Go-shape outer wrapper. Cons:
the public wire is still v2.1.8, which means JWT-shaped envelopes, marker bytes,
yamux multiplexing, and ES256K signatures all remain on the user-visible
surface. R2 type-level trust-boundary enforcement degrades to advisory because
the wire still carries one JWT shape across all three trust surfaces. The
"modern reference implementation" claim cannot be honestly made because the wire
is the v2.1.8 wire. **This alternative is named explicitly per product-lens
P2#8** so future readers see it was considered and rejected.

### C. Greenfield wire — selected

Drops the v2.1.8 byte-compat constraint entirely. Costs are listed under
"Negative — accepted" above; mitigations documented in ADR-0003.

## References

- Roadmap plan: [`port_go_to_rust_greenfield_383a2dc9.plan.md`](../../) §
  Summary + Implementation Unit U2 (Phase 1 wire-protocol.md owner)
- Phase 1 deliverable that operationalizes this ADR: `docs/wire-protocol.md`
  (deferred to Phase 1 plan; this ADR fixes the *posture*, not the per-field bytes)
- ADR-0003 (registry-fork + v2.1.8 migration posture) and ADR-0004
  (upgrade-encouragement matrix) bound the user-facing consequences of this ADR
