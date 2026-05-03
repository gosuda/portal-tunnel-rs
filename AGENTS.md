# portal-tunnel-rs — AGENTS.md

Greenfield Rust port of Portal. Go upstream (`gosuda/portal-tunnel` v2.1.8 in
the sibling `portal-tunnel/` checkout) is **read-only behavioral spec**, not a
wire constraint — see [ADR-0001](docs/adr/0001-greenfield-wire.md). The v2.1.8
user-base migration posture is in
[ADR-0003](docs/adr/0003-registry-fork-and-v2-1-8-migration.md). The
public-internet upgrade-encouragement matrix is in
[ADR-0004](docs/adr/0004-supported-clients-and-upgrade-encouragement.md).

## Crate ownership

Each contract has exactly one owner. No mirroring; no umbrella `portal-utils`
or `portal-types` crates (R7).

| Crate | Owns | Phase |
|---|---|---|
| `portal-wire` | greenfield protocol types, codecs, framing constants | 1 |
| `portal-crypto` | every `SecretBox<KeyType>` constructor; ed25519 + k256 + keyless skeleton | 2 |
| `portal-net` | quinn QUIC backhaul; TCP/UDP relay; QUIC trust boundary (`SecretBox<QuicIdentityKey>`) | 3 |
| `portal-acme` | ACME issuance + DNS-01 providers (local / Cloudflare / Route53 / Cloud DNS) | 4 |
| `portal-relay` | lease lifecycle, axum API surface, policy engine, discovery, overlay, keyless oracle (`SecretBox<ApiHttpsKey>`, `SecretBox<KeylessSigningKey>`) | 5–6b |
| `portal-sdk` | client orchestration — expose, listener, RFC-5705 MITM probe, eclipse-resistant relay picker | 6a |
| `portal-relay-bin` | `portal-relay` binary; embedded admin SPA + docs site | 7 |
| `portal-cli` | `portal` binary (R5+C11: distinct binary name from crate name) | 7 |
| `portal-demo` | `portal-demo` sample target binary | 7 |
| `xtask` | codegen, release, openapi-export, dep-audit, refresh-frontend-bundle | 0 (skeleton) |

## Trust boundaries — key-material isolation (R2)

Three trust surfaces. Each loads its signing key from a distinct path, holds it
in a distinct `secrecy::SecretBox<KeyType>` newtype, and the type system rejects
cross-use. A CI clippy `disallowed_methods` rule (Phase 5 deliverable) rejects
any function returning more than one `SigningKey` from a single load call. The
three `rustls::ServerConfig` instances are downstream consumers of these
isolated key types, not load-bearing on their own.

| Surface | Key newtype | Owning crate | Downstream consumer |
|---|---|---|---|
| Relay API HTTPS | `SecretBox<ApiHttpsKey>` | `portal-relay` (`state/`) | `crates/portal-relay/src/api/` axum::Router |
| Tenant TLS keyless signing | `SecretBox<KeylessSigningKey>` | `portal-relay` (`keyless/`) | `crates/portal-relay/src/keyless/` axum::Router with mTLS |
| QUIC datagram identity | `SecretBox<QuicIdentityKey>` | `portal-net` (`quic/`) | `crates/portal-net/src/quic/` quinn endpoint (NOT an axum::Router) |

Cross-crate plumbing of `SecretBox<QuicIdentityKey>` from `portal-relay`'s
identity loader to `portal-net`'s endpoint constructor is documented in U6 (the
Phase 5 plan).

## 2026 Rust house style

Engineering Defaults R7-R9 from the roadmap (codified in
[ADR-0002](docs/adr/0002-aggressive-2026-register.md)). Deviation requires an
ADR amendment in the same commit as the dep / lint / config change — see
[`docs/adr/README.md`](docs/adr/README.md) for the procedure.

| Setting | Value |
|---|---|
| Edition | 2024 |
| Resolver | 3 |
| MSRV | `1.91` (declared in `[workspace.package]`) |
| `unsafe_code` | `forbid` (zero unsafe blocks in workspace) |
| Clippy lints | `pedantic` + `cargo` + `nursery` warn at `priority = -1`; `unwrap_used` + `expect_used` deny |
| Per-lint silence | `#[expect(lint_name, reason = "…")]` — never `#[allow]` |
| Dep declarations | `[workspace.dependencies]` only; member crates write `dep.workspace = true` |
| TLS | `rustls 0.23` + `aws-lc-rs` MANDATORY (R13); `openssl` family banned direct + transitive |
| Time | `jiff` (ban `chrono`, `time`) |
| Builder | `bon` (ban `derive_builder`, `typed-builder`) |
| Async-fn-in-trait | edition-2024 native + `trait_variant` for Send-bound shapes (ban `async-trait`) |
| Singleton cell | `std::sync::OnceLock` (ban `lazy_static`, `once_cell`) |
| Coverage | `cargo-llvm-cov` (ban `tarpaulin`) |
| Bench | `divan` (iterative); `criterion` permitted (CI regression detection only) |
| Concurrent map | `papaya` primary (read-heavy) with `pin_owned()` for await-crossing guards; `dashmap` fallback (write-heavy only) |
| Hot-reload config | `arc-swap` |
| Rate limit | `governor` |
| Secrets | `secrecy::SecretBox<T>` mandatory at type level |
| Inner binary codec | `postcard` |
| OpenAPI | `utoipa` + `utoipa-axum` |

The full register, banned-crates list, and per-pick rationale live in
[ADR-0002](docs/adr/0002-aggressive-2026-register.md). The cargo-deny `bans`
table operationally enforces the bans.

## Atomic commits / tidy-first

One concern per commit. ≤200 LoC substantive diff (file moves and generated
files do not count toward this limit).

- Minimize concepts, duplication, and ceremony.
- One real owner per contract — no mirroring.
- Remove dead code in the same commit where you touch nearby code.
- No behavior change bundled with restructure — split them.
- New behavior follows TDD where practical (red → green → refactor); edits
  prefer the smallest diff that satisfies the spec.

## Decision Stability

Once Phase 0 ships (commit 11 lands), the v0.1 R-ID set (R1-R6 + R10-R15) and
the v0.2 Backlog enumeration both **freeze**. Reopening any frozen decision
requires an ADR amendment (rationale, considered alternatives, impact on phase
plans), not a TODO. ADR amendments use the procedure documented in
[`docs/adr/README.md`](docs/adr/README.md). New scope additions after v0.1
freeze land in a future v0.3 Backlog (separate ADR), never in v0.2.

Reversing a Resolved-During-Planning decision additionally requires citing the
original rationale, documenting why it no longer holds, and passing
ce-doc-review at the time of reversal. Mid-flight reversals via TODO are out of
process.

This clause is itself binding from this round forward; reopening Decision
Stability requires an ADR amendment.
