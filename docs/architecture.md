# Architecture

> Phase 0 + Phase 1 baseline. Wire framing and threat model live in their own documents (see below). Each subsequent phase plan extends the relevant section.

## Component map

```
                 ┌──────────────────────────────────────────────┐
                 │                portal-relay-bin              │
                 │  (binary `portal-relay`; embedded admin SPA) │
                 └─────────────────────┬────────────────────────┘
                                       │
              ┌────────────────────────┴────────────────────────┐
              │                  portal-relay                   │
              │  lease · api (admin/sdk/discovery)              │
              │  policy (R10 v0.1 per-relay) · listeners        │
              │  state · admin · keyless · overlay              │
              └────┬───────────┬───────────┬───────────┬────────┘
                   │           │           │           │
              ┌────▼─────┐ ┌───▼────┐ ┌────▼────┐ ┌────▼────┐
              │portal-net│ │ acme   │ │ wire    │ │ crypto  │
              │ quinn +  │ │ instant│ │ codec   │ │ ed25519 │
              │ TCP/UDP  │ │ -acme  │ │ + types │ │ + k256  │
              └──────────┘ └────────┘ └─────────┘ └─────────┘

              ┌──────────────┐                ┌──────────────┐
              │ portal-cli   │ ──── uses ──── │  portal-sdk  │
              │ (binary      │                │  expose +    │
              │  `portal`)   │                │  listener +  │
              │  + Tunnel    │                │  MITM probe  │
              │   TUI        │                │              │
              └──────────────┘                └──────────────┘
```

The full crate dependency graph + per-phase sequencing diagrams live in the
roadmap plan (`port_go_to_rust_greenfield_383a2dc9.plan.md` §`High-Level
Technical Design`).

## Three trust boundaries (R2)

| Surface | Owning crate | Key newtype | Loaded from |
|---|---|---|---|
| Relay API HTTPS | `portal-relay` `state/` | `SecretBox<ApiHttpsKey>` | per-relay config path |
| Tenant TLS keyless signing | `portal-relay` `keyless/` | `SecretBox<KeylessSigningKey>` | per-tenant lease config |
| QUIC datagram identity | `portal-net` `quic/` | `SecretBox<QuicIdentityKey>` | per-relay identity.json |

**Invariant**: each surface's `rustls::ServerConfig` (or quinn endpoint
config) loads its key from a distinct path through a distinct
`secrecy::SecretBox<KeyType>` newtype constructor. The three constructors live
in three distinct modules. A function returning more than one `SigningKey`
from a single load call is rejected by two complementary CI gates: clippy's
`disallowed_methods` (`portal_crypto::load_all_keys` sentinel in
[`../clippy.toml`](../clippy.toml), `allow-invalid = true` so it fires the
moment the symbol is defined and called) plus the `multi-key-return-gate`
regex job in [`../.github/workflows/ci.yml`](../.github/workflows/ci.yml) that
catches the return-type shape `-> (SecretBox<A>, SecretBox<B>)` which
`disallowed_methods` cannot express. The trust-boundary table in `AGENTS.md`
is the canonical reference.

The QUIC trust boundary lives in `portal-net` (FEAS-R2-5 / CORR-R2-06). Cross-
crate plumbing of `SecretBox<QuicIdentityKey>` from `portal-relay`'s identity
loader to `portal-net`'s endpoint constructor is documented in U6 (Phase 5
plan).

## Structured concurrency invariant (R9)

Every spawned task lives inside a `tokio::task::JoinSet` or carries a
`tokio_util::sync::CancellationToken`. Free `tokio::spawn` is permitted only
at the very top of `main`. Library code that calls `tokio::spawn` directly
violates R9.

**Mechanical CI enforcement of this invariant is currently deferred.** The
committed Phase 5/6b plans assume a workspace-wide clippy
`disallowed_methods` rule on `tokio::spawn` exists (Phase 5 plan
§Concurrency, Phase 6b plan §U2 verification), but [`../clippy.toml`](../clippy.toml)
does not yet carry the rule and current library code at
`crates/portal-acme/src/manager.rs`, `crates/portal-net/src/allocator.rs`,
and `crates/portal-relay/src/server.rs` does call free `tokio::spawn`.
Closing this gap requires (a) adding the rule, (b) refactoring those call
sites to take a `&mut JoinSet` from the caller (or applying
`#[expect(clippy::disallowed_methods, reason = "...")]` at audited sites),
and (c) verifying the workspace lints pass clean. Tracked as a follow-on
landing alongside Phase 5 Batch 8 hot-reload (which already touches
`server.rs` task-spawning).

Each library crate documents its task-spawning contract — i.e., which entry
points spawn tasks, which `JoinSet` / `CancellationToken` owns them, which
graceful-shutdown sequence drains them. Per-dep task-spawning audit (quinn,
axum, instant-acme, chosen WireGuard fork) is documented in
[`dep-spawning-audit.md`](dep-spawning-audit.md) per F4.

## Secret-handling invariant

Every private key, admin token, lease secret, ACME account key, DNS-provider
credential, and keyless signing key lives inside `secrecy::SecretBox<T>` at
type level. Bare `String` for secrets is rejected by clippy
`disallowed_types`. The newtype `T` parameter encodes the role (R2 trust
boundary), so the type system rejects cross-use even when both keys happen to
be ed25519:

```rust
pub struct ApiHttpsKey(SigningKey);
pub struct KeylessSigningKey(SigningKey);
pub struct QuicIdentityKey(SigningKey);

// API HTTPS ServerConfig accepts only SecretBox<ApiHttpsKey>;
// passing SecretBox<QuicIdentityKey> is a type error.
```

At-rest encryption strategy for `identity.json`, ACME private keys, and DNS-
provider credentials (SEC-005) is a Phase 5 deliverable. v0.1 plaintext-on-
disk is acknowledged in `SECURITY.md`.

### Supply-chain auditing

Dependency auditing is governed by `cargo-vet` under
`supply-chain/{audits,config}.toml`; gate timeline and the `cargo vet
certify` workflow live in [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## `trait_variant` Send-bound migration shape (R9)

Edition 2024 native `async fn` in trait is the default. The compiler infers
non-`Send` for the returned `impl Future` unless the auto-trait propagates
through every `&self` field. When a trait must be Send-bounded for tokio
multi-threaded scheduling, generate a parallel Send-bounded trait via
`trait_variant::make`:

```rust
#[trait_variant::make(SendableSignerExt: Send)]
pub trait SignerExt {
    async fn sign(&self, payload: &[u8]) -> Result<Signature, SignerError>;
}
```

`trait_variant` generates `SendableSignerExt` whose returned future is Send-
bounded. Implementors of the original `SignerExt` automatically satisfy
`SendableSignerExt` when their `&self` fields are `Send + Sync`. Consumers
that need Send (e.g., `tokio::spawn` boundaries) bound on the Send-variant.

This is the **only** sanctioned migration shape for async-fn-in-trait that
needs a Send bound. `async-trait` macro is banned (R9 / ADR-0002 / deny.toml).
Reaching for `async-trait` after the first Send-related compile error is the
expected anti-pattern; this section exists to head it off.

## Open architectural sections (Phase 1+ owners)

Landed/partial/pending per-section state mirrors `PLAN.md` "Current
implementation status"; pointers below resolve to the canonical doc or
code module for each section.

- **Wire framing + codec layout** — landed in Phase 1: see [`docs/wire-protocol.md`](wire-protocol.md). Spec/code lockstep is the U16 invariant; gate ownership lives in [`xtask/src/wire_drift_check.rs`](../xtask/src/wire_drift_check.rs).
- **Threat model** — landed in Phase 1: see [`docs/threat-model.md`](threat-model.md). Adversary capabilities, multi-hop privacy claims, R10 8-class enumeration, and SEC-001..005 evaluation context are documented there.
- **Lease registry data layout (papaya `pin_owned()` boundaries)** — landed in Phase 5 Batch 4: see `crates/portal-relay/src/state/lease_registry.rs`.
- **Three trust boundaries' rustls::ServerConfig assembly** — landed in Phase 5 (Batch 2 listeners + Batch 5 envelope) and Phase 6b/A (Batch 2 keyless mTLS endpoint): see `crates/portal-relay/src/{listeners,api,keyless}/`.
- **Hot-reload semantics for `arc-swap<Config>` trust-boundary keys** — pending Phase 5 Batch 8 (SEC-010); cohesive `arc-swap<RuntimeConfig>` + governor rebuild + tokio file-watcher.
- **WireGuard-userspace fork pick + smoltcp integration shape** — partial. Fork pick (`defguard_boringtun` 0.6.5) landed in Phase 6b/B Batch 1-2: see [ADR-0015](adr/0015-wireguard-userspace-fork-pick.md) + `crates/portal-relay/src/overlay/wg_device.rs`. smoltcp + Overlay orchestrator + `quinn::AsyncUdpSocket` adapter pending Phase 6b/B Batch 3.
- **End-to-end harness + behavioral-trace replay shape** — pending Phase 7 Batch 3 (single-process e2e) + Batch 4 (behavioral-trace Go sidecar).
