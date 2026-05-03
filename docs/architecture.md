# Architecture

> Phase 0 skeleton. Each subsequent phase plan extends the relevant section.

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
from a single load call is rejected by a clippy `disallowed_methods` rule
(Phase 5 deliverable). The trust-boundary table in `AGENTS.md` is the
canonical reference.

The QUIC trust boundary lives in `portal-net` (FEAS-R2-5 / CORR-R2-06). Cross-
crate plumbing of `SecretBox<QuicIdentityKey>` from `portal-relay`'s identity
loader to `portal-net`'s endpoint constructor is documented in U6 (Phase 5
plan).

## Structured concurrency invariant (R9)

Every spawned task lives inside a `tokio::task::JoinSet` or carries a
`tokio_util::sync::CancellationToken`. Free `tokio::spawn` is permitted only
at the very top of `main`. Library code that calls `tokio::spawn` directly is
rejected by a clippy `disallowed_methods` rule (Phase 5 deliverable).

Each library crate documents its task-spawning contract — i.e., which entry
points spawn tasks, which `JoinSet` / `CancellationToken` owns them, which
graceful-shutdown sequence drains them. Per-dep task-spawning audit (quinn,
axum, instant-acme, chosen WireGuard fork) lands in Phase 7 per F4.

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

The following sections will be populated by the corresponding phase plans:

- **Wire framing + codec layout** — Phase 1 (`docs/wire-protocol.md` + this
  file's `## Wire framing` section)
- **Threat model** — Phase 1 (`docs/threat-model.md` per SEC-006)
- **Lease registry data layout (papaya `pin_owned()` boundaries)** — Phase 5
- **Hot-reload semantics for `arc-swap<Config>` trust-boundary keys** — Phase 5 (SEC-010)
- **Three trust boundaries' rustls::ServerConfig assembly** — Phase 5
- **WireGuard-userspace fork pick + smoltcp integration shape** — Phase 6b
- **End-to-end harness + behavioral-trace replay shape** — Phase 7
