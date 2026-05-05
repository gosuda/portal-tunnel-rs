//! Relay-server library — lease registry, axum API surface, base
//! policy + R10 v0.1 anti-abuse, discovery announce/refresh, R11 v0.1
//! `/metrics`, R15 v0.1 status TUI scaffold, R13 ECH-aware tenant TLS
//! routing.
//!
//! ## Phase 5 implementation status
//!
//! Phase 5 lands incrementally per
//! `docs/plans/2026-05-04-005-feat-portal-relay-plan.md`. Per-batch
//! state lives in `PLAN.md` "Current implementation status"; in
//! summary:
//!
//! - **Batches 1-6 + 9 landed end-to-end**: cargo-vet harness,
//!   listeners, identity loaders, persistence, papaya lease registry,
//!   envelope + SDK API endpoints, admin API + discovery, ECH router +
//!   server orchestrator.
//! - **Batch 7 partial-landed**: the R10 v0.1 reputation-engine core
//!   ([`policy::reputation`] — governor-keyed rate limit on
//!   `(identity, ip, lease)`, per-identity exponential-decay score,
//!   signal infra) plus the [`policy::honeypot`] matcher are
//!   committed; `TODO(R10-followup)` markers in `reputation.rs` carve
//!   out the deferrals — ENS Sybil-gating exemption (waits on
//!   `Arc<dyn EnsResolver>` from B6's API surface), honeypot
//!   call-site wiring, `reputation.json` persistence, hot-swap
//!   support, per-signal-kind weight policy.
//! - **Batches 8 + 10 fully pending**: hot-reload + keyless I/O
//!   wiring; Admin View + R15 Status TUI.
//!
//! Module-level rustdocs name the per-module deferral state where one
//! applies.
//!
//! ## Trust boundaries (R2)
//!
//! Three independent `SecretBox<KeyType>` newtypes load from distinct
//! disk paths:
//! - `SecretBox<portal_crypto::ApiHttpsKey>` — relay HTTPS API surface.
//! - `SecretBox<portal_crypto::KeylessSigningKey>` — Phase 6b keyless
//!   tenant-TLS oracle.
//! - `SecretBox<portal_net::QuicIdentityKey>` — QUIC backhaul identity.
//!
//! No function in this crate ever returns more than one signing key
//! from a single load call (workspace clippy `disallowed_methods`
//! enforces).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod admin;
pub mod api;
pub mod config;
pub mod discovery;
pub mod error;
pub mod keyless;
pub mod listeners;
pub mod overlay;
pub mod policy;
pub mod proxy;
pub mod reload;
pub mod server;
pub mod state;
pub mod tui;

pub use error::{RelayError, RelayResult};
pub use server::{JANITOR_INTERVAL, LifecyclePhase, Server, ServerStatus};
