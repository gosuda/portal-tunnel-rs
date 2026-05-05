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
//!   out the remaining deferrals — ENS Sybil-gating exemption
//!   (waits on `Arc<dyn EnsResolver>` from B6's API surface) and
//!   honeypot call-site wiring. The per-signal-kind weight
//!   plumbing landed via
//!   [`policy::reputation::ReputationConfig::signal_weights`] +
//!   [`policy::reputation::ReputationEngine::record_signal_default`];
//!   per-kind tuning values remain an ADR-0007 decision. Engine-side
//!   `reputation.json` persistence helpers (`persist_to_path` /
//!   `restore_from_path`) over a
//!   [`policy::reputation::ReputationSnapshotEntry`] DTO list also
//!   landed; only the 60s-cadence task that drives them remains B8
//!   territory. Engine-side hot-swap also landed via
//!   [`policy::reputation::ReputationEngine::swap_config`] (atomic
//!   `(config, limiter)` pair behind [`arc_swap::ArcSwap`]); the
//!   SIGHUP / admin-api reload run-loop **trigger** that calls
//!   `swap_config` on a config-file change remains B8 territory. The
//!   workspace-level [`reload::ReloadHandle`] type-level scaffolding
//!   (Phase 5 U13) landed; consumer wiring remains B8 territory.
//! - **Batches 8 + 10 fully pending**: hot-reload consumer wiring +
//!   keyless I/O wiring; Admin View + R15 Status TUI.
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

pub use config::{RelayServerConfig, RuntimeConfig};
pub use error::{RelayError, RelayResult};
pub use reload::{ReloadError, ReloadHandle};
pub use server::{JANITOR_INTERVAL, LifecyclePhase, Server, ServerStatus};
