//! Relay-server library — lease registry, axum API surface, base
//! policy + R10 v0.1 anti-abuse, discovery announce/refresh, R11 v0.1
//! `/metrics`, R15 v0.1 status TUI scaffold, R13 ECH-aware tenant TLS
//! routing.
//!
//! ## Phase 5 implementation status
//!
//! Phase 5 lands incrementally per
//! `docs/plans/2026-05-04-005-feat-portal-relay-plan.md`.
//!
//! Batch 1 (U1, U2) ships the cargo-vet supply-chain harness and this
//! empty crate skeleton. Subsequent units fill the modules below;
//! until their owning batch lands, each module has a stub `mod.rs`
//! that documents the deferral.
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
