//! Keyless tenant-TLS oracle (Phase 6b/A) — R2 trust-boundary surface
//! and SEC-004 protections live here.
//!
//! ## Phase 6b/A implementation status
//!
//! Phase 6b/A lands incrementally per
//! `docs/plans/2026-05-04-007-feat-portal-relay-overlay-keyless-plan.md`.
//!
//! Batch 1 first half (U1) shipped this module skeleton and:
//! - [`KeylessSigningKey`] — opaque [`secrecy::SecretBox<KeyMaterial>`]
//!   newtype + [`load_keyless_signing_key`] PEM loader.
//! - [`KeylessError`] — `thiserror`, `#[non_exhaustive]` variants.
//!
//! Batch 1 second half (U2) adds the rustls-side surface:
//! - [`signer::KeylessSignerAdapter`] — sync rustls
//!   [`rustls::sign::SigningKey`] impl that delegates crypto
//!   primitives to the aws-lc-rs provider (R13 / ADR-0014 — workspace
//!   policy is "use rustls's own provider, don't roll our own").
//! - [`bridge::Bridge`] — bounded async-to-sync bridge: a tokio
//!   `mpsc` queue feeding a JoinSet-tracked supervisor pool that
//!   dispatches each sync `Signer::sign` onto tokio's blocking pool
//!   via `spawn_blocking`.  Backpressure surfaces as
//!   [`KeylessError::QueueFull`] (handler maps to HTTP 503).
//!   ADR-0016 captures the design + rejected alternatives.
//!
//! Subsequent units fill in the rest of the surface; until each
//! lands, this module exposes only the type-level R2 isolation
//! plus the U2 sign surface.
//!
//! - U3 (next): axum mTLS endpoint + SEC-004 protections +
//!   signrpc-equivalent wire shape.
//! - U4: SEC-015 routing-context refuse-to-sign guard.
//!
//! ## Trust-boundary discipline (R2)
//!
//! [`KeylessSigningKey`] is the relay-owned newtype for the keyless
//! key role and is a distinct
//! [`secrecy::SecretBox<…>`][secrecy::SecretBox] type from the relay's
//! other key roles, all of which live as separate fields on
//! [`crate::state::RelayIdentity`]:
//!
//! - `RelayIdentity::api_https` — relay HTTPS API surface.
//! - `RelayIdentity::quic` — QUIC backhaul identity.
//! - `RelayIdentity::keyless` (Phase 6b/A wiring) — this module's
//!   [`KeylessSigningKey`].
//!
//! Each field is a separate Rust type, so accidental cross-use is
//! rejected at compile time.  [`load_keyless_signing_key`] returns
//! exactly one key — the workspace clippy `disallowed_methods` rule on
//! `portal_crypto::load_all_keys` plus the multi-key-return regex CI
//! gate cover the bundle-loader bypass.

pub mod bridge;
pub mod error;
pub mod material;
pub mod signer;

pub use bridge::{Bridge, BridgeConfig};
pub use error::KeylessError;
pub use material::{KeylessSigningKey, load_keyless_signing_key};
pub use signer::KeylessSignerAdapter;
