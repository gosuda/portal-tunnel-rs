//! `portal-sdk` — client-side orchestration for the portal-tunnel
//! greenfield Rust port.
//!
//! Owns:
//! - `expose` session lifecycle (lease registration, listener loop,
//!   reconnect/backoff).
//! - RFC 5705 MITM probe via rustls TLS exporter labels.
//! - Eclipse-resistant relay-set selection (R10 v0.1 — per-relay
//!   defense).
//! - Structured event bus for the R15 v0.1 Tunnel TUI mode.
//!
//! Does NOT own:
//! - Wire encoding (lives in `portal_wire`).
//! - QUIC trust-boundary identity (lives in `portal_net`).
//! - Tenant signing keys (loaded via `portal_crypto`).
//! - Any TUI rendering (lives in the eventual `portal_cli` crate).
//!
//! # Phase 6a implementation status
//!
//! Phase 6a lands in batches per
//! `docs/plans/2026-05-04-006-feat-portal-sdk-plan.md`. **B1** ships
//! the crate scaffold (this `lib.rs`), [`error::SdkError`], and the
//! [`events`] module ([`TunnelState`], [`TunnelEvent`],
//! `broadcast`-channel factories). Subsequent batches add
//! `relay_set`, `picker`, `mitm`, `expose`, `listener`, and
//! `identity`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod events;

pub use error::{SdkError, SdkResult};
pub use events::{
    DEFAULT_EVENT_CHANNEL_CAPACITY, TunnelEvent, TunnelState, channel, channel_with_capacity,
};
