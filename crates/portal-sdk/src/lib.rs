//! `portal-sdk` — client-side orchestration for the portal-tunnel
//! greenfield Rust port.
//!
//! Owns (full Phase 6a scope per
//! `docs/plans/2026-05-04-006-feat-portal-sdk-plan.md` — landed-vs-
//! pending state below):
//! - `expose` session lifecycle (lease registration, listener loop,
//!   reconnect/backoff). **Pending — Phase 6a U6.**
//! - RFC 5705 MITM probe via rustls TLS exporter labels. **Landed.**
//! - Eclipse-resistant relay-set selection (R10 v0.1 — per-relay
//!   defense). **Landed.**
//! - Structured event bus for the R15 v0.1 Tunnel TUI mode. **Landed.**
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
//! `broadcast`-channel factories). **B2** ships [`relay_set`],
//! [`picker`], and [`mitm`]. **U6 (`expose.rs`), U7 (`listener.rs`),
//! and U8 (`identity.rs`)** remain pending — see `PLAN.md` "Current
//! implementation status" for the per-unit deferral.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod events;
pub mod expose;
pub mod identity;
pub mod listener;
pub mod mitm;
pub mod picker;
pub mod relay_set;

pub use error::{SdkError, SdkResult};
pub use events::{
    DEFAULT_EVENT_CHANNEL_CAPACITY, TunnelEvent, TunnelState, channel, channel_with_capacity,
};
pub use expose::{ExposeConfig, ExposeSession};
pub use identity::{
    ProtocolKey, generate_protocol_key, load_protocol_key, load_tenant_key, protocol_pubkey,
    tenant_public_key,
};
pub use listener::Listener;
pub use mitm::{MitmError, PROBE_EKM_LEN, derive_probe_ekm};
pub use picker::{PickerConstraints, pick_relays};
pub use portal_net::AcceptedStream;
pub use relay_set::{AsnBin, MetadataProvenance, RelayCandidate, RelayMetadata, RelaySet};
