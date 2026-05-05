//! Relay runtime state — identity, lease registry, TLS material.
//!
//! Phase 5 B2 lands `identity` (R2 newtype shape + QUIC-only load).
//! Phase 5 B4 lands `lease_registry` (papaya-backed register / renew
//! / unregister / lookup + `cleanup_expired`). Other Phase 5 batches
//! further extend the state surface: B3 with the full identity
//! bundle, B5+ with the policy- and lease-token-aware admission seam
//! on top of `LeaseRegistry`, B8 with the TLS material handoff from
//! portal-acme. See this crate's `lib.rs` for current Phase 5
//! status.

pub mod identity;
pub mod lease_registry;
pub mod lease_token;
pub mod persistence;

pub use identity::{IdentityPaths, RelayIdentity, load_quic_only, load_relay_protocol_only};
pub use lease_registry::{IdentityKey, LeaseRecord, LeaseRegistry};
pub use lease_token::{LEASE_TOKEN_VERSION, LeaseTokenClaims, LeaseTokenError};
pub use persistence::{STATE_FILE_MODE, read_json, write_json_atomic};
