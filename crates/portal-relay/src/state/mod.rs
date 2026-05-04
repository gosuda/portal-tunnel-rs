//! Relay runtime state — identity, lease registry, TLS material.
//!
//! Phase 5 B2 lands `identity` (R2 newtype shape + QUIC-only load).
//! Phase 5 B4 lands `lease_registry` (papaya-backed register / renew
//! / unregister / lookup + `cleanup_expired`). Subsequent batches
//! extend with the full identity bundle (B3), the policy- and
//! lease-token-aware admission seam on top of `LeaseRegistry`
//! (B5+), and TLS material handoff from portal-acme (B8).

pub mod identity;
pub mod lease_registry;
pub mod persistence;

pub use identity::{IdentityPaths, RelayIdentity, load_quic_only};
pub use lease_registry::{IdentityKey, LeaseRecord, LeaseRegistry};
pub use persistence::{STATE_FILE_MODE, read_json, write_json_atomic};
