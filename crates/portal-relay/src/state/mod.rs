//! Relay runtime state — identity, lease registry, TLS material.
//!
//! Phase 5 B2 lands `identity` (R2 newtype shape + QUIC-only load).
//! Subsequent batches extend with the full identity bundle (B3),
//! lease registry (B4), and TLS material handoff from portal-acme
//! (B8).

pub mod identity;

pub use identity::{IdentityPaths, RelayIdentity, load_quic_only};
