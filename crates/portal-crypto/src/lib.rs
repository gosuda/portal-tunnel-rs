//! All cryptographic primitives for the portal-tunnel-rs workspace.
//!
//! This crate is the single owner of every private-key constructor in the
//! workspace. No other crate may load a private key from disk or derive a
//! signing key; all callers must go through the types vended here.
//!
//! # Trust-boundary roles (planned)
//!
//! Four key types will represent the four trust surfaces once fully implemented:
//!
//! - **`RelayEd25519Key`** — relay protocol identity (Phase 2 U3).
//! - **`TenantSecp256k1Key`** — tenant Ethereum / SIWE identity (Phase 2 U4).
//! - **`KeylessSigningKey`** — ephemeral keyless signing oracle key (Phase 6b).
//! - **`ApiHttpsKey`** — HTTPS mutual-TLS identity for the relay admin API (Phase 5).
//!
//! # Current surface (U1 + U2)
//!
//! - [`PortalCryptoError`] — workspace-wide crypto error type.
//! - [`DomainSeparator`] + [`Role`] — SEC-007 domain-separation typestate.

#![forbid(unsafe_code)]

pub mod error;
pub mod separator;

pub use error::PortalCryptoError;
pub use separator::{
    BindingAttestation, DomainSeparator, HopRoute, KeylessRequest, LeaseToken, RelayDescriptor,
    ReputationDelta, Role,
};
