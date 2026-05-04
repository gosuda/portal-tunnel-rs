//! All cryptographic primitives for the portal-tunnel-rs workspace.
//!
//! This crate is the single owner of every private-key constructor in the
//! workspace. No other crate may load a private key from disk or derive a
//! signing key; all callers must go through the types vended here.
//!
//! # Trust-boundary roles
//!
//! Four key types represent the four trust surfaces:
//!
//! - **[`RelayEd25519Key`]** — relay protocol identity (U3).
//! - **`TenantSecp256k1Key`** — tenant Ethereum / SIWE identity (Phase 2 U5).
//! - **`KeylessSigningKey`** — ephemeral keyless signing oracle key (Phase 6b).
//! - **`ApiHttpsKey`** — HTTPS mutual-TLS identity for the relay admin API (Phase 5).
//!
//! # Current surface (U1 + U2 + U3 + U4)
//!
//! - [`PortalCryptoError`] — workspace-wide crypto error type.
//! - [`DomainSeparator`] + [`Role`] — SEC-007 domain-separation typestate.
//! - [`RelayEd25519Key`] + [`load_relay_ed25519_key`] + [`verifying_key`] — relay ed25519 key.
//! - [`Ed25519Signer`] — domain-separated signing (sole public sign method).
//! - [`Ed25519Verifier`] — domain-separated verification (`verify_strict`).

#![forbid(unsafe_code)]

pub mod ed25519;
pub mod error;
pub mod separator;

pub use ed25519::key::{RelayEd25519Key, load_relay_ed25519_key, verifying_key};
pub use ed25519::sign::Ed25519Signer;
pub use ed25519::verify::Ed25519Verifier;
pub use error::PortalCryptoError;
pub use separator::{
    BindingAttestation, DomainSeparator, HopRoute, KeylessRequest, LeaseToken, RelayDescriptor,
    ReputationDelta, Role,
};
