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
//! - **[`TenantSecp256k1Key`]** — tenant Ethereum / SIWE identity (U5).
//! - **`KeylessSigningKey`** — ephemeral keyless signing oracle key (Phase 6b).
//! - **`ApiHttpsKey`** — HTTPS mutual-TLS identity for the relay admin API (Phase 5).
//!
//! # Current surface (U1 + U2 + U3 + U4 + U5 + U6 + U7)
//!
//! - [`PortalCryptoError`] — workspace-wide crypto error type.
//! - [`DomainSeparator`] + [`Role`] — SEC-007 domain-separation typestate.
//! - [`RelayEd25519Key`] + [`load_relay_ed25519_key`] + [`verifying_key`] — relay ed25519 key.
//! - [`Ed25519Signer`] — domain-separated signing (sole public sign method).
//! - [`Ed25519Verifier`] — domain-separated verification (`verify_strict`).
//! - [`TenantSecp256k1Key`] + [`load_tenant_secp256k1_key`] + [`tenant_public_key`] — tenant secp256k1 key.
//! - [`EthAddress`] + [`evm_address_from_pubkey`] — EVM address derivation (EIP-55).
//! - [`sign_eip191_personal`] — EIP-191 personal-message signing.
//! - [`ChallengeBuilder`] + [`RegisterChallenge`] + [`verify_siwe`] — SIWE challenge (U6).
//! - [`BindingAttestation`] + [`build_binding`] + [`into_siwe_statement`] + [`verify_binding`] — SIWE→ed25519 binding (U7, SEC-002).

#![forbid(unsafe_code)]

pub(crate) mod ed25519;
pub mod error;
pub(crate) mod secp256k1;
pub(crate) mod secret;
pub mod separator;
pub(crate) mod siwe;

pub use ed25519::key::{RelayEd25519Key, load_relay_ed25519_key, verifying_key};
pub use ed25519::sign::Ed25519Signer;
pub use ed25519::verify::Ed25519Verifier;
pub use error::PortalCryptoError;
pub use secp256k1::address::{EthAddress, evm_address_from_pubkey};
pub use secp256k1::eip191::sign_eip191_personal;
pub use secp256k1::key::{
    TenantSecp256k1Key, load_tenant_secp256k1_key, public_key as tenant_public_key,
};
pub use separator::{
    BindingAttestation as BindingRole, DomainSeparator, HopRoute, KeylessRequest, LeaseToken,
    RelayDescriptor, ReputationDelta, Role,
};
pub use siwe::binding::{BindingAttestation, build_binding, into_siwe_statement, verify_binding};
pub use siwe::challenge::{
    ChallengeBuilder, RegisterChallenge, build as build_siwe_challenge, verify_siwe,
};
