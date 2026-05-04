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
//! # Current surface (U1 + U2 + U3 + U4 + U5 + U6 + U7 + U8 + U9 + U10 + U11)
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
//! - [`sign_envelope`] + [`verify_envelope`] — SEC-001 envelope sign/verify (U8).
//! - [`KeylessSigningKey`] + [`KeylessSigningKeyHandle`] + [`KeylessError`] + [`SigningInput`] + [`SignatureScheme`] + [`load_keyless_signing_key`] — keyless sync-trait skeleton (U9).
//! - `ApiHttpsKey` + `load_api_https_key` + `api_https_signing_key` — relay API HTTPS key (U10).
//!   `ApiHttpsKey` wraps `Arc<dyn rustls::sign::SigningKey>` directly; it is structurally
//!   inseparable from `rustls` and therefore gated on the `rustls-integration` feature.
//!   All consumers of this type (i.e. `portal-relay`) must enable that feature.
//! - [`EnsResolver`] + [`AlloyEnsResolver`] + [`EnsError`] — ENS name resolution (U11).

#![forbid(unsafe_code)]

#[cfg(feature = "rustls-integration")]
pub(crate) mod api_https;
pub(crate) mod ed25519;
pub(crate) mod ens;
pub(crate) mod envelope;
pub mod error;
pub(crate) mod keyless;
pub(crate) mod secp256k1;
pub(crate) mod secret;
pub mod separator;
pub(crate) mod siwe;

#[cfg(feature = "rustls-integration")]
pub use api_https::signing_key as api_https_signing_key;
#[cfg(feature = "rustls-integration")]
pub use api_https::{ApiHttpsKey, load_api_https_key};
pub use ed25519::key::{RelayEd25519Key, load_relay_ed25519_key, verifying_key};
pub use ed25519::sign::Ed25519Signer;
pub use ed25519::verify::Ed25519Verifier;
pub use ens::{AlloyEnsResolver, EnsError, EnsResolver};
pub use envelope::{sign_envelope, verify_envelope};
pub use error::PortalCryptoError;
pub use keyless::{
    KeylessError, KeylessSigningKey, KeylessSigningKeyHandle, SignatureScheme, SigningInput,
    load_keyless_signing_key,
};
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

// ---------------------------------------------------------------------------
// Integration-test helpers (doc-hidden, not part of the public production API)
// ---------------------------------------------------------------------------
//
// These re-exports make `from_seed_for_test` / `from_bytes_for_test` reachable
// from the `crates/portal-crypto/tests/` integration-test compilation units.
// They are gated on `cfg(test)` (unit tests within this crate) and the
// `insecure-test-constructors` feature (integration tests in tests/ and
// external harnesses that activate it).
// `#[doc(hidden)]` keeps them out of published rustdoc.  Phase 2 B8 / ADR-0002 R2.

#[cfg(any(test, feature = "insecure-test-constructors"))]
#[doc(hidden)]
pub use ed25519::key::from_seed_for_test as ed25519_from_seed_for_test;

#[cfg(any(test, feature = "insecure-test-constructors"))]
#[doc(hidden)]
pub use secp256k1::key::from_bytes_for_test as secp256k1_from_bytes_for_test;
