//! SIWE (Sign-In With Ethereum, EIP-4361) wrapper and SIWE→ed25519 binding.
//!
//! This module implements two concerns:
//!
//! - **[`challenge`]** — [`ChallengeBuilder`] that constructs a [`::siwe::Message`]
//!   embedding the portal-tunnel binding statement, and [`verify_siwe`] which
//!   synchronously verifies an EIP-191 signature over that message.
//!
//! - **[`binding`]** — [`BindingAttestation`] that ties an Ethereum address to
//!   an ed25519 public key through the SIWE statement field (SEC-002).

// `pub mod` (not `pub(crate)`) is intentional: clippy::redundant_pub_crate fires
// because `siwe` itself is declared `pub(crate)` in `lib.rs`, making an inner
// `pub(crate)` redundant. Visibility is already capped at the crate root.
pub mod binding;
pub mod challenge;
