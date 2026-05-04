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

pub mod binding;
pub mod challenge;

pub use binding::{BindingAttestation, build_binding, into_siwe_statement, verify_binding};
pub use challenge::{ChallengeBuilder, RegisterChallenge, verify_siwe};
