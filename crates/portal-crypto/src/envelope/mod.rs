//! Signed [`portal_wire::envelope::Envelope`] helpers (U8).
//!
//! This module provides the two-sided envelope API:
//!
//! - **[`sign`]** — [`sign::sign_envelope`] builds and signs a
//!   [`portal_wire::envelope::Envelope`] using an [`crate::Ed25519Signer`].
//!   The signing input is sourced exclusively from
//!   [`portal_wire::envelope::Envelope::signing_input`], keeping the canonical
//!   wire shape single-sourced in `portal-wire`.
//!
//! - **[`verify`]** — [`verify::verify_envelope`] reconstructs the signing
//!   input and performs SEC-001 claim-set checks (time window, audience,
//!   purpose) **before** the cryptographic verification, so cheap rejections
//!   happen first.

pub mod sign;
pub mod verify;

pub use sign::sign_envelope;
pub use verify::verify_envelope;
