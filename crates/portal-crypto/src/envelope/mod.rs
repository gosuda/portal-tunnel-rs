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

// `pub mod` (not `pub(crate)`) is intentional: clippy::redundant_pub_crate fires
// because `envelope` itself is declared `pub(crate)` in `lib.rs`, making an
// inner `pub(crate)` redundant. The `ed25519/`, `secp256k1/`, and `siwe/`
// submodules use `pub(crate)` directly because they live under a `pub(crate)`
// parent that is also `pub(crate)` in `lib.rs` — the lint did not fire there
// due to nesting depth differences. Consistency here is blocked by the lint.
pub mod sign;
pub mod verify;

pub use sign::sign_envelope;
pub use verify::verify_envelope;
