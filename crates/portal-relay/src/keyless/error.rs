//! Error type for the keyless PEM loader and (Phase 6b/A U2+) signer.
//!
//! Phase 6b/A Batch 1 first half (U1) ships only the loader-side
//! variants: `MalformedPem`, `UnsupportedAlgorithm`, `InvalidKey`. The
//! signer / async-bridge variants land alongside U2.
//!
//! The variant set is `#[non_exhaustive]` so adding signer arms in U2
//! is not a breaking change.

use thiserror::Error;

/// Errors produced by the keyless PEM loader and (forthcoming) signer.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum KeylessError {
    /// The supplied PEM bytes were syntactically invalid (no recognised
    /// section, base64 decode failure, missing END marker, etc.).
    #[error("malformed pem: {0}")]
    MalformedPem(String),

    /// The PEM was parseable, but the embedded private-key algorithm or
    /// curve is not on the v0.1 keyless allow-list.
    ///
    /// v0.1 accepts:
    /// - PKCS#1 / PKCS#8 RSA (RSA-2048; RSA-3072 lands when an operator
    ///   surfaces a need — see `material.rs` rustdoc).
    /// - PKCS#8 / SEC1 ECDSA on the NIST P-256 curve.
    ///
    /// Everything else (DSA, Ed25519, P-384, P-521, secp256k1, …) is
    /// refused at load time so we cannot accidentally hand a
    /// non-allow-listed algorithm to the (forthcoming U2) rustls
    /// `SigningKey` adapter.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// The PEM's algorithm was on the allow-list but the inner DER body
    /// failed to parse (truncated PKCS#8, malformed SEC1 sequence,
    /// missing curve parameters, etc.).
    #[error("invalid key body: {0}")]
    InvalidKey(String),
}
