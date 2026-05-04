//! Error type for the `portal-crypto` crate.

use thiserror::Error;

/// Top-level error for all `portal-crypto` operations.
///
/// This type is `#[non_exhaustive]` so that new variants can be added
/// in later batch units without breaking downstream match arms.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum PortalCryptoError {
    /// I/O error propagated from key-material file loading.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Ed25519 signing or verification failure.
    ///
    /// Replaced by `Ed25519Error` in U3.
    #[error("ed25519: {0}")]
    Ed25519(String),

    /// secp256k1 / ECDSA failure (k256).
    ///
    /// Replaced by `Secp256k1Error` in U3.
    #[error("secp256k1: {0}")]
    Secp256k1(String),

    /// SIWE message parse or verification failure.
    ///
    /// Replaced by `SiweError` in U4.
    #[error("siwe: {0}")]
    Siwe(String),

    /// Identity-binding attestation failure.
    ///
    /// Replaced by `BindingError` in U4.
    #[error("binding: {0}")]
    Binding(String),

    /// Signed-envelope encode / decode failure.
    ///
    /// Replaced by `EnvelopeError` in U5.
    #[error("envelope: {0}")]
    Envelope(String),

    /// ENS / on-chain name resolution failure.
    ///
    /// Replaced by `EnsError` in U6.
    #[error("ens: {0}")]
    Ens(String),

    /// Keyless signing oracle failure (Phase 6b).
    ///
    /// Replaced by `KeylessError` in U7.
    #[error("keyless: {0}")]
    Keyless(String),

    /// API HTTPS key load / parse failure (U10 / Phase 5).
    #[error("api-https-key: {0}")]
    HttpsKey(String),
}

// Compile-time assertion: PortalCryptoError must be Send + Sync + 'static.
const _: fn() = || {
    const fn assert_send_sync_static<T: Send + Sync + 'static>() {}
    assert_send_sync_static::<PortalCryptoError>();
};
