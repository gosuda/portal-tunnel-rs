//! Core trait and supporting types for the keyless signing oracle.
//!
//! This module defines the **sync-only** [`KeylessSigningKey`] trait that acts
//! as the single contract between `portal-crypto` and any concrete keyless
//! signing back-end (HSM, remote oracle, software key).  The async bridge that
//! proxies calls to a remote keyless server is deferred to Phase 6b.
//!
//! # Design note (FEAS-2)
//!
//! The trait is deliberately **sync** — `fn sign`, not `async fn sign`.  Phase
//! 6b will wrap this in a `tokio::sync::oneshot` channel so that the blocking
//! call runs on a `spawn_blocking` thread pool, preserving the async executor
//! from blocking.  Keeping the trait sync means concrete implementations
//! (software keys, test doubles) need not pull in async runtimes.

use thiserror::Error;

use crate::error::PortalCryptoError;

// ---------------------------------------------------------------------------
// SignatureScheme
// ---------------------------------------------------------------------------

/// The signature algorithm to use when constructing a [`SigningInput`].
///
/// Mirrors the three schemes that the portal-tunnel keyless oracle exposes.
/// Additional schemes (RSA-PKCS1, ECDSA-P384, etc.) are reserved for Phase 6b
/// and are deliberately excluded here so that callers fail at compile time if
/// they attempt to use an unsupported algorithm.
///
/// # Non-exhaustiveness
///
/// `#[non_exhaustive]` allows new variants to be added in later batches without
/// breaking downstream `match` arms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureScheme {
    /// ECDSA over NIST P-256 with SHA-256 digest.
    EcdsaNistP256Sha256,
    /// RSA-PSS with SHA-256 digest.
    RsaPssSha256,
    /// Pure Ed25519 (RFC 8032).
    Ed25519,
}

// ---------------------------------------------------------------------------
// SigningInput
// ---------------------------------------------------------------------------

/// Input bundle passed to [`KeylessSigningKey::sign`].
///
/// Bundles the raw message bytes together with the requested signature scheme
/// so that the signing key can reject unsupported algorithms before attempting
/// any cryptographic work.
#[derive(Debug)]
pub struct SigningInput<'a> {
    /// The raw message bytes to sign.  The caller is responsible for any
    /// pre-hashing or domain separation that the higher-level protocol requires.
    pub message: &'a [u8],
    /// The requested signature algorithm.
    pub scheme: SignatureScheme,
}

// ---------------------------------------------------------------------------
// KeylessError
// ---------------------------------------------------------------------------

/// Errors that can arise during a keyless signing operation.
///
/// # Non-exhaustiveness
///
/// `#[non_exhaustive]` allows new variants to be added without breaking
/// existing downstream `match` arms.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum KeylessError {
    /// The requested signature scheme is not supported by this key.
    #[error("unsupported scheme: {0:?}")]
    UnsupportedScheme(SignatureScheme),

    /// The underlying signing operation failed (e.g., hardware fault, RNG
    /// failure, or invalid key material at runtime).
    #[error("signing failed: {0}")]
    SignFailed(String),

    /// The key material is invalid or could not be parsed.
    #[error("invalid key material: {0}")]
    InvalidKey(String),
}

impl From<KeylessError> for PortalCryptoError {
    fn from(e: KeylessError) -> Self {
        Self::Keyless(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// KeylessSigningKey trait
// ---------------------------------------------------------------------------

/// A sync-only signing key abstraction for the keyless oracle.
///
/// Any type that wraps a private key — software, HSM-backed, or remote — must
/// implement this trait to participate in the keyless signing protocol.
///
/// # Object safety
///
/// The trait is object-safe so that `Box<dyn KeylessSigningKey>` and
/// `Arc<dyn KeylessSigningKey>` can be used as trait objects.
///
/// # Thread safety
///
/// The `Send + Sync` bounds ensure that a boxed `KeylessSigningKey` may be
/// shared across thread boundaries without additional locking at the call site.
///
/// # No async
///
/// Per FEAS-2, there is **no** `async fn sign`.  See the module-level doc for
/// the rationale.
pub trait KeylessSigningKey: Send + Sync {
    /// Sign `input.message` using `input.scheme`.
    ///
    /// # Errors
    ///
    /// Returns [`KeylessError::UnsupportedScheme`] when `input.scheme` is not
    /// in `self.supported_schemes()`.
    /// Returns [`KeylessError::SignFailed`] when the cryptographic operation
    /// itself fails.
    fn sign(&self, input: &SigningInput<'_>) -> Result<Vec<u8>, KeylessError>;

    /// Returns the set of [`SignatureScheme`]s that this key supports.
    ///
    /// Callers should check this before constructing a [`SigningInput`] to
    /// avoid a round-trip that ends in [`KeylessError::UnsupportedScheme`].
    fn supported_schemes(&self) -> &[SignatureScheme];

    /// Returns the DER-encoded public key corresponding to this signing key.
    ///
    /// The encoding follows RFC 5480 (`SubjectPublicKeyInfo`) for EC keys and
    /// RFC 3279 for RSA keys.  Ed25519 keys use the RFC 8410 OID.
    fn public_key_der(&self) -> &[u8];
}

// ---------------------------------------------------------------------------
// Compile-time Send + Sync assertions
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::KeylessSigningKey;

    /// Compile-only assertion: `Box<dyn KeylessSigningKey>` must be `Send + Sync`.
    ///
    /// This test has no runtime body — it exists solely so that the compiler
    /// checks the bound.  If the trait loses `Send` or `Sync` this const will
    /// fail to type-check.
    const fn assert_send_sync<T: Send + Sync>() {}
    const _: () = assert_send_sync::<Box<dyn KeylessSigningKey>>();
}
