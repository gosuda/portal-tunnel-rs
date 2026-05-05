//! [`KeylessSigningKeyHandle`] newtype and its file-backed constructor stub.
//!
//! ## Zeroization design
//!
//! `Box<dyn KeylessSigningKey>` cannot implement `Zeroize` polymorphically
//! because `Zeroize` requires a concrete `&mut self` method, and calling it
//! through a vtable on an arbitrary `dyn` type gives no compile-time guarantee
//! that the memory was actually wiped.
//!
//! As a result, the `Zeroize` implementation on `KeylessSigningKeyHandle` is a
//! **no-op**.  The responsibility for zeroing secret material rests with the
//! *concrete* type that implements [`KeylessSigningKey`] — that type should
//! derive or implement [`ZeroizeOnDrop`][zeroize::ZeroizeOnDrop] independently.
//!
//! This mirrors the pattern used by [`crate::ed25519::key::RelayEd25519Key`]
//! and [`crate::secp256k1::key::TenantSecp256k1Key`].
//!
//! ## PEM loading
//!
//! [`load_keyless_signing_key`] is currently a **stub** for the
//! file-path-based public API. The eventual implementation will use
//! `rustls_pki_types::PrivateKeyDer::from_pem_slice` to decode PEM →
//! DER and then dispatch the concrete key type based on the detected
//! algorithm OID.

use std::path::Path;

use secrecy::SecretBox;
use zeroize::Zeroize;

use super::trait_def::KeylessSigningKey;
use crate::error::PortalCryptoError;

// ---------------------------------------------------------------------------
// KeylessSigningKeyHandle
// ---------------------------------------------------------------------------

/// Opaque handle to a heap-allocated [`KeylessSigningKey`] trait object.
///
/// Callers obtain instances either through [`load_keyless_signing_key`] (file
/// path) or through `handle_for_test` (test-only, `#[cfg(test)]` —
/// doesn't render in standard rustdoc).  The inner
/// `Box<dyn KeylessSigningKey>` is sealed behind a [`SecretBox`] so that
/// debug-printing does not accidentally leak key material.
///
/// # Zeroization caveat
///
/// See the module-level documentation for why `Zeroize` is a no-op here and
/// why the concrete type must implement `ZeroizeOnDrop` independently.
pub struct KeylessSigningKeyHandle(Box<dyn KeylessSigningKey>);

impl KeylessSigningKeyHandle {
    /// Delegates a sign call to the inner trait object.
    ///
    /// This is the primary entry point for code that holds a
    /// `SecretBox<KeylessSigningKeyHandle>` and needs to produce a signature.
    ///
    /// # Errors
    ///
    /// Propagates [`super::trait_def::KeylessError`] from the inner
    /// [`KeylessSigningKey::sign`] implementation unchanged.
    pub fn sign(
        &self,
        input: &super::trait_def::SigningInput<'_>,
    ) -> Result<Vec<u8>, super::trait_def::KeylessError> {
        self.0.sign(input)
    }

    /// Returns the supported schemes of the inner key.
    #[must_use]
    pub fn supported_schemes(&self) -> &[super::trait_def::SignatureScheme] {
        self.0.supported_schemes()
    }

    /// Returns the DER-encoded public key of the inner key.
    #[must_use]
    pub fn public_key_der(&self) -> &[u8] {
        self.0.public_key_der()
    }
}

/// The `Zeroize` impl is intentionally a no-op.
///
/// `Box<dyn KeylessSigningKey>` cannot be zeroed polymorphically through a
/// vtable.  The *concrete* type inside the box must implement
/// [`ZeroizeOnDrop`][zeroize::ZeroizeOnDrop] to ensure secret bytes are wiped
/// on drop.  See the module-level doc for the full rationale.
impl Zeroize for KeylessSigningKeyHandle {
    fn zeroize(&mut self) {
        // No-op by design.  See module-level documentation for the rationale.
    }
}

// ---------------------------------------------------------------------------
// Constructor (stub)
// ---------------------------------------------------------------------------

/// Load a keyless signing key from a PEM-encoded private key file.
///
/// # Current status — STUB
///
/// The PEM-decoding body is not yet wired; this function always returns
/// [`PortalCryptoError::Keyless`] with a message describing the deferral.
///
/// The eventual implementation will:
/// 1. Open the file at the syscall boundary so any access failure
///    (missing path, permission denied, ENOTDIR) surfaces as
///    [`PortalCryptoError::Io`].
/// 2. Read the PEM bytes into a `Zeroizing<Vec<u8>>` (or
///    equivalent) so the buffer wipes on drop after parsing.
/// 3. Parse PEM → DER via `rustls_pki_types::PrivateKeyDer::from_pem_slice`.
/// 4. Dispatch to a concrete `KeylessSigningKey` impl based on algorithm OID
///    (Ed25519 first; RSA-PSS and ECDSA-P256 follow).
/// 5. Return `SecretBox::new(Box::new(KeylessSigningKeyHandle(boxed)))`.
///
/// # Errors
///
/// Always returns [`PortalCryptoError::Keyless`] today; the eventual
/// implementation also surfaces [`PortalCryptoError::Io`] for path-
/// access failures (per step 1 above).
pub fn load_keyless_signing_key(
    _path: &Path,
) -> Result<SecretBox<KeylessSigningKeyHandle>, PortalCryptoError> {
    // Note: unlike `load_api_https_key`, this stub does not probe the
    // path. Adding a `File::open` boundary check here would be the
    // mechanical port of the api_https approach; it lands when the
    // real PEM-decoding body lands, alongside a regression test that
    // pins the `Io` error category.
    Err(PortalCryptoError::Keyless(
        "PEM loading not yet wired".to_owned(),
    ))
}

// ---------------------------------------------------------------------------
// Test helper
// ---------------------------------------------------------------------------

/// Construct a `SecretBox<KeylessSigningKeyHandle>` from an arbitrary
/// `Box<dyn KeylessSigningKey>` for use in unit tests.
///
/// This function is **test-only** (`#[cfg(test)]`).  It provides Phase 6b
/// tests with a back-door constructor that bypasses the file loader.
#[cfg(test)]
pub fn handle_for_test(boxed: Box<dyn KeylessSigningKey>) -> SecretBox<KeylessSigningKeyHandle> {
    SecretBox::new(Box::new(KeylessSigningKeyHandle(boxed)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyless::trait_def::{KeylessError, SignatureScheme, SigningInput};

    /// A minimal test double that implements [`KeylessSigningKey`].
    struct NoopKey;

    impl KeylessSigningKey for NoopKey {
        fn sign(&self, _input: &SigningInput<'_>) -> Result<Vec<u8>, KeylessError> {
            Ok(vec![])
        }

        fn supported_schemes(&self) -> &[SignatureScheme] {
            &[SignatureScheme::Ed25519]
        }

        fn public_key_der(&self) -> &[u8] {
            &[]
        }
    }

    impl Zeroize for NoopKey {
        fn zeroize(&mut self) {}
    }

    /// Smoke test: construct a `SecretBox<KeylessSigningKeyHandle>` via
    /// `handle_for_test`, then drop it without panicking.
    ///
    /// This verifies that the no-op `Zeroize` impl is accepted by
    /// `SecretBox` and that drop order is sound.
    #[test]
    fn keyless_handle_zeroize_compiles() {
        let handle = handle_for_test(Box::new(NoopKey));
        drop(handle);
        // No panic ⟹ test passes.
    }
}
