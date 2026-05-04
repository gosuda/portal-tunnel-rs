//! [`ApiHttpsKey`] newtype and its file-backed constructor stub.
//!
//! ## Zeroization design
//!
//! `Arc<dyn rustls::sign::SigningKey>` cannot be zeroed polymorphically
//! through a vtable.  The `Zeroize` implementation on [`ApiHttpsKey`] is
//! therefore a **no-op**.  The *concrete* type that is placed behind the
//! `Arc` must arrange its own zeroing (e.g., via `ZeroizeOnDrop`) before
//! the last `Arc` reference is dropped.
//!
//! This mirrors the pattern used for [`KeylessSigningKeyHandle`][crate::KeylessSigningKeyHandle].
//!
//! ## PEM loading
//!
//! [`load_api_https_key`] is currently a **stub**.  `rustls-pemfile` is not
//! yet pinned in `[workspace.dependencies]`.  Phase 5 will replace the stub
//! with real PEM → DER decoding via `rustls_pemfile::private_key` and will
//! call `rustls::crypto::aws_lc_rs::sign::any_supported_type` to obtain the
//! concrete `Arc<dyn rustls::sign::SigningKey>`.

use std::path::Path;
use std::sync::Arc;

use secrecy::SecretBox;
use zeroize::Zeroize;

use crate::error::PortalCryptoError;

// ---------------------------------------------------------------------------
// ApiHttpsKey
// ---------------------------------------------------------------------------

/// Wraps the rustls-ready signing key for the relay's API HTTPS surface.
///
/// Portal-relay consumes this via [`api_https_signing_key`][crate::api_https_signing_key]
/// to build a [`rustls::ServerConfig`].  The inner
/// `Arc<dyn rustls::sign::SigningKey>` is the exact type that rustls expects
/// in `CertifiedKey::new`.
///
/// # Zeroization caveat
///
/// See the module-level documentation for why `Zeroize` is a no-op here and
/// why the concrete type behind the `Arc` must implement `ZeroizeOnDrop`
/// independently.
pub struct ApiHttpsKey(Arc<dyn rustls::sign::SigningKey>);

/// The `Zeroize` impl is intentionally a no-op.
///
/// `Arc<dyn rustls::sign::SigningKey>` cannot be zeroed polymorphically
/// through a vtable.  The concrete type inside the `Arc` must implement
/// `ZeroizeOnDrop` to ensure secret bytes are wiped on drop.  See the
/// module-level doc for the full rationale.
impl Zeroize for ApiHttpsKey {
    fn zeroize(&mut self) {
        // No-op by design — delegated to Drop on Arc replacement.
        // See module-level documentation for the rationale.
    }
}

// ---------------------------------------------------------------------------
// Constructor (stub)
// ---------------------------------------------------------------------------

/// Load an API HTTPS signing key from a PEM-encoded private key file.
///
/// # Current status — STUB
///
/// `rustls-pemfile` is not yet pinned in `[workspace.dependencies]`.  Until
/// Phase 5 wires the real loader, this function always returns
/// [`PortalCryptoError::HttpsKey`] with a message describing the deferral.
///
/// Phase 5 will replace the stub body with:
/// 1. Read the file via [`std::fs::read`].
/// 2. Parse PEM → DER via `rustls_pemfile::private_key`.
/// 3. Call `rustls::crypto::aws_lc_rs::sign::any_supported_type` on the
///    resulting `PrivateKeyDer<'static>` to get the `Arc<dyn SigningKey>`.
/// 4. Return `SecretBox::new(Box::new(ApiHttpsKey(arc)))`.
///
/// # Errors
///
/// - [`PortalCryptoError::Io`] — if the file cannot be opened or read.
/// - [`PortalCryptoError::HttpsKey`] — always, until Phase 5 (stub).
pub fn load_api_https_key(path: &Path) -> Result<SecretBox<ApiHttpsKey>, PortalCryptoError> {
    // Surface an Io error for a completely missing path so that the mandatory
    // test (`load_api_https_key_returns_error_for_missing_path`) can assert
    // `PortalCryptoError::Io` without requiring `rustls_pemfile`.
    let _ = std::fs::metadata(path)?;

    // STUB: PEM loading not yet wired (Phase 5).
    // rustls-pemfile is not pinned in [workspace.dependencies].
    Err(PortalCryptoError::HttpsKey(
        "PEM loading not yet wired (Phase 5)".to_owned(),
    ))
}

// ---------------------------------------------------------------------------
// Accessor
// ---------------------------------------------------------------------------

/// Extract the inner `Arc<dyn rustls::sign::SigningKey>` for consumption by
/// `rustls::sign::CertifiedKey::new` or `rustls::ServerConfig`.
///
/// The returned `Arc` is a clone of the one held inside `api_key`, so the
/// caller can share it across multiple rustls configurations without copying
/// the secret material.
#[must_use]
pub fn signing_key(api_key: &SecretBox<ApiHttpsKey>) -> Arc<dyn rustls::sign::SigningKey> {
    use secrecy::ExposeSecret;
    Arc::clone(&api_key.expose_secret().0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// Invoke the loader on a path that cannot possibly exist and assert that
    /// the error is [`PortalCryptoError::Io`].
    ///
    /// The PEM stub branch makes a happy-path test impossible without
    /// `rustls-pemfile`; that test is deferred to Phase 5.
    #[test]
    fn load_api_https_key_returns_error_for_missing_path() {
        let missing = PathBuf::from("/nonexistent/portal-test/api-key.pem");
        let result = load_api_https_key(&missing);
        assert!(
            matches!(result, Err(PortalCryptoError::Io(_))),
            "expected PortalCryptoError::Io for missing path, got: {result:?}",
        );
    }
}
