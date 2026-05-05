//! [`ApiHttpsKey`] newtype + the `signing_key` accessor that hands the
//! wrapped `Arc<dyn rustls::sign::SigningKey>` to the rustls
//! `ServerConfig` builder.
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
/// The PEM-decoding body is not yet wired; until it lands, this function
/// surfaces `PortalCryptoError::Io` for a missing path and
/// [`PortalCryptoError::HttpsKey`] otherwise. The path-existence
/// behavior is pinned by the regression test below; downstream callers
/// can rely on that error shape today.
///
/// The eventual implementation will:
/// 1. Read the file via [`std::fs::read`].
/// 2. Parse PEM → DER via `rustls_pki_types::PrivateKeyDer::from_pem_slice`
///    (the workspace's chosen PEM parser, already used by
///    `portal-relay::keyless::material`).
/// 3. Call `rustls::crypto::aws_lc_rs::sign::any_supported_type` on the
///    resulting `PrivateKeyDer<'static>` to get the `Arc<dyn SigningKey>`.
/// 4. Return `SecretBox::new(Box::new(ApiHttpsKey(arc)))`.
///
/// # Errors
///
/// - [`PortalCryptoError::Io`] — if the file cannot be opened or read.
/// - [`PortalCryptoError::HttpsKey`] — always, until the real loader lands.
pub fn load_api_https_key(path: &Path) -> Result<SecretBox<ApiHttpsKey>, PortalCryptoError> {
    // I/O boundary check, designed to surface every access-failure
    // mode as `PortalCryptoError::Io` without producing a `Vec<u8>`
    // of plaintext key bytes that would sit outside
    // `secrecy`/zeroization. Steps:
    //
    // 1. `File::open(path)?` — catches missing path, permission
    //    denied, ENOTDIR, and other access failures at the syscall
    //    level. Plain `metadata(path)?` would only probe
    //    directory-entry accessibility and would let unreadable
    //    files reach the `HttpsKey` arm with the wrong error type.
    //    `std::fs::read(path)?` would surface the right error
    //    category but at the cost of plaintext residency.
    // 2. Verify the opened handle is a regular file via the
    //    handle's own metadata (no TOCTOU window between this check
    //    and the open). On Unix, `File::open` succeeds for
    //    directories, so without this guard a key path pointing at
    //    a directory would fall through to `HttpsKey` instead of
    //    surfacing as `Io`.
    let file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(PortalCryptoError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "key path is not a regular file",
        )));
    }

    Err(PortalCryptoError::HttpsKey(
        "PEM loading not yet wired".to_owned(),
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
    /// the error is [`PortalCryptoError::Io`]. This pins the path-existence
    /// surface of the stub independently of the eventual PEM-decoding body.
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
