//! `QuicIdentityKey` newtype + PKCS#8-backed load/generate/save.
//!
//! Mirrors the Phase 2 `RelayEd25519Key` pattern: stores the 32-byte ed25519
//! seed in `Zeroizing<[u8; 32]>` (since `ed25519_dalek::SigningKey` implements
//! `ZeroizeOnDrop` but not `Zeroize` directly, and `SecretBox<T>` requires
//! `T: Zeroize`).

use std::path::Path;

use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::{Zeroize, Zeroizing};

use crate::error::NetError;

/// Wraps the 32-byte ed25519 seed for the QUIC endpoint identity (R2 surface 3).
pub struct QuicIdentityKey(Zeroizing<[u8; 32]>);

impl Zeroize for QuicIdentityKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl QuicIdentityKey {
    /// Reconstruct the ephemeral [`ed25519_dalek::SigningKey`] from the stored
    /// seed. The returned key implements `ZeroizeOnDrop`.
    pub(super) fn signing_key(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&self.0)
    }
}

/// Load a `QuicIdentityKey` from a PKCS#8 DER file.
///
/// # Errors
///
/// Returns [`NetError::IdentityLoad`] for any I/O or PKCS#8 decode failure
/// (the I/O variant is intentionally remapped here to enforce the spec
/// invariant that ed25519 key loading surfaces a single error variant).
pub fn load_quic_key(path: &Path) -> Result<SecretBox<QuicIdentityKey>, NetError> {
    let data: Zeroizing<Vec<u8>> = Zeroizing::new(
        std::fs::read(path).map_err(|e| NetError::IdentityLoad(format!("read failed: {e}")))?,
    );
    let sk = ed25519_dalek::SigningKey::from_pkcs8_der(&data)
        .map_err(|e| NetError::IdentityLoad(format!("PKCS#8 decode failed: {e}")))?;
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(sk.to_bytes());
    Ok(SecretBox::new(Box::new(QuicIdentityKey(seed))))
}

/// Generate a fresh `QuicIdentityKey` using the OS RNG.
#[must_use]
pub fn generate_quic_key() -> SecretBox<QuicIdentityKey> {
    let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(sk.to_bytes());
    SecretBox::new(Box::new(QuicIdentityKey(seed)))
}

/// Save a `QuicIdentityKey` to disk in PKCS#8 DER format with 0600 perms (Unix).
///
/// Uses atomic write: creates a uniquely-named sibling temp file with
/// `create_new(true)`, fsyncs, then renames atomically over `path`.
///
/// # Errors
///
/// Returns [`NetError::IdentityLoad`] on PKCS#8 encode failure or
/// [`NetError::Io`] on filesystem failure.
pub fn save_quic_key(key: &SecretBox<QuicIdentityKey>, path: &Path) -> Result<(), NetError> {
    use std::io::Write as _;

    let sk = key.expose_secret().signing_key();
    let der = sk
        .to_pkcs8_der()
        .map_err(|e| NetError::IdentityLoad(format!("PKCS#8 encode failed: {e}")))?;
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(der.as_bytes().to_vec());

    // Build a unique sibling temp path via OS RNG nonce.
    // `create_new(true)` prevents reuse of an existing path (no TOCTOU).
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp_path = unique_sibling_tmp(parent);

    // Inner closure so we can clean up on error.
    let write_result = (|| -> Result<(), NetError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut f = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&tmp_path)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            let mut f = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&tmp_path)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    })();

    if write_result.is_err() {
        // Best-effort cleanup; ignore secondary errors.
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_result
}

/// Return a path like `<dir>/.portal-net-tmp-<16-hex-chars>` that does not
/// yet exist. The caller must open it with `create_new(true)`.
fn unique_sibling_tmp(dir: &Path) -> std::path::PathBuf {
    use std::fmt::Write as _;
    let mut nonce = [0u8; 8];
    OsRng.fill_bytes(&mut nonce);
    let mut hex = String::with_capacity(16);
    for b in nonce {
        let _ = write!(hex, "{b:02x}");
    }
    dir.join(format!(".portal-net-tmp-{hex}"))
}

/// Extract the public verifying key from a loaded identity.
#[must_use]
pub fn verifying_key(key: &SecretBox<QuicIdentityKey>) -> ed25519_dalek::VerifyingKey {
    key.expose_secret().signing_key().verifying_key()
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "tests use unwrap on tempdir + key derivations with deterministic inputs"
)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_extract_pubkey_nonzero() {
        let key = generate_quic_key();
        let vk = verifying_key(&key);
        assert_ne!(vk.to_bytes(), [0u8; 32]);
    }

    #[test]
    fn round_trip_save_then_load_yields_same_pubkey() {
        let key = generate_quic_key();
        let expected = verifying_key(&key);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("quic.der");
        save_quic_key(&key, &path).unwrap();
        let loaded = load_quic_key(&path).unwrap();
        assert_eq!(expected, verifying_key(&loaded));
    }

    #[test]
    fn load_missing_path_returns_identity_load_error() {
        let result = load_quic_key(Path::new("/nonexistent/path/quic.der"));
        assert!(matches!(result, Err(NetError::IdentityLoad(_))));
    }

    #[test]
    fn load_malformed_pkcs8_returns_identity_load_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.der");
        std::fs::write(&path, b"not pkcs8").unwrap();
        let result = load_quic_key(&path);
        assert!(matches!(result, Err(NetError::IdentityLoad(_))));
    }
}
