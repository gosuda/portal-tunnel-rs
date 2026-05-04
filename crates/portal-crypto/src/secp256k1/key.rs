//! [`TenantSecp256k1Key`] newtype and its sole file-backed constructor.
//!
//! ## Zeroization design
//!
//! `k256::ecdsa::SigningKey` does not implement `Zeroize` directly (only
//! `ZeroizeOnDrop` via its `Drop` impl).  `secrecy::SecretBox<T>` requires
//! `T: Zeroize`, so we cannot wrap `SigningKey` directly.
//!
//! Instead, `TenantSecp256k1Key` stores the 32-byte secret scalar in a
//! `zeroize::Zeroizing<[u8; 32]>` field, which does implement `Zeroize`.
//! A `SigningKey` is reconstructed on demand via [`TenantSecp256k1Key::signing_key`].

use std::path::Path;

use secrecy::{ExposeSecret, SecretBox};
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use crate::error::PortalCryptoError;
use crate::secret::decode_hex_exact;

// ---------------------------------------------------------------------------
// Newtype
// ---------------------------------------------------------------------------

/// Wrapper around the 32-byte secp256k1 secret scalar representing the
/// tenant's Ethereum / SIWE identity key.
///
/// All access to the secret material is mediated by
/// `secrecy::SecretBox<TenantSecp256k1Key>`.  The only public constructor is
/// [`load_tenant_secp256k1_key`].
pub struct TenantSecp256k1Key(Zeroizing<[u8; 32]>);

impl Zeroize for TenantSecp256k1Key {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl TenantSecp256k1Key {
    /// Reconstruct the ephemeral [`k256::ecdsa::SigningKey`] from the stored
    /// secret scalar.  The returned key is `ZeroizeOnDrop`.
    ///
    /// # Errors
    ///
    /// Returns [`PortalCryptoError::Secp256k1`] if the stored bytes do not
    /// constitute a valid secp256k1 scalar (e.g. all-zero or out-of-range).
    pub(super) fn signing_key(&self) -> Result<k256::ecdsa::SigningKey, PortalCryptoError> {
        k256::ecdsa::SigningKey::from_slice(&self.0[..])
            .map_err(|e| PortalCryptoError::Secp256k1(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// JSON loader shape
// ---------------------------------------------------------------------------

/// Deserialisation target for the on-disk secp256k1 identity JSON.
///
/// `deny_unknown_fields` enforces the single-field contract: a file that
/// contains `ed25519_secret_key` or any other unexpected field is rejected,
/// preventing accidental cross-loading of mixed-role identity files.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSecp256k1KeyFile {
    /// 32-byte secret scalar encoded as a 64-character lowercase hex string.
    #[serde(deserialize_with = "deserialize_zeroizing_string")]
    secp256k1_secret_key: Zeroizing<String>,
}

/// Serde visitor that deserialises a JSON string into `Zeroizing<String>`.
fn deserialize_zeroizing_string<'de, D>(d: D) -> Result<Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    Ok(Zeroizing::new(s))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load the tenant's secp256k1 signing key from a JSON file.
///
/// The file must contain a JSON object with a single field:
///
/// ```json
/// { "secp256k1_secret_key": "<64 lowercase hex chars>" }
/// ```
///
/// The all-zero scalar is rejected (`requireNonZero` port from Go's
/// `portal-tunnel/utils/crypto.go`).
///
/// All intermediate secret material is wrapped in [`Zeroizing`] so it is
/// wiped from memory as soon as it goes out of scope.
///
/// # Errors
///
/// - [`PortalCryptoError::Io`] — file read failure.
/// - [`PortalCryptoError::Secp256k1`] — JSON parse failure, hex decode
///   failure, length mismatch, all-zero scalar, or unknown fields in the
///   key file.
pub fn load_tenant_secp256k1_key(
    path: &Path,
) -> Result<SecretBox<TenantSecp256k1Key>, PortalCryptoError> {
    let data: Zeroizing<Vec<u8>> = Zeroizing::new(std::fs::read(path)?);

    let raw: RawSecp256k1KeyFile =
        serde_json::from_slice(&data).map_err(|e| PortalCryptoError::Secp256k1(e.to_string()))?;

    let scalar =
        decode_hex_exact::<32>(&raw.secp256k1_secret_key).map_err(PortalCryptoError::Secp256k1)?;

    // Port of Go's requireNonZero: reject the all-zero scalar.
    if scalar.iter().all(|&b| b == 0) {
        return Err(PortalCryptoError::Secp256k1(
            "zero secret scalar".to_owned(),
        ));
    }

    Ok(SecretBox::new(Box::new(TenantSecp256k1Key(scalar))))
}

/// Extract the [`k256::PublicKey`] from a loaded tenant signing key.
///
/// This is the only way to obtain the public half of a [`TenantSecp256k1Key`].
///
/// # Errors
///
/// Returns [`PortalCryptoError::Secp256k1`] if the stored scalar is invalid
/// (should not occur for keys produced by [`load_tenant_secp256k1_key`]).
pub fn public_key(
    key: &SecretBox<TenantSecp256k1Key>,
) -> Result<k256::PublicKey, PortalCryptoError> {
    let sk = key.expose_secret().signing_key()?;
    Ok(sk.verifying_key().into())
}

// ---------------------------------------------------------------------------
// Test-only helpers
// ---------------------------------------------------------------------------

/// Construct a [`SecretBox<TenantSecp256k1Key>`] deterministically from a
/// 32-byte secret scalar.
///
/// Not part of the public production API.  Gated on `cfg(test)` (for unit
/// tests within this crate) and the `insecure-test-constructors` feature (for
/// integration tests in `tests/` and external test harnesses that activate it).
/// The `#[doc(hidden)]` attribute suppresses it from published rustdoc.
///
/// Panics if `seed` is all-zero (invalid scalar), because test code that
/// passes an all-zero seed has a bug.
#[cfg(any(test, feature = "insecure-test-constructors"))]
#[doc(hidden)]
#[must_use]
pub fn from_bytes_for_test(seed: [u8; 32]) -> SecretBox<TenantSecp256k1Key> {
    assert!(
        seed.iter().any(|&b| b != 0),
        "from_bytes_for_test: all-zero scalar is invalid"
    );
    SecretBox::new(Box::new(TenantSecp256k1Key(Zeroizing::new(seed))))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn scalar_hex(scalar: &[u8; 32]) -> String {
        use std::fmt::Write as _;
        scalar.iter().fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    const TEST_SCALAR: [u8; 32] = [
        0x4c, 0x08, 0x83, 0xa6, 0x91, 0x02, 0x93, 0x7d, 0x62, 0x31, 0x47, 0x1b, 0x5d, 0xbb, 0x62,
        0x04, 0xfe, 0x51, 0x29, 0x61, 0x70, 0x82, 0x79, 0x2a, 0xe4, 0x68, 0xd0, 0x1a, 0x3f, 0x36,
        0x23, 0x18,
    ];

    #[test]
    fn load_round_trip_produces_matching_public_key() -> Result<(), Box<dyn std::error::Error>> {
        let json = format!(
            r#"{{"secp256k1_secret_key": "{}"}}"#,
            scalar_hex(&TEST_SCALAR)
        );

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("key.json");
        std::fs::File::create(&path)?.write_all(json.as_bytes())?;

        let secret_box = load_tenant_secp256k1_key(&path)?;
        let pk = public_key(&secret_box)?;

        let sk_ref = k256::ecdsa::SigningKey::from_slice(&TEST_SCALAR)?;
        let pk_ref: k256::PublicKey = sk_ref.verifying_key().into();
        assert_eq!(pk, pk_ref);
        Ok(())
    }

    #[test]
    fn load_rejects_zero_scalar() -> Result<(), Box<dyn std::error::Error>> {
        let zero_hex = "00".repeat(32);
        let json = format!(r#"{{"secp256k1_secret_key": "{zero_hex}"}}"#);
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("zero.json");
        std::fs::File::create(&path)?.write_all(json.as_bytes())?;
        let result = load_tenant_secp256k1_key(&path);
        assert!(
            matches!(result, Err(PortalCryptoError::Secp256k1(ref msg)) if msg.contains("zero")),
            "expected zero-scalar rejection, got: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn load_rejects_wrong_length_hex() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("short.json");
        std::fs::File::create(&path)?.write_all(br#"{"secp256k1_secret_key": "aabbccdd"}"#)?;
        let result = load_tenant_secp256k1_key(&path);
        assert!(
            matches!(result, Err(PortalCryptoError::Secp256k1(_))),
            "unexpected result: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn load_rejects_unknown_fields() -> Result<(), Box<dyn std::error::Error>> {
        let hex64 = scalar_hex(&TEST_SCALAR);
        let json =
            format!(r#"{{"secp256k1_secret_key": "{hex64}", "ed25519_secret_key": "{hex64}"}}"#);
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("mixed.json");
        std::fs::File::create(&path)?.write_all(json.as_bytes())?;
        let result = load_tenant_secp256k1_key(&path);
        assert!(
            matches!(result, Err(PortalCryptoError::Secp256k1(_))),
            "unexpected result: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn from_bytes_for_test_matches_k256_directly() -> Result<(), Box<dyn std::error::Error>> {
        let secret_box = from_bytes_for_test(TEST_SCALAR);
        let pk = public_key(&secret_box)?;
        let sk_ref = k256::ecdsa::SigningKey::from_slice(&TEST_SCALAR)?;
        let pk_ref: k256::PublicKey = sk_ref.verifying_key().into();
        assert_eq!(pk, pk_ref);
        Ok(())
    }
}
