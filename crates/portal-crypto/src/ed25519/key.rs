//! [`RelayEd25519Key`] newtype and its sole file-backed constructor.
//!
//! ## Zeroization design
//!
//! `ed25519_dalek::SigningKey` implements `ZeroizeOnDrop` (via its `Drop`
//! impl when the `zeroize` feature is enabled) but does **not** implement
//! `Zeroize` directly.  `secrecy::SecretBox<T>` requires `T: Zeroize`, so we
//! cannot wrap `SigningKey` directly.
//!
//! Instead, `RelayEd25519Key` stores the 32-byte seed in a
//! `zeroize::Zeroizing<[u8; 32]>` field, which does implement `Zeroize`.
//! A `SigningKey` is reconstructed from the seed on each call to
//! [`RelayEd25519Key::signing_key`].  The reconstruction is cheap (one scalar
//! multiply) and only happens inside signing operations.

use secrecy::{ExposeSecret, SecretBox};
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use crate::error::PortalCryptoError;
use crate::secret::decode_hex_exact;

// ---------------------------------------------------------------------------
// Newtype
// ---------------------------------------------------------------------------

/// Wrapper around the 32-byte ed25519 seed that represents the relay's
/// protocol-identity key.
///
/// All access to the secret material is mediated by
/// `secrecy::SecretBox<RelayEd25519Key>`.  The only public constructor is
/// [`load_relay_ed25519_key`].
pub struct RelayEd25519Key(Zeroizing<[u8; 32]>);

impl Zeroize for RelayEd25519Key {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl RelayEd25519Key {
    /// Reconstruct the ephemeral [`ed25519_dalek::SigningKey`] from the stored
    /// seed.  The returned key implements `ZeroizeOnDrop`, so secret bytes are
    /// wiped when it is dropped.
    pub(super) fn signing_key(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&self.0)
    }
}

// ---------------------------------------------------------------------------
// JSON loader shape
// ---------------------------------------------------------------------------

/// Deserialisation target for the on-disk identity JSON.
///
/// The `String` field is wrapped in [`Zeroizing`] so the hex text is wiped
/// from the heap as soon as this value is dropped.
///
/// `deny_unknown_fields` enforces the single-field contract: a file that
/// contains `secp256k1_secret_key` or any other unexpected field is rejected,
/// preventing accidental cross-loading of mixed-role identity files.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEd25519KeyFile {
    /// 32-byte secret key encoded as a 64-character lowercase hex string.
    #[serde(deserialize_with = "deserialize_zeroizing_string")]
    ed25519_secret_key: Zeroizing<String>,
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

/// Load the relay's ed25519 signing key from a JSON file.
///
/// The file must contain a JSON object with a single field:
///
/// ```json
/// { "ed25519_secret_key": "<64 lowercase hex chars>" }
/// ```
///
/// The field name `ed25519_secret_key` differs from the Go upstream's
/// `private_key` field because the Rust port deliberately splits ed25519
/// (protocol identity) and secp256k1 (Ethereum / SIWE) into separate files
/// and loader functions.  Using distinct field names prevents accidental
/// cross-loading.
///
/// All intermediate secret material (`Vec<u8>` file bytes, hex `String`, and
/// the decoded seed array) is wrapped in [`Zeroizing`] so it is wiped from
/// memory as soon as it goes out of scope.
///
/// # Errors
///
/// - [`PortalCryptoError::Io`] — file read failure.
/// - [`PortalCryptoError::Ed25519`] — JSON parse failure, hex decode failure,
///   length mismatch, or unknown fields in the key file.
pub fn load_relay_ed25519_key(
    path: &std::path::Path,
) -> Result<SecretBox<RelayEd25519Key>, PortalCryptoError> {
    // Read raw bytes; wrap in Zeroizing so the file content is wiped on drop.
    let data: Zeroizing<Vec<u8>> = Zeroizing::new(std::fs::read(path)?);

    let raw: RawEd25519KeyFile =
        serde_json::from_slice(&data).map_err(|e| PortalCryptoError::Ed25519(e.to_string()))?;
    // `data` is still live here; both are dropped (and zeroized) at end of scope.

    // `seed` is `Zeroizing<[u8; 32]>` — wiped on drop.
    let seed =
        decode_hex_exact::<32>(&raw.ed25519_secret_key).map_err(PortalCryptoError::Ed25519)?;
    Ok(SecretBox::new(Box::new(RelayEd25519Key(seed))))
}

/// Extract the [`ed25519_dalek::VerifyingKey`] (public key) from a loaded
/// relay signing key.
///
/// This is the only way to obtain the public half of a [`RelayEd25519Key`].
#[must_use]
pub fn verifying_key(key: &SecretBox<RelayEd25519Key>) -> ed25519_dalek::VerifyingKey {
    key.expose_secret().signing_key().verifying_key()
}

// ---------------------------------------------------------------------------
// Test-only helpers
// ---------------------------------------------------------------------------

/// Construct a [`SecretBox<RelayEd25519Key>`] deterministically from a 32-byte
/// seed.
///
/// Not part of the public production API.  Gated on `cfg(test)` (for unit
/// tests within this crate) and the `insecure-test-constructors` feature (for
/// integration tests in `tests/` and external test harnesses that activate it).
/// The `#[doc(hidden)]` attribute suppresses it from published rustdoc.
///
/// Used by the Phase 2 Batch 8 proptest suite (`tests/ed25519_roundtrip.rs`)
/// and SIWE binding integration tests (`tests/siwe_binding.rs`).
#[cfg(any(test, feature = "insecure-test-constructors"))]
#[doc(hidden)]
#[must_use]
pub fn from_seed_for_test(seed: [u8; 32]) -> SecretBox<RelayEd25519Key> {
    SecretBox::new(Box::new(RelayEd25519Key(Zeroizing::new(seed))))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn seed_hex(seed: &[u8; 32]) -> String {
        use std::fmt::Write as _;
        seed.iter().fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    #[test]
    fn load_round_trip_produces_matching_verifying_key() -> Result<(), Box<dyn std::error::Error>> {
        let seed: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0x44, 0xc2, 0xaa, 0x4d, 0x99, 0xfe, 0x3c, 0xc7, 0xcb, 0x5a, 0xb9, 0xdf, 0xe8,
            0x33, 0x72, 0x35, 0x1d,
        ];
        let json = format!(r#"{{"ed25519_secret_key": "{}"}}"#, seed_hex(&seed));

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("key.json");
        std::fs::File::create(&path)?.write_all(json.as_bytes())?;

        let secret_box = load_relay_ed25519_key(&path)?;
        let vk = verifying_key(&secret_box);

        let sk_ref = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(vk, sk_ref.verifying_key());
        Ok(())
    }

    #[test]
    fn load_rejects_wrong_length_hex() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("key.json");
        // 4 bytes of hex — far too short for a 32-byte key.
        std::fs::File::create(&path)?.write_all(br#"{"ed25519_secret_key": "aabbccdd"}"#)?;
        let result = load_relay_ed25519_key(&path);
        assert!(
            matches!(result, Err(crate::error::PortalCryptoError::Ed25519(_))),
            "unexpected result: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn load_rejects_unknown_fields() -> Result<(), Box<dyn std::error::Error>> {
        // A mixed-role file with both ed25519 and secp256k1 keys must be rejected
        // to enforce the single-field identity-file contract.
        let hex = "9d61b19deffd5a60ba844af492ec2c44c2aa4d99fe3cc7cb5ab9dfe833723510d";
        // Pad to 64 chars (32 bytes).
        let hex64 = &hex[..64];
        let json =
            format!(r#"{{"ed25519_secret_key": "{hex64}", "secp256k1_secret_key": "{hex64}"}}"#);
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("mixed.json");
        std::fs::File::create(&path)?.write_all(json.as_bytes())?;
        let result = load_relay_ed25519_key(&path);
        assert!(
            matches!(result, Err(crate::error::PortalCryptoError::Ed25519(_))),
            "unexpected result: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn from_seed_for_test_matches_dalek_directly() {
        let seed = [0x42u8; 32];
        let secret_box = from_seed_for_test(seed);
        let vk = verifying_key(&secret_box);
        let sk_ref = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(vk, sk_ref.verifying_key());
    }
}
