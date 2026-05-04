//! EVM address derivation and EIP-55 mixed-case checksum encoding.
//!
//! [`evm_address_from_pubkey`] ports `AddressFromCompressedPublicKeyHex` from
//! `portal-tunnel/utils/crypto.go`.  The derivation is:
//!
//! 1. Serialize the public key as **uncompressed** SEC1 (65 bytes).
//! 2. Drop the leading `0x04` byte, leaving 64 bytes (`X || Y`).
//! 3. Apply Keccak-256 (the pre-NIST variant, `sha3.NewLegacyKeccak256` in Go)
//!    to the 64-byte input.
//! 4. Take the trailing 20 bytes of the 32-byte digest as the raw address.
//!
//! [`EthAddress::fmt`] (via `Display`) produces the EIP-55 mixed-case
//! checksum form, e.g. `0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed`.

use std::fmt;

use k256::elliptic_curve::sec1::ToEncodedPoint as _;

// ---------------------------------------------------------------------------
// EthAddress newtype
// ---------------------------------------------------------------------------

/// A 20-byte Ethereum address.
///
/// `Display` and `Debug` both emit the EIP-55 mixed-case checksum form with a
/// `0x` prefix (e.g. `0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EthAddress([u8; 20]);

impl EthAddress {
    /// Construct an [`EthAddress`] from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Return a reference to the underlying 20 raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl fmt::Display for EthAddress {
    /// Emit the EIP-55 mixed-case checksum address with a `0x` prefix.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&eip55_checksum(self))
    }
}

impl fmt::Debug for EthAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Intentionally identical to Display so debug output is human-readable.
        fmt::Display::fmt(self, f)
    }
}

// ---------------------------------------------------------------------------
// EIP-55 checksum helper
// ---------------------------------------------------------------------------

/// Produce the EIP-55 mixed-case checksum string (with `0x` prefix) for the
/// given address.
///
/// Algorithm:
/// 1. Lowercase-hex-encode the 20 raw bytes (40 chars, no prefix).
/// 2. Keccak-256 hash that 40-character ASCII string.
/// 3. For each of the 40 hex characters, check the corresponding nibble of
///    the hash: if the nibble is `≥ 8`, uppercase the character.
/// 4. Prepend `0x`.
fn eip55_checksum(addr: &EthAddress) -> String {
    // Step 1: lowercase hex encoding of the raw bytes (40 ASCII chars).
    let mut hex_chars = [0u8; 40];
    for (i, &byte) in addr.0.iter().enumerate() {
        hex_chars[i * 2] = nibble_to_hex_lower(byte >> 4);
        hex_chars[i * 2 + 1] = nibble_to_hex_lower(byte & 0x0f);
    }

    // Step 2: Keccak-256 of the lowercase ASCII hex string.
    let hash = alloy::primitives::keccak256(hex_chars);

    // Step 3: conditionally uppercase each hex character.
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, &ch) in hex_chars.iter().enumerate() {
        // Each hash byte covers two hex nibbles; nibble index `i` maps to
        // byte `i/2`, and the high nibble of that byte for even `i`, the
        // low nibble for odd `i`.
        let hash_nibble = if i % 2 == 0 {
            hash[i / 2] >> 4
        } else {
            hash[i / 2] & 0x0f
        };
        if hash_nibble >= 8 && ch.is_ascii_lowercase() {
            out.push(ch.to_ascii_uppercase() as char);
        } else {
            out.push(ch as char);
        }
    }
    out
}

/// Convert a nibble (0–15) to its lowercase ASCII hex character.
const fn nibble_to_hex_lower(n: u8) -> u8 {
    if n < 10 { b'0' + n } else { b'a' + n - 10 }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Derive the EVM address from a secp256k1 public key.
///
/// Ports `AddressFromCompressedPublicKeyHex` from
/// `portal-tunnel/utils/crypto.go`.
///
/// Steps:
/// 1. Serialize `pk` as uncompressed SEC1 (65 bytes: `0x04 || X || Y`).
/// 2. Drop the leading `0x04` byte.
/// 3. Keccak-256 the remaining 64 bytes.
/// 4. Take the trailing 20 bytes as the raw Ethereum address.
#[must_use]
pub fn evm_address_from_pubkey(pk: &k256::PublicKey) -> EthAddress {
    // Uncompressed SEC1: 0x04 || X(32) || Y(32) = 65 bytes.
    let encoded = pk.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    // bytes[0] == 0x04; bytes[1..65] == X || Y.
    let xy = &bytes[1..65];

    let hash = alloy::primitives::keccak256(xy);

    // Trailing 20 bytes of the 32-byte digest.
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    EthAddress(addr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a lowercase hex string (no `0x` prefix) into exactly `N` bytes.
    /// Panics on invalid input — test code only.
    fn hex_to_bytes<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), N * 2, "hex string length mismatch");
        let mut out = [0u8; N];
        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            let hi = pair[0];
            let lo = pair[1];
            let decode_nibble = |b: u8| -> u8 {
                match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    b'A'..=b'F' => b - b'A' + 10,
                    _ => panic!("invalid hex char"),
                }
            };
            out[i] = (decode_nibble(hi) << 4) | decode_nibble(lo);
        }
        out
    }

    /// The four canonical EIP-55 reference vectors from the Ethereum Foundation.
    /// <https://eips.ethereum.org/EIPS/eip-55#test-cases>
    const EIP55_VECTORS: &[&str] = &[
        "0x52908400098527886E0F7030069857D2E4169EE7",
        "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
        "0xde709f2102306220921060314715629080e2fb77",
        "0x27b1fdb04752bbc536007a920d24acb045561c26",
    ];

    #[test]
    fn eip55_checksum_matches_reference_vectors() {
        for &canonical in EIP55_VECTORS {
            // Strip "0x" and decode the raw 20 bytes ignoring case.
            let hex_no_prefix = &canonical[2..];
            let lower: String = hex_no_prefix.to_lowercase();
            let raw = hex_to_bytes::<20>(&lower);
            let addr = EthAddress::new(raw);
            let formatted = format!("{addr}");
            assert_eq!(
                formatted, canonical,
                "EIP-55 mismatch for vector {canonical}: got {formatted}"
            );
        }
    }

    #[test]
    fn display_and_debug_agree() {
        let raw = hex_to_bytes::<20>("27b1fdb04752bbc536007a920d24acb045561c26");
        let addr = EthAddress::new(raw);
        assert_eq!(format!("{addr}"), format!("{addr:?}"));
    }

    #[test]
    fn evm_address_from_pubkey_has_correct_length() {
        // Use a known non-zero scalar to generate a public key.
        let scalar = [0x4cu8; 32];
        let sk = match k256::ecdsa::SigningKey::from_slice(&scalar) {
            Ok(k) => k,
            Err(e) => panic!("test scalar should be valid: {e}"),
        };
        let pk: k256::PublicKey = sk.verifying_key().into();
        let addr = evm_address_from_pubkey(&pk);
        // The address string is always "0x" + 40 hex chars = 42 chars.
        assert_eq!(format!("{addr}").len(), 42);
        assert!(format!("{addr}").starts_with("0x"));
    }
}
