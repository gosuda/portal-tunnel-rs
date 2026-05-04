//! Crate-internal helpers for secret-material construction.
//!
//! This module centralises the hex-decode helper used by every key loader
//! so that the byte-level validation logic is tested and maintained in one
//! place.

use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

/// Decode a lowercase or uppercase hex string into exactly `N` bytes.
///
/// Returns `Err(message)` — a plain `String` — if the string is not valid
/// hex or its decoded byte-length differs from `N`.  Callers are expected to
/// wrap the error string in the appropriate [`crate::error::PortalCryptoError`]
/// variant.
///
/// The output is wrapped in [`Zeroizing`] so the decoded secret material is
/// wiped from the heap when it is dropped.
pub fn decode_hex_exact<const N: usize>(s: &str) -> Result<Zeroizing<[u8; N]>, String> {
    if s.len() != N * 2 {
        return Err(format!(
            "expected {N}-byte hex string ({} chars), got {} chars",
            N * 2,
            s.len()
        ));
    }
    let mut out = Zeroizing::new([0u8; N]);
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(pair[0]).map_err(|e| format!("invalid hex at byte {}: {e}", i * 2))?;
        let lo =
            hex_nibble(pair[1]).map_err(|e| format!("invalid hex at byte {}: {e}", i * 2 + 1))?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

/// Convert a single ASCII hex character to its nibble value.
const fn hex_nibble(b: u8) -> Result<u8, &'static str> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("invalid hex character in key material"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_valid_32_byte_hex() {
        let hex = "00".repeat(32);
        match decode_hex_exact::<32>(&hex) {
            Ok(bytes) => assert_eq!(*bytes, [0u8; 32]),
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn decode_rejects_wrong_length() {
        let hex = "aabbccdd"; // 4 bytes, not 32
        match decode_hex_exact::<32>(hex) {
            Ok(_) => panic!("should have rejected wrong-length hex"),
            Err(msg) => assert!(
                msg.contains("expected 32-byte"),
                "error should mention expected length; got: {msg}"
            ),
        }
    }

    #[test]
    fn decode_rejects_invalid_character() {
        let mut hex = "00".repeat(32);
        // Replace one character with an invalid one.
        hex.replace_range(10..11, "z");
        match decode_hex_exact::<32>(&hex) {
            Ok(_) => panic!("should have rejected invalid hex character"),
            Err(msg) => assert!(
                msg.contains("invalid hex character"),
                "error should name the bad character; got: {msg}"
            ),
        }
    }

    #[test]
    fn decode_round_trips_known_bytes() {
        // RFC 4648 test vector: 0xde, 0xad, 0xbe, 0xef
        let hex = "deadbeef".to_owned() + &"00".repeat(28);
        match decode_hex_exact::<32>(&hex) {
            Ok(bytes) => {
                assert_eq!(bytes[0], 0xde);
                assert_eq!(bytes[1], 0xad);
                assert_eq!(bytes[2], 0xbe);
                assert_eq!(bytes[3], 0xef);
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}
