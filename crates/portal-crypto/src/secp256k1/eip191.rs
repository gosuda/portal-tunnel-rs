//! EIP-191 personal-message signing.
//!
//! [`sign_eip191_personal`] ports `SignEthereumPersonalMessage` from
//! `portal-tunnel/utils/crypto.go`.
//!
//! The EIP-191 prefix for personal messages is:
//!
//! ```text
//! "\x19Ethereum Signed Message:\n" + ASCII-decimal(message.len())
//! ```
//!
//! The full input `prefix || message` is hashed with Keccak-256 and signed
//! with `k256`'s recoverable ECDSA.  The 65-byte output is `r(32) || s(32) ||
//! v(1)` where `v = 27 + recovery_id`, matching the Ethereum convention used
//! by `ecrecover`.

use secrecy::ExposeSecret as _;
use secrecy::SecretBox;

use crate::error::PortalCryptoError;

use super::key::TenantSecp256k1Key;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Sign `message` with the EIP-191 personal-message prefix using the given
/// secp256k1 key.
///
/// Returns a 65-byte signature in `r(32) || s(32) || v(1)` order, where
/// `v = 27 + recovery_id` per the Ethereum `eth_sign` convention.
///
/// # Errors
///
/// Returns [`PortalCryptoError::Secp256k1`] if the stored scalar is invalid
/// or if the signing operation fails.
pub fn sign_eip191_personal(
    message: &[u8],
    key: &SecretBox<TenantSecp256k1Key>,
) -> Result<[u8; 65], PortalCryptoError> {
    // Build the EIP-191 prefix: "\x19Ethereum Signed Message:\n" + len_decimal.
    let len_str = message.len().to_string();
    let prefix = b"\x19Ethereum Signed Message:\n";

    // Concatenate prefix || len_str || message, then Keccak-256.
    let mut input = Vec::with_capacity(prefix.len() + len_str.len() + message.len());
    input.extend_from_slice(prefix);
    input.extend_from_slice(len_str.as_bytes());
    input.extend_from_slice(message);

    let digest = alloy::primitives::keccak256(&input);

    // Reconstruct the signing key on demand.
    let sk = key.expose_secret().signing_key()?;

    // sign_prehash_recoverable takes the raw 32-byte digest.
    let (sig, recid) = sk
        .sign_prehash_recoverable(digest.as_slice())
        .map_err(|e| PortalCryptoError::Secp256k1(e.to_string()))?;

    // Ethereum's ecrecover only supports the two standard recovery values
    // (v = 27 or 28).  The x-reduced case (recid ≥ 2) is cryptographically
    // negligible on secp256k1 but cannot be represented in Ethereum's v byte
    // convention; reject it explicitly.
    if recid.is_x_reduced() {
        return Err(PortalCryptoError::Secp256k1(
            "non-standard recovery id (x-reduced): not representable as Ethereum v byte".to_owned(),
        ));
    }

    // v = 27 + is_y_odd, which is 27 or 28.
    let v = 27u8 + u8::from(recid.is_y_odd());

    // Pack into r || s || v.
    let sig_bytes = sig.to_bytes();
    let mut out = [0u8; 65];
    out[..32].copy_from_slice(&sig_bytes[..32]); // r
    out[32..64].copy_from_slice(&sig_bytes[32..]); // s
    out[64] = v;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use k256::ecdsa::RecoveryId;

    use super::*;
    use crate::secp256k1::address::evm_address_from_pubkey;
    use crate::secp256k1::key::{from_bytes_for_test, public_key};

    /// Known non-zero scalar for deterministic tests.
    const TEST_SCALAR: [u8; 32] = [
        0x4c, 0x08, 0x83, 0xa6, 0x91, 0x02, 0x93, 0x7d, 0x62, 0x31, 0x47, 0x1b, 0x5d, 0xbb, 0x62,
        0x04, 0xfe, 0x51, 0x29, 0x61, 0x70, 0x82, 0x79, 0x2a, 0xe4, 0x68, 0xd0, 0x1a, 0x3f, 0x36,
        0x23, 0x18,
    ];

    /// Sign a known message and verify the recovered address matches the
    /// public-key-derived address.
    #[test]
    fn sign_and_recover_address_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let key = from_bytes_for_test(TEST_SCALAR);
        let pk = public_key(&key)?;
        let expected_addr = evm_address_from_pubkey(&pk);

        let message = b"hello portal-tunnel";
        let sig65 = sign_eip191_personal(message, &key)?;

        // Rebuild the EIP-191 digest to recover the signer.
        let len_str = message.len().to_string();
        let prefix = b"\x19Ethereum Signed Message:\n";
        let mut input = Vec::new();
        input.extend_from_slice(prefix);
        input.extend_from_slice(len_str.as_bytes());
        input.extend_from_slice(message);
        let digest = alloy::primitives::keccak256(&input);

        // Decode r || s || v back into Signature + RecoveryId.
        // v is 27 or 28; recid is 0 (y-even) or 1 (y-odd), no x-reduction.
        let sig_bytes: [u8; 64] = sig65[..64].try_into()?;
        let v = sig65[64];
        if v != 27 && v != 28 {
            return Err(Box::from(format!("expected v=27 or v=28, got {v}")));
        }
        let is_y_odd = v == 28;
        let sig = k256::ecdsa::Signature::from_bytes(&sig_bytes.into())?;
        let recid = RecoveryId::new(is_y_odd, false);

        let signer_vk =
            k256::ecdsa::VerifyingKey::recover_from_prehash(digest.as_slice(), &sig, recid)?;
        let signer_pubkey: k256::PublicKey = signer_vk.into();
        let recovered_addr = evm_address_from_pubkey(&signer_pubkey);

        assert_eq!(
            recovered_addr, expected_addr,
            "recovered address {recovered_addr} != expected {expected_addr}"
        );
        Ok(())
    }

    /// Signature output is always exactly 65 bytes.
    #[test]
    fn output_is_65_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let key = from_bytes_for_test(TEST_SCALAR);
        let sig65 = sign_eip191_personal(b"test", &key)?;
        assert_eq!(sig65.len(), 65);
        Ok(())
    }

    /// The `v` byte is always 27 or 28 (Ethereum convention).
    #[test]
    fn v_byte_is_27_or_28() -> Result<(), Box<dyn std::error::Error>> {
        let key = from_bytes_for_test(TEST_SCALAR);
        let sig65 = sign_eip191_personal(b"ethereum v byte test", &key)?;
        let v = sig65[64];
        assert!(v == 27 || v == 28, "v byte must be 27 or 28, got {v}");
        Ok(())
    }
}
