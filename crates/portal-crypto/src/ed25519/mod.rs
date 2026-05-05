//! Ed25519 protocol-identity primitives for the relay.
//!
//! This module owns the three concerns that together form the relay's
//! ed25519 identity:
//!
//! - **[`key`]** — the [`key::RelayEd25519Key`] newtype and its sole constructor
//!   [`key::load_relay_ed25519_key`]. Key material is held behind
//!   `secrecy::SecretBox<RelayEd25519Key>` so secrets are zeroized on drop.
//!
//! - **[`sign`]** — [`sign::Ed25519Signer`], which exposes exactly one public sign
//!   method: [`sign::Ed25519Signer::sign_with_separator`]. The method prepends the
//!   SEC-007 domain separator (chosen at compile time via the [`Role`] typestate)
//!   plus length prefixes before signing, making cross-protocol confusion
//!   attacks structurally impossible.
//!
//! - **[`verify`]** — [`verify::Ed25519Verifier`], the mirror of [`sign::Ed25519Signer`].
//!   Uses `verify_strict` (ed25519-dalek 2.x) to reject malleable signatures.
//!
//! ## Hash-input framing (SEC-007)
//!
//! Both signer and verifier share [`build_hash_input`], which lives here in
//! the neutral module root so the same framing code is used by both sides.
//! Keeping it out of `sign.rs` prevents a class of bugs where sign and verify
//! happen to agree because they share the same buggy code path.

// `pub mod` (not `pub(crate)`) is intentional: clippy::redundant_pub_crate fires
// because `ed25519` itself is declared `pub(crate)` in `lib.rs`, making an
// inner `pub(crate)` redundant. Visibility is already capped at the crate root.
pub mod key;
pub mod sign;
pub mod verify;

use crate::error::PortalCryptoError;
use crate::separator::Role;

/// Build the canonical SEC-007 hash input for `payload` under role `R`.
///
/// Layout (per the Phase 2 plan U4 spec):
///
/// ```text
/// u8(sep_len) || sep_bytes || u32_be(payload_len) || payload_bytes
/// ```
///
/// - `sep_len` is `u8` because [`crate::separator::DomainSeparator::new`]
///   enforces `len ≤ 255` at compile time.
/// - `payload_len` is `u32` big-endian to accommodate envelope payloads up
///   to portal-wire's per-channel size budget.
///
/// Both [`sign::Ed25519Signer::sign_with_separator`] and
/// [`verify::Ed25519Verifier::verify_with_separator`] call this function, ensuring
/// the framing is identical on both sides.
///
/// # Errors
///
/// Returns [`PortalCryptoError::Ed25519`] if `payload.len()` exceeds
/// `u32::MAX`.
pub fn build_hash_input<R: Role>(payload: &[u8]) -> Result<Vec<u8>, PortalCryptoError> {
    let sep = R::SEPARATOR.as_bytes();
    // DomainSeparator::new enforces len ≤ u8::MAX at compile time.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "DomainSeparator guarantees len ≤ 255"
    )]
    let sep_len = sep.len() as u8;

    // Validate length before allocating — so an oversized payload returns an
    // error instead of triggering a multi-GiB allocation.
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| PortalCryptoError::Ed25519("payload exceeds u32::MAX bytes".to_owned()))?;

    let capacity = 1 + sep.len() + 4 + payload.len();
    let mut input = Vec::with_capacity(capacity);
    input.push(sep_len);
    input.extend_from_slice(sep);
    input.extend_from_slice(&payload_len.to_be_bytes());
    input.extend_from_slice(payload);
    Ok(input)
}

#[cfg(test)]
mod framing_tests {
    use super::*;
    use crate::separator::RelayDescriptor;

    /// Verify the exact byte layout of `build_hash_input` against the U4 spec:
    /// `u8(sep_len) || sep_bytes || u32_be(payload_len) || payload_bytes`.
    #[test]
    fn hash_input_byte_layout_matches_spec() -> Result<(), PortalCryptoError> {
        let sep = <RelayDescriptor as Role>::SEPARATOR.as_bytes();
        let payload = b"test";

        let input = build_hash_input::<RelayDescriptor>(payload)?;

        // Byte 0: separator length as u8.
        let expected_sep_len = u8::try_from(sep.len())
            .map_err(|_| PortalCryptoError::Ed25519("test sep exceeds u8".to_owned()))?;
        assert_eq!(input[0], expected_sep_len, "sep_len byte mismatch");

        // Bytes 1..1+sep_len: separator bytes verbatim.
        let sep_end = 1 + sep.len();
        assert_eq!(&input[1..sep_end], sep, "separator bytes mismatch");

        // Bytes sep_end..sep_end+4: payload length as u32 big-endian.
        let payload_len_bytes: [u8; 4] = input[sep_end..sep_end + 4]
            .try_into()
            .map_err(|_| PortalCryptoError::Ed25519("slice length wrong".to_owned()))?;
        let expected_len = u32::try_from(payload.len())
            .map_err(|_| PortalCryptoError::Ed25519("test payload exceeds u32".to_owned()))?;
        assert_eq!(
            u32::from_be_bytes(payload_len_bytes),
            expected_len,
            "payload_len u32_be mismatch"
        );

        // Remaining bytes: payload verbatim.
        assert_eq!(&input[sep_end + 4..], payload, "payload bytes mismatch");

        // Total length sanity check.
        assert_eq!(input.len(), 1 + sep.len() + 4 + payload.len());
        Ok(())
    }
}
