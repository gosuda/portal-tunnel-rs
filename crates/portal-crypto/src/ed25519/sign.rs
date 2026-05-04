//! [`Ed25519Signer`] — domain-separated ed25519 signing.

use ed25519_dalek::Signer as _;
use secrecy::ExposeSecret as _;
use secrecy::SecretBox;

use crate::error::PortalCryptoError;
use crate::separator::Role;

use super::build_hash_input;
use super::key::RelayEd25519Key;

// ---------------------------------------------------------------------------
// Signer
// ---------------------------------------------------------------------------

/// Borrowed signer over a loaded [`RelayEd25519Key`].
///
/// The lifetime `'k` is tied to the `SecretBox<RelayEd25519Key>` held by the
/// caller, so the signer cannot outlive the key material.
///
/// ## Sole public sign method
///
/// [`Ed25519Signer::sign_with_separator`] is the **only** public sign path.
/// It prepends the SEC-007 domain separator and explicit length fields before
/// signing, making cross-protocol confusion attacks structurally impossible
/// (SEC-007).
///
/// ## Relation to Go upstream
///
/// Go's `Identity::DeriveToken` uses `hmac_sha256(key, separator || payload)`.
/// The Rust port adopts the same length-prefix discipline but applies it as
/// ed25519 input preparation instead of HMAC, and adds explicit `u8` and
/// `u32` length prefixes for unambiguous framing (SEC-007 delta from Go).
pub struct Ed25519Signer<'k> {
    key: &'k SecretBox<RelayEd25519Key>,
}

impl<'k> Ed25519Signer<'k> {
    /// Create a new signer that borrows the given key box.
    #[must_use]
    pub const fn new(key: &'k SecretBox<RelayEd25519Key>) -> Self {
        Self { key }
    }

    /// Sign `payload` under the SEC-007 domain separator for role `R`.
    ///
    /// The hash input layout is:
    ///
    /// ```text
    /// u8(separator_len) || separator_bytes || u32_be(payload_len) || payload_bytes
    /// ```
    ///
    /// - `separator_len` is `u8` because all SEC-007 separators are ≤ 64 bytes
    ///   (enforced by `DomainSeparator::new` at compile time).
    /// - `payload_len` is `u32` big-endian to accommodate envelope payloads up
    ///   to portal-wire's per-channel size budget.
    ///
    /// # Errors
    ///
    /// Returns [`PortalCryptoError::Ed25519`] if the payload length exceeds
    /// `u32::MAX` bytes or if the signing operation fails.
    pub fn sign_with_separator<R: Role>(
        &self,
        payload: &[u8],
    ) -> Result<ed25519_dalek::Signature, PortalCryptoError> {
        let hash_input = build_hash_input::<R>(payload)?;
        // Reconstruct the ephemeral SigningKey from the stored seed; it is
        // ZeroizeOnDrop so the secret bytes on the stack are wiped on drop.
        let sk = self.key.expose_secret().signing_key();
        let sig = sk
            .try_sign(&hash_input)
            .map_err(|e| PortalCryptoError::Ed25519(e.to_string()))?;
        Ok(sig)
    }
}

// ---------------------------------------------------------------------------
// Envelope-specific helper (pub(crate) only)
// ---------------------------------------------------------------------------

impl Ed25519Signer<'_> {
    /// Sign pre-canonicalized signing-input bytes for an envelope.
    ///
    /// Used by [`crate::envelope::sign::sign_envelope`] **only**. The envelope
    /// flow builds its own canonical signing input via
    /// [`portal_wire::envelope::Envelope::signing_input`], so we **must not**
    /// add the length-prefix framing that [`Ed25519Signer::sign_with_separator`]
    /// adds — doing so would double-canonicalize the input and produce
    /// signatures that [`crate::envelope::verify::verify_envelope`] cannot
    /// validate.
    ///
    /// For free-form payloads (not going through `portal_wire::Envelope`) use
    /// [`Ed25519Signer::sign_with_separator`] instead.
    pub(crate) fn sign_raw_signing_input(
        &self,
        bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, PortalCryptoError> {
        let sk = self.key.expose_secret().signing_key();
        sk.try_sign(bytes)
            .map_err(|e| PortalCryptoError::Envelope(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Unit tests (three mandatory tests from U4 spec)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519::key::from_seed_for_test;
    use crate::ed25519::verify::Ed25519Verifier;
    use crate::separator::{HopRoute, RelayDescriptor};

    /// 1. Sign with `RelayDescriptor`, verify with `RelayDescriptor` — must succeed.
    #[test]
    fn sign_then_verify_same_role_succeeds() -> Result<(), PortalCryptoError> {
        let key = from_seed_for_test([0x01u8; 32]);
        let vk = crate::ed25519::key::verifying_key(&key);
        let signer = Ed25519Signer::new(&key);
        let verifier = Ed25519Verifier::new(vk);

        let payload = b"hello portal";
        let sig = signer.sign_with_separator::<RelayDescriptor>(payload)?;
        verifier.verify_with_separator::<RelayDescriptor>(payload, &sig)
    }

    /// 2. Sign with `RelayDescriptor`, verify with `HopRoute` — must fail.
    #[test]
    fn sign_one_role_verify_other_role_fails() -> Result<(), Box<dyn std::error::Error>> {
        let key = from_seed_for_test([0x02u8; 32]);
        let vk = crate::ed25519::key::verifying_key(&key);
        let signer = Ed25519Signer::new(&key);
        let verifier = Ed25519Verifier::new(vk);

        let payload = b"cross-role payload";
        let sig = signer.sign_with_separator::<RelayDescriptor>(payload)?;
        let result = verifier.verify_with_separator::<HopRoute>(payload, &sig);
        assert!(
            matches!(result, Err(PortalCryptoError::Ed25519(_))),
            "expected Ed25519 error for role mismatch, got: {result:?}"
        );
        Ok(())
    }

    /// 3. Sign over payload A, verify over payload B (one byte flipped) — must fail.
    #[test]
    fn tampered_payload_verify_fails() -> Result<(), Box<dyn std::error::Error>> {
        let key = from_seed_for_test([0x03u8; 32]);
        let vk = crate::ed25519::key::verifying_key(&key);
        let signer = Ed25519Signer::new(&key);
        let verifier = Ed25519Verifier::new(vk);

        let payload_a = b"original payload";
        let sig = signer.sign_with_separator::<RelayDescriptor>(payload_a)?;

        let mut payload_b = *payload_a;
        payload_b[0] ^= 0xff;
        let result = verifier.verify_with_separator::<RelayDescriptor>(&payload_b, &sig);
        assert!(
            matches!(result, Err(PortalCryptoError::Ed25519(_))),
            "expected Ed25519 error for tampered payload, got: {result:?}"
        );
        Ok(())
    }
}
