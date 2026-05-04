//! [`Ed25519Verifier`] — domain-separated ed25519 verification.

use crate::error::PortalCryptoError;
use crate::separator::Role;

use super::build_hash_input;

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Stateless verifier for ed25519 signatures produced by [`super::sign::Ed25519Signer`].
///
/// Verification uses `verify_strict` (ed25519-dalek 2.x), which rejects
/// malleable signatures (small-order points and non-canonical encodings) per
/// best practice for protocol-identity signatures.
pub struct Ed25519Verifier {
    vk: ed25519_dalek::VerifyingKey,
}

impl Ed25519Verifier {
    /// Construct a verifier from a raw [`ed25519_dalek::VerifyingKey`].
    ///
    /// Typically obtained via [`crate::ed25519::key::verifying_key`].
    #[must_use]
    pub const fn new(vk: ed25519_dalek::VerifyingKey) -> Self {
        Self { vk }
    }

    /// Verify pre-canonicalized signing-input bytes for an envelope.
    ///
    /// Used by [`crate::envelope::verify::verify_envelope`] **only**. The
    /// envelope flow builds its own canonical signing input via
    /// [`portal_wire::envelope::Envelope::signing_input`], so we **must not**
    /// rebuild the length-prefix framing here — the bytes are already
    /// domain-separated by portal-wire.
    ///
    /// Uses `verify_strict` to reject malleable signatures.
    ///
    /// # Errors
    ///
    /// Returns [`PortalCryptoError::Envelope`] if the signature is invalid.
    pub(crate) fn verify_strict_signing_input(
        &self,
        bytes: &[u8],
        sig: &ed25519_dalek::Signature,
    ) -> Result<(), PortalCryptoError> {
        self.vk
            .verify_strict(bytes, sig)
            .map_err(|e| PortalCryptoError::Envelope(e.to_string()))
    }

    /// Verify that `sig` is a valid signature over `payload` under role `R`'s
    /// SEC-007 domain separator.
    ///
    /// Internally rebuilds the same hash-input layout used by
    /// [`super::sign::Ed25519Signer::sign_with_separator`]:
    ///
    /// ```text
    /// u8(sep_len) || sep_bytes || u32_be(payload_len) || payload_bytes
    /// ```
    ///
    /// Uses `verify_strict` to reject malleable signatures.
    ///
    /// # Errors
    ///
    /// Returns [`PortalCryptoError::Ed25519`] if the signature is invalid,
    /// the payload length overflows `u32`, or the verifying key rejects the
    /// signature.
    pub fn verify_with_separator<R: Role>(
        &self,
        payload: &[u8],
        sig: &ed25519_dalek::Signature,
    ) -> Result<(), PortalCryptoError> {
        let hash_input = build_hash_input::<R>(payload)?;
        self.vk
            .verify_strict(&hash_input, sig)
            .map_err(|e| PortalCryptoError::Ed25519(e.to_string()))
    }
}
