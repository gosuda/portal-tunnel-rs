//! [`verify_envelope`] — verify a signed [`portal_wire::envelope::Envelope`].
//!
//! SEC-001 claim checks (time window, audience, purpose) execute **before**
//! the cryptographic verification so cheap rejections happen first.

use jiff::Timestamp;
use portal_wire::envelope::{Audience, Envelope, Purpose};

use crate::ed25519::verify::Ed25519Verifier;
use crate::error::PortalCryptoError;
use crate::separator::Role;

/// Verify a signed [`portal_wire::envelope::Envelope`] and return a reference
/// to its payload bytes on success.
///
/// # Verification order (cheap-first, SEC-001)
///
/// 1. **Time window** — `env.claims.not_before <= now < env.claims.not_after`.
///    Returns `PortalCryptoError::Envelope("expired or not yet valid")` on
///    failure.
/// 2. **Audience** — `env.claims.audience == expected_audience`.
///    Returns `PortalCryptoError::Envelope("audience mismatch")` on failure.
/// 3. **Purpose** — `env.claims.purpose == expected_purpose`.
///    Returns `PortalCryptoError::Envelope("purpose mismatch")` on failure.
/// 4. **Signature** — reconstructs the canonical signing input via
///    [`portal_wire::envelope::Envelope::signing_input`] and calls
///    the private `Ed25519Verifier::verify_strict_signing_input` method.
///    Returns `PortalCryptoError::Envelope(sig_error)` on failure.
///
/// # Errors
///
/// All failure paths return [`PortalCryptoError::Envelope`] with a
/// human-readable description.
pub fn verify_envelope<'env, R: Role>(
    env: &'env Envelope,
    verifier: &Ed25519Verifier,
    expected_audience: Audience,
    expected_purpose: Purpose,
    now: Timestamp,
) -> Result<&'env [u8], PortalCryptoError> {
    // Step 1: time-window check (cheap).
    if now < env.claims.not_before || now >= env.claims.not_after {
        return Err(PortalCryptoError::Envelope(
            "expired or not yet valid".to_owned(),
        ));
    }

    // Step 2: audience check (cheap).
    if env.claims.audience != expected_audience {
        return Err(PortalCryptoError::Envelope("audience mismatch".to_owned()));
    }

    // Step 3: purpose check (cheap).
    if env.claims.purpose != expected_purpose {
        return Err(PortalCryptoError::Envelope("purpose mismatch".to_owned()));
    }

    // Step 4: reconstruct canonical signing input and verify signature.
    let signing_input = env
        .signing_input(R::SEPARATOR.as_bytes())
        .map_err(|e| PortalCryptoError::Envelope(e.to_string()))?;

    let sig = ed25519_dalek::Signature::from_bytes(&env.sig);
    verifier.verify_strict_signing_input(&signing_input, &sig)?;

    Ok(&env.payload[..])
}
