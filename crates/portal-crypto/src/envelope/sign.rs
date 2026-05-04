//! [`sign_envelope`] — build and sign a [`portal_wire::envelope::Envelope`].
//!
//! The signing input shape is **owned by `portal-wire`**
//! ([`portal_wire::envelope::Envelope::signing_input`]); this module only
//! attaches the ed25519 signature.

use bytes::Bytes;
use portal_wire::envelope::{Claims, Envelope};

use crate::ed25519::sign::Ed25519Signer;
use crate::error::PortalCryptoError;
use crate::separator::Role;

/// Build a signed [`portal_wire::envelope::Envelope`] from `claims` and
/// `payload`.
///
/// # Signing-input design
///
/// Consumes portal-wire's `Envelope` + `Claims`; produces a signed `Envelope`.
/// The signing input shape is owned by portal-wire
/// (`Envelope::signing_input`); this function only adds the ed25519 signature.
///
/// Specifically:
///
/// 1. A temporary `Envelope` is constructed with `sig: [0u8; 64]` and the
///    caller-supplied `claims` + `payload`.
/// 2. [`portal_wire::envelope::Envelope::signing_input`] is called with
///    `R::SEPARATOR.as_bytes()` to produce the canonical bytes.
/// 3. [`Ed25519Signer::sign_raw_signing_input`] signs those bytes **directly**
///    — without adding extra length-prefix framing — so the wire shape is
///    single-sourced from `portal-wire` and the verifier can reconstruct it
///    identically.
///
/// # Errors
///
/// - [`PortalCryptoError::Envelope`] — postcard serialization failed inside
///   `Envelope::signing_input`, or the ed25519 signing step failed.
pub fn sign_envelope<R: Role>(
    claims: Claims,
    payload: Bytes,
    signer: &Ed25519Signer<'_>,
) -> Result<Envelope, PortalCryptoError> {
    // Step 1: build temporary envelope with a zero signature.
    let mut env = Envelope {
        payload,
        sig: [0u8; 64],
        claims,
    };

    // Step 2: produce the canonical signing-input bytes from portal-wire.
    let signing_input = env
        .signing_input(R::SEPARATOR.as_bytes())
        .map_err(|e| PortalCryptoError::Envelope(e.to_string()))?;

    // Step 3: sign the raw bytes (no extra framing — portal-wire already
    // domain-separates via postcard serialization of (separator, payload, claims)).
    let sig = signer.sign_raw_signing_input(&signing_input)?;

    // Step 4: write the signature into the envelope and return.
    env.sig = sig.to_bytes();
    Ok(env)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test helpers — panics are acceptable in #[cfg(test)]"
    )]

    use bytes::Bytes;
    use jiff::Timestamp;
    use portal_wire::envelope::{Audience, Claims, Purpose};

    use super::*;
    use crate::ed25519::key::from_seed_for_test;
    use crate::ed25519::verify::Ed25519Verifier;
    use crate::envelope::verify::verify_envelope;
    use crate::separator::{HopRoute, RelayDescriptor};

    /// Helper: build a valid `Claims` with a window from `now` to `now + 60s`.
    fn make_claims(now: Timestamp, audience: Audience, purpose: Purpose) -> Claims {
        Claims {
            nonce: [0u8; 16],
            not_before: now,
            not_after: now
                .checked_add(jiff::SignedDuration::from_secs(60))
                .unwrap(),
            audience,
            purpose,
        }
    }

    /// Helper: build a signer + verifier from a fixed seed.
    fn make_signer_verifier(
        seed: [u8; 32],
    ) -> (
        secrecy::SecretBox<crate::ed25519::key::RelayEd25519Key>,
        Ed25519Verifier,
    ) {
        let key = from_seed_for_test(seed);
        let vk = crate::ed25519::key::verifying_key(&key);
        let verifier = Ed25519Verifier::new(vk);
        (key, verifier)
    }

    /// 1. Round-trip: sign then verify with matching role; payload is returned.
    #[test]
    fn envelope_round_trip_succeeds() {
        let now = Timestamp::UNIX_EPOCH
            .checked_add(jiff::SignedDuration::from_secs(1_000_000))
            .unwrap();
        let (key, verifier) = make_signer_verifier([0x10u8; 32]);
        let signer = Ed25519Signer::new(&key);

        let payload = Bytes::from_static(b"round-trip payload");
        let claims = make_claims(now, Audience::RelayApiSdk, Purpose::Register);

        let env = sign_envelope::<RelayDescriptor>(claims, payload.clone(), &signer).unwrap();

        let result = verify_envelope::<RelayDescriptor>(
            &env,
            &verifier,
            Audience::RelayApiSdk,
            Purpose::Register,
            now.checked_add(jiff::SignedDuration::from_secs(1)).unwrap(),
        );

        assert!(result.is_ok(), "round-trip verify failed: {result:?}");
        assert_eq!(result.unwrap(), payload.as_ref());
    }

    /// 2. Tampered payload: mutate `env.payload` after signing; verify must fail.
    #[test]
    fn envelope_tampered_payload_fails() {
        let now = Timestamp::UNIX_EPOCH
            .checked_add(jiff::SignedDuration::from_secs(1_000_000))
            .unwrap();
        let (key, verifier) = make_signer_verifier([0x11u8; 32]);
        let signer = Ed25519Signer::new(&key);

        let payload = Bytes::from_static(b"original payload bytes");
        let claims = make_claims(now, Audience::RelayApiSdk, Purpose::Register);

        let mut env = sign_envelope::<RelayDescriptor>(claims, payload, &signer).unwrap();

        // Flip the first byte of the payload.
        let mut tampered = env.payload.to_vec();
        tampered[0] ^= 0xff;
        env.payload = Bytes::from(tampered);

        let result = verify_envelope::<RelayDescriptor>(
            &env,
            &verifier,
            Audience::RelayApiSdk,
            Purpose::Register,
            now.checked_add(jiff::SignedDuration::from_secs(1)).unwrap(),
        );

        assert!(
            matches!(result, Err(PortalCryptoError::Envelope(_))),
            "expected Envelope error for tampered payload, got: {result:?}"
        );
    }

    /// 3. Expired claims: `not_after = now`, verify at `now + 1s` → "expired".
    #[test]
    fn envelope_expired_claims_fails() {
        let now = Timestamp::UNIX_EPOCH
            .checked_add(jiff::SignedDuration::from_secs(1_000_000))
            .unwrap();
        let (key, verifier) = make_signer_verifier([0x12u8; 32]);
        let signer = Ed25519Signer::new(&key);

        let payload = Bytes::from_static(b"expiry test payload");
        // `not_after = now` so the window expires immediately.
        let claims = Claims {
            nonce: [0u8; 16],
            not_before: now,
            not_after: now, // already at boundary — expired one instant later
            audience: Audience::RelayApiSdk,
            purpose: Purpose::Register,
        };

        let env = sign_envelope::<RelayDescriptor>(claims, payload, &signer).unwrap();

        // Verify one second after `not_after`.
        let verify_at = now.checked_add(jiff::SignedDuration::from_secs(1)).unwrap();

        let result = verify_envelope::<RelayDescriptor>(
            &env,
            &verifier,
            Audience::RelayApiSdk,
            Purpose::Register,
            verify_at,
        );

        match &result {
            Err(PortalCryptoError::Envelope(msg)) => {
                assert!(
                    msg.contains("expired"),
                    "expected 'expired' in message, got: {msg}"
                );
            }
            other => panic!("expected Envelope(expired) error, got: {other:?}"),
        }
    }

    /// 4. Audience mismatch: sign with audience A, verify with expected B.
    #[test]
    fn envelope_audience_mismatch_fails() {
        let now = Timestamp::UNIX_EPOCH
            .checked_add(jiff::SignedDuration::from_secs(1_000_000))
            .unwrap();
        let (key, verifier) = make_signer_verifier([0x13u8; 32]);
        let signer = Ed25519Signer::new(&key);

        let payload = Bytes::from_static(b"audience test payload");
        let claims = make_claims(now, Audience::RelayApiSdk, Purpose::Register); // audience A

        let env = sign_envelope::<RelayDescriptor>(claims, payload, &signer).unwrap();

        let result = verify_envelope::<RelayDescriptor>(
            &env,
            &verifier,
            Audience::RelayApiAdmin, // expected B — mismatch
            Purpose::Register,
            now.checked_add(jiff::SignedDuration::from_secs(1)).unwrap(),
        );

        match &result {
            Err(PortalCryptoError::Envelope(msg)) => {
                assert!(
                    msg.contains("audience"),
                    "expected 'audience' in message, got: {msg}"
                );
            }
            other => panic!("expected Envelope(audience mismatch) error, got: {other:?}"),
        }
    }

    /// 6. Purpose mismatch: sign with `Purpose::Register`, verify expecting
    ///    `Purpose::Renew` → "purpose" in error message.
    #[test]
    fn envelope_purpose_mismatch_fails() {
        let now = Timestamp::UNIX_EPOCH
            .checked_add(jiff::SignedDuration::from_secs(1_000_000))
            .unwrap();
        let (key, verifier) = make_signer_verifier([0x15u8; 32]);
        let signer = Ed25519Signer::new(&key);

        let payload = Bytes::from_static(b"purpose mismatch payload");
        let claims = make_claims(now, Audience::RelayApiSdk, Purpose::Register); // signed with Register

        let env = sign_envelope::<RelayDescriptor>(claims, payload, &signer).unwrap();

        let result = verify_envelope::<RelayDescriptor>(
            &env,
            &verifier,
            Audience::RelayApiSdk,
            Purpose::Renew, // expected Renew — mismatch
            now.checked_add(jiff::SignedDuration::from_secs(1)).unwrap(),
        );

        match &result {
            Err(PortalCryptoError::Envelope(msg)) => {
                assert!(
                    msg.contains("purpose"),
                    "expected 'purpose' in message, got: {msg}"
                );
            }
            other => panic!("expected Envelope(purpose mismatch) error, got: {other:?}"),
        }
    }

    /// 7. Wrong key: sign with key A, verify with verifier from key B → sig fails.
    #[test]
    fn envelope_wrong_key_fails() {
        let now = Timestamp::UNIX_EPOCH
            .checked_add(jiff::SignedDuration::from_secs(1_000_000))
            .unwrap();
        let (key_a, _) = make_signer_verifier([0x20u8; 32]);
        let (_, verifier_b) = make_signer_verifier([0x21u8; 32]);
        let signer_a = Ed25519Signer::new(&key_a);

        let payload = Bytes::from_static(b"wrong key payload");
        let claims = make_claims(now, Audience::RelayApiSdk, Purpose::Register);

        // Sign with key A…
        let env = sign_envelope::<RelayDescriptor>(claims, payload, &signer_a).unwrap();

        // …but verify with verifier derived from key B.
        let result = verify_envelope::<RelayDescriptor>(
            &env,
            &verifier_b,
            Audience::RelayApiSdk,
            Purpose::Register,
            now.checked_add(jiff::SignedDuration::from_secs(1)).unwrap(),
        );

        assert!(
            matches!(result, Err(PortalCryptoError::Envelope(_))),
            "expected Envelope error for wrong key, got: {result:?}"
        );
    }

    /// 8. Not-yet-valid: sign with `not_before` = now, verify at now - 1s →
    ///    "not yet valid" / "expired or not yet valid" in error message.
    ///
    /// This covers the `now < not_before` branch in `verify_envelope` which
    /// previously had no test.
    #[test]
    fn envelope_not_yet_valid_fails() {
        let now = Timestamp::UNIX_EPOCH
            .checked_add(jiff::SignedDuration::from_secs(1_000_000))
            .unwrap();
        let (key, verifier) = make_signer_verifier([0x16u8; 32]);
        let signer = Ed25519Signer::new(&key);

        let payload = Bytes::from_static(b"not yet valid payload");
        // not_before = now, not_after = now + 60s.
        let claims = make_claims(now, Audience::RelayApiSdk, Purpose::Register);

        let env = sign_envelope::<RelayDescriptor>(claims, payload, &signer).unwrap();

        // Verify one second BEFORE not_before → not yet valid.
        let verify_at = now.checked_sub(jiff::SignedDuration::from_secs(1)).unwrap();

        let result = verify_envelope::<RelayDescriptor>(
            &env,
            &verifier,
            Audience::RelayApiSdk,
            Purpose::Register,
            verify_at,
        );

        match &result {
            Err(PortalCryptoError::Envelope(msg)) => {
                assert!(
                    msg.contains("not yet valid") || msg.contains("expired or not yet valid"),
                    "expected 'not yet valid' or 'expired or not yet valid' in message, got: {msg}"
                );
            }
            other => panic!("expected Envelope(not yet valid) error, got: {other:?}"),
        }
    }

    /// 5. Role mismatch: sign under `RelayDescriptor`, verify under `HopRoute`.
    ///
    /// The domain separator bytes differ → different signing input → signature
    /// verify fails.
    #[test]
    fn envelope_role_mismatch_fails() {
        let now = Timestamp::UNIX_EPOCH
            .checked_add(jiff::SignedDuration::from_secs(1_000_000))
            .unwrap();
        let (key, verifier) = make_signer_verifier([0x14u8; 32]);
        let signer = Ed25519Signer::new(&key);

        let payload = Bytes::from_static(b"role mismatch payload");
        let claims = make_claims(now, Audience::RelayApiSdk, Purpose::Register);

        // Sign under RelayDescriptor…
        let env = sign_envelope::<RelayDescriptor>(claims, payload, &signer).unwrap();

        // …but verify under HopRoute (different separator → different signing input).
        let result = verify_envelope::<HopRoute>(
            &env,
            &verifier,
            Audience::RelayApiSdk,
            Purpose::Register,
            now.checked_add(jiff::SignedDuration::from_secs(1)).unwrap(),
        );

        assert!(
            matches!(result, Err(PortalCryptoError::Envelope(_))),
            "expected Envelope error for role mismatch, got: {result:?}"
        );
    }
}
