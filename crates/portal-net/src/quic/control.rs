//! Backhaul control handshake — typed `Envelope` exchange replacing Go's
//! JSON `quicBackhaulControlMessage`.
//!
//! ## Wire shape
//!
//! - SDK opens a server-initiated bidi stream, writes `Channel::Control`
//!   tag, then a length-prefixed postcard `Envelope` carrying lease-access
//!   claims (audience = `Audience::QuicBackhaul`, purpose =
//!   `Purpose::LeaseAccess`).
//! - Relay reads the envelope, verifies signature against the tenant's
//!   registered ed25519 pubkey + claim window, returns either an Ok
//!   response envelope or a Reject envelope and closes the connection.
//!
//! ## Replay protection
//!
//! Nonce-replay is OWNED BY PHASE 5 (relay-side lookup table). Phase 3
//! supplies the wire shape and per-handshake invariants only.

use bytes::Bytes;
use jiff::Timestamp;
use portal_wire::envelope::{Audience, Claims, Envelope, Purpose};
use portal_wire::limits::CONTROL_MAX;

use crate::error::NetError;

/// Maximum control-handshake envelope size (postcard-encoded). Reuses
/// portal-wire's [`CONTROL_MAX`] so the cap is single-sourced from the
/// wire register.
const CONTROL_ENVELOPE_MAX: usize = CONTROL_MAX;

/// Send a length-prefixed postcard `Envelope` over a quinn `SendStream`.
///
/// # Errors
/// Returns [`NetError::WireDecode`] on encode failure or oversize;
/// [`NetError::Io`] on stream write failure.
pub async fn send_control_envelope(
    send: &mut quinn::SendStream,
    env: &Envelope,
) -> Result<(), NetError> {
    use tokio::io::AsyncWriteExt as _;

    let bytes = env
        .to_bytes()
        .map_err(|e| NetError::WireDecode(format!("envelope encode: {e}")))?;
    let len = u32::try_from(bytes.len())
        .map_err(|_| NetError::WireDecode("envelope > u32::MAX".to_owned()))?;
    if bytes.len() > CONTROL_ENVELOPE_MAX {
        return Err(NetError::WireDecode(format!(
            "envelope {len} bytes exceeds {CONTROL_ENVELOPE_MAX}",
        )));
    }
    send.write_u32(len)
        .await
        .map_err(|e| NetError::Io(std::io::Error::other(e.to_string())))?;
    send.write_all(&bytes)
        .await
        .map_err(|e| NetError::Io(std::io::Error::other(e.to_string())))?;
    Ok(())
}

/// Read a length-prefixed postcard `Envelope` from a quinn `RecvStream`.
///
/// # Errors
/// Returns [`NetError::Io`] on a truncated stream; [`NetError::WireDecode`]
/// on a length-field overflow or postcard decode failure.
pub async fn recv_control_envelope(
    recv: &mut quinn::RecvStream,
) -> Result<Envelope, NetError> {
    use tokio::io::AsyncReadExt as _;

    let len = recv
        .read_u32()
        .await
        .map_err(|e| NetError::Io(std::io::Error::other(e.to_string())))?;
    let len_usize = usize::try_from(len)
        .map_err(|_| NetError::WireDecode(format!("envelope length {len} exceeds usize")))?;
    if len_usize > CONTROL_ENVELOPE_MAX {
        return Err(NetError::WireDecode(format!(
            "envelope {len} bytes exceeds cap {CONTROL_ENVELOPE_MAX}",
        )));
    }
    let mut buf = vec![0u8; len_usize];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| NetError::Io(std::io::Error::other(e.to_string())))?;
    Envelope::from_bytes(&buf).map_err(|e| NetError::WireDecode(format!("envelope decode: {e}")))
}

/// 60-second valid window for a backhaul control handshake; mirrors Go's
/// `quicBackhaulConfig.AccessTokenTTL`.
const CONTROL_HANDSHAKE_TTL_SECS: i64 = 60;

/// Build the SDK-side control-handshake claims.
///
/// The signing of these claims happens at the call site using
/// [`portal_crypto::sign_envelope`] under the
/// [`portal_crypto::RelayDescriptor`] domain separator.
///
/// `now` is provided explicitly so tests can drive a deterministic clock.
#[must_use]
pub fn build_control_claims(now: Timestamp, nonce: [u8; 16]) -> Claims {
    let ttl = jiff::SignedDuration::from_secs(CONTROL_HANDSHAKE_TTL_SECS);
    // `Timestamp::saturating_add(SignedDuration)` clamps at `Timestamp::MAX`
    // and never errors (unlike the calendrical-Span overload), so an
    // unwrap-free expression is safe and surfaces the saturation semantic.
    let not_after = now
        .saturating_add(ttl)
        .unwrap_or(jiff::Timestamp::MAX);
    Claims {
        nonce,
        not_before: now,
        not_after,
        audience: Audience::QuicBackhaul,
        purpose: Purpose::LeaseAccess,
    }
}

/// Verify a control-handshake envelope against expected audience/purpose
/// and the supplied tenant signing key. Returns the payload bytes on
/// success.
///
/// Verification delegates to portal-crypto's `verify_envelope` — see
/// `portal_crypto::verify_envelope` for the cheap-first verification order
/// (time → audience → purpose → signature).
///
/// # Errors
/// Returns [`NetError::BackhaulHandshake`] for any verification failure
/// (audience mismatch, expired claims, bad signature, etc.) — the relay
/// MUST collapse to one external error class so attackers cannot
/// distinguish failure modes.
pub fn verify_control_envelope(
    env: &Envelope,
    tenant_verifier: &portal_crypto::Ed25519Verifier,
    now: Timestamp,
) -> Result<Bytes, NetError> {
    use portal_crypto::{RelayDescriptor, verify_envelope};

    let payload_slice = verify_envelope::<RelayDescriptor>(
        env,
        tenant_verifier,
        Audience::QuicBackhaul,
        Purpose::LeaseAccess,
        now,
    )
    .map_err(|e| NetError::BackhaulHandshake(e.to_string()))?;
    // Detach the borrow into an owned Bytes for caller convenience.
    Ok(Bytes::copy_from_slice(payload_slice))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test fixtures use deterministic keys")]
mod tests {
    use super::*;
    use jiff::SignedDuration;
    use portal_crypto::{
        Ed25519Signer, Ed25519Verifier, RelayDescriptor, ed25519_from_seed_for_test,
        sign_envelope, verifying_key,
    };

    fn fixed_now() -> Timestamp {
        // 2026-05-04 12:00:00 UTC
        Timestamp::from_second(1_778_155_200).unwrap()
    }

    #[test]
    fn build_claims_yields_quic_backhaul_audience() {
        let claims = build_control_claims(fixed_now(), [0u8; 16]);
        assert_eq!(claims.audience, Audience::QuicBackhaul);
        assert_eq!(claims.purpose, Purpose::LeaseAccess);
        assert!(claims.not_after > claims.not_before);
    }

    #[test]
    fn verify_control_envelope_round_trip_succeeds() {
        let key = ed25519_from_seed_for_test([0xa5_u8; 32]);
        let vk = verifying_key(&key);
        let signer = Ed25519Signer::new(&key);
        let verifier = Ed25519Verifier::new(vk);

        let claims = build_control_claims(fixed_now(), [0xb6_u8; 16]);
        let payload = Bytes::from_static(b"lease-token-bytes");
        let env =
            sign_envelope::<RelayDescriptor>(claims, payload.clone(), &signer).unwrap();

        let payload_back = verify_control_envelope(&env, &verifier, fixed_now()).unwrap();
        assert_eq!(payload_back.as_ref(), payload.as_ref());
    }

    #[test]
    fn verify_control_envelope_rejects_wrong_audience() {
        let key = ed25519_from_seed_for_test([0xc7_u8; 32]);
        let vk = verifying_key(&key);
        let signer = Ed25519Signer::new(&key);
        let verifier = Ed25519Verifier::new(vk);

        // Build claims with the WRONG audience (Keyless instead of QuicBackhaul).
        // `SignedDuration` is a non-calendrical duration so `saturating_add`
        // clamps at `Timestamp::MAX` rather than erroring; the `unwrap_or`
        // mirrors the production helper and avoids any `unwrap()` panic path.
        let not_after = fixed_now()
            .saturating_add(SignedDuration::from_secs(60))
            .unwrap_or(Timestamp::MAX);
        let claims = Claims {
            nonce: [0xd8_u8; 16],
            not_before: fixed_now(),
            not_after,
            audience: Audience::Keyless,
            purpose: Purpose::LeaseAccess,
        };
        let env =
            sign_envelope::<RelayDescriptor>(claims, Bytes::from_static(b"x"), &signer).unwrap();

        let result = verify_control_envelope(&env, &verifier, fixed_now());
        assert!(
            matches!(result, Err(NetError::BackhaulHandshake(_))),
            "wrong audience must surface BackhaulHandshake: {result:?}",
        );
    }

    #[test]
    fn verify_control_envelope_rejects_expired_claims() {
        let key = ed25519_from_seed_for_test([0xe9_u8; 32]);
        let vk = verifying_key(&key);
        let signer = Ed25519Signer::new(&key);
        let verifier = Ed25519Verifier::new(vk);

        let claims = build_control_claims(fixed_now(), [0xfa; 16]);
        let env =
            sign_envelope::<RelayDescriptor>(claims, Bytes::from_static(b"x"), &signer).unwrap();
        // now is 2 hours past the 60s window.
        let later = fixed_now()
            .saturating_add(SignedDuration::from_secs(7200))
            .unwrap_or(Timestamp::MAX);
        let result = verify_control_envelope(&env, &verifier, later);
        assert!(matches!(result, Err(NetError::BackhaulHandshake(_))));
    }
}
