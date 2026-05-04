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
    // tokio AsyncWriteExt::write_u32 → io::Error directly (preserves
    // ErrorKind via the #[from] path on NetError::Io).
    send.write_u32(len).await.map_err(NetError::Io)?;
    // quinn::SendStream::write_all is the *intrinsic* method (shadowing
    // tokio AsyncWriteExt) and returns quinn::WriteError. Wrap into
    // io::Error::other(e) so the source() chain remains traversable;
    // outer ErrorKind becomes Other but quinn::WriteError carries its own
    // typed variants for ConnectionLost / Stopped.
    send.write_all(&bytes)
        .await
        .map_err(|e| NetError::Io(std::io::Error::other(e)))?;
    Ok(())
}

/// Read a length-prefixed postcard `Envelope` from a quinn `RecvStream`.
///
/// # Errors
/// Returns [`NetError::Io`] on a truncated stream; [`NetError::WireDecode`]
/// on a length-field overflow or postcard decode failure.
pub async fn recv_control_envelope(recv: &mut quinn::RecvStream) -> Result<Envelope, NetError> {
    use tokio::io::AsyncReadExt as _;

    // tokio AsyncReadExt::read_u32 → io::Error → NetError::Io directly
    // (preserves ErrorKind for caller-side discrimination).
    let len = recv.read_u32().await.map_err(NetError::Io)?;
    let len_usize = usize::try_from(len)
        .map_err(|_| NetError::WireDecode(format!("envelope length {len} exceeds usize")))?;
    if len_usize > CONTROL_ENVELOPE_MAX {
        return Err(NetError::WireDecode(format!(
            "envelope {len} bytes exceeds cap {CONTROL_ENVELOPE_MAX}",
        )));
    }
    let mut buf = vec![0u8; len_usize];
    // quinn::RecvStream::read_exact returns quinn::ReadExactError (not
    // io::Error), so we MUST wrap into io::Error here. `Error::other(e)`
    // preserves the source() chain (it boxes the error rather than
    // stringifying), at the cost of an outer ErrorKind::Other — quinn's
    // ReadExactError already carries its own typed variants for
    // ConnectionLost / FinishedEarly so the kind-loss is acceptable.
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| NetError::Io(std::io::Error::other(e)))?;
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
    let not_after = now.saturating_add(ttl).unwrap_or(jiff::Timestamp::MAX);
    Claims {
        nonce,
        not_before: now,
        not_after,
        audience: Audience::QuicBackhaul,
        purpose: Purpose::LeaseAccess,
    }
}

/// Constant payload returned by every [`verify_control_envelope`] failure
/// so the variant *and* its `String` content are byte-identical regardless
/// of the underlying mode (time-window, audience, purpose, signature). A
/// peer or downstream logger keyed on the error message therefore cannot
/// distinguish failure modes from observable handshake responses.
///
/// The relay SHOULD `tracing::debug!` the underlying typed error
/// internally so operators retain visibility, but it MUST NOT echo that
/// detail across a trust boundary.
const HANDSHAKE_REJECT_MESSAGE: &str = "verification failed";

/// Verify a control-handshake envelope against expected audience/purpose
/// and the supplied tenant signing key. Returns the payload bytes on
/// success.
///
/// Verification delegates to portal-crypto's `verify_envelope` — see
/// `portal_crypto::verify_envelope` for the cheap-first verification order
/// (time → audience → purpose → signature). Note: this provides
/// *uniform-error-class* not *constant-time* verification; an attacker who
/// can time the response can still distinguish signature-failure from
/// time/audience-failure because the cheap checks short-circuit before
/// the signature verify. Constant-time is out of scope for U6.
///
/// # Errors
/// Returns [`NetError::BackhaulHandshake`] with the constant
/// [`HANDSHAKE_REJECT_MESSAGE`] for ANY verification failure (audience,
/// expired, purpose, signature) — failure modes are NOT distinguishable
/// from the error payload.
pub fn verify_control_envelope(
    env: &Envelope,
    tenant_verifier: &portal_crypto::Ed25519Verifier,
    now: Timestamp,
) -> Result<Bytes, NetError> {
    use portal_crypto::{RelayDescriptor, verify_envelope};

    match verify_envelope::<RelayDescriptor>(
        env,
        tenant_verifier,
        Audience::QuicBackhaul,
        Purpose::LeaseAccess,
        now,
    ) {
        Ok(_payload_slice) => {
            // Refcount-bump rather than allocating a fresh buffer: env.payload
            // is already a `Bytes`, so cloning the field decouples the
            // returned lifetime from `env` without copying.
            Ok(env.payload.clone())
        }
        Err(detail) => {
            tracing::debug!(?detail, "control envelope verify failed");
            Err(NetError::BackhaulHandshake(
                HANDSHAKE_REJECT_MESSAGE.to_owned(),
            ))
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test fixtures use deterministic keys")]
mod tests {
    use super::*;
    use jiff::SignedDuration;
    use portal_crypto::{
        Ed25519Signer, Ed25519Verifier, RelayDescriptor, ed25519_from_seed_for_test, sign_envelope,
        verifying_key,
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
        let env = sign_envelope::<RelayDescriptor>(claims, payload.clone(), &signer).unwrap();

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

    /// All four verification failure modes (audience, expired, purpose,
    /// signature) MUST surface byte-identical `BackhaulHandshake` payloads
    /// so observers cannot fingerprint the failure class. This test pins
    /// the side-channel-uniform contract.
    #[test]
    fn verify_control_envelope_failure_modes_are_indistinguishable() {
        let key = ed25519_from_seed_for_test([0x11_u8; 32]);
        let vk = verifying_key(&key);
        let signer = Ed25519Signer::new(&key);
        let verifier = Ed25519Verifier::new(vk);

        let now = fixed_now();
        let payload = Bytes::from_static(b"x");

        // Build each failing envelope from a freshly-constructed claim set
        // so the test reads top-to-bottom without struct-update plumbing
        // and clippy's redundant_clone lint stays happy. Claims is a small
        // value type — rebuilding is cheaper than the cognitive overhead
        // of a shared baseline + struct-update spreads.

        // 1) Wrong audience.
        let mut claims = build_control_claims(now, [0u8; 16]);
        claims.audience = Audience::Keyless;
        let env_bad_aud =
            sign_envelope::<RelayDescriptor>(claims, payload.clone(), &signer).unwrap();

        // 2) Wrong purpose.
        let mut claims = build_control_claims(now, [0u8; 16]);
        claims.purpose = Purpose::Register;
        let env_bad_pur =
            sign_envelope::<RelayDescriptor>(claims, payload.clone(), &signer).unwrap();

        // 3) Expired (verify with `later` against valid claims).
        let env_valid = sign_envelope::<RelayDescriptor>(
            build_control_claims(now, [0u8; 16]),
            payload.clone(),
            &signer,
        )
        .unwrap();
        let later = now
            .saturating_add(SignedDuration::from_secs(7200))
            .unwrap_or(Timestamp::MAX);

        // 4) Bad signature (flip a sig byte).
        let mut env_bad_sig = sign_envelope::<RelayDescriptor>(
            build_control_claims(now, [0u8; 16]),
            payload,
            &signer,
        )
        .unwrap();
        env_bad_sig.sig[0] ^= 0xff;

        let messages: Vec<String> = [
            verify_control_envelope(&env_bad_aud, &verifier, now),
            verify_control_envelope(&env_bad_pur, &verifier, now),
            verify_control_envelope(&env_valid, &verifier, later),
            verify_control_envelope(&env_bad_sig, &verifier, now),
        ]
        .into_iter()
        .map(|r| match r {
            Err(NetError::BackhaulHandshake(msg)) => msg,
            other => panic!("expected BackhaulHandshake, got: {other:?}"),
        })
        .collect();

        // All four must produce the EXACT same constant payload — anything
        // varying between them would let an observer fingerprint the mode.
        assert_eq!(messages[0], HANDSHAKE_REJECT_MESSAGE);
        assert_eq!(messages[1], HANDSHAKE_REJECT_MESSAGE);
        assert_eq!(messages[2], HANDSHAKE_REJECT_MESSAGE);
        assert_eq!(messages[3], HANDSHAKE_REJECT_MESSAGE);
    }
}
