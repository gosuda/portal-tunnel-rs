//! Lease-access-token issue/verify helper (Phase 5 SDK-API S1).
//!
//! ## Wire shape
//!
//! A lease-access token is a JWT-style compact string:
//!
//! ```text
//! <base64url(postcard(claims))>.<base64url(sig64))>
//! ```
//!
//! - `claims` is the postcard-encoded [`LeaseTokenClaims`] struct.
//! - `sig64` is the 64-byte raw ed25519 signature over `postcard(claims)`
//!   under the SEC-007 `LeaseToken` domain separator. The separator
//!   length-prefix framing is added inside
//!   [`portal_crypto::Ed25519Signer::sign_with_separator`] /
//!   [`portal_crypto::Ed25519Verifier::verify_with_separator`]; this
//!   module never prepends the separator itself (avoids the
//!   double-canonicalisation bug class).
//! - Both halves use the URL-safe base64 alphabet without padding
//!   (`base64::engine::general_purpose::URL_SAFE_NO_PAD`).
//!
//! ## Why postcard, not JSON
//!
//! Greenfield wire shape per ADR-0001: byte-stable framing, no
//! third-party JWT dep. The Go upstream's `tokenPrivateKey` /
//! `tokenPublicKey` JWT serialisation is intentionally **not**
//! preserved — see the slice plan for the deviation rationale.
//!
//! ## Claims minimalism
//!
//! v0.1 single-key relay: `{ version, identity, issued_at,
//! expires_at }` only. No `kid`, `iss`, or `scope`. The
//! `version: u8 = 1` byte reserves space for forward-compatible
//! frame evolution without breaking on-the-wire parsing.
//!
//! ## Role separation
//!
//! The `LeaseToken` role separator pin (turbofish on
//! `sign_with_separator::<portal_crypto::LeaseToken>` /
//! `verify_with_separator::<portal_crypto::LeaseToken>`) means a
//! token signed under any other in-tree [`portal_crypto::Role`]
//! (e.g. [`portal_crypto::RelayDescriptor`]) cannot verify here —
//! the role-mismatch test below proves this.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use compact_str::CompactString;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::lease_registry::IdentityKey;
use crate::error::RelayResult;

/// HTTP header carrying a lease access token on hijack-style SDK
/// endpoints.
///
/// Stored lower-case so callers use the canonical case-insensitive
/// [`http::HeaderMap`] lookup path rather than doing string comparisons
/// themselves.
pub const ACCESS_TOKEN_HEADER: &str = "x-portal-access-token";

/// Current on-the-wire claim-frame version. Bumping this is a
/// breaking change to the lease-access-token format and MUST land
/// alongside a parallel `verify` accept-list expansion.
pub const LEASE_TOKEN_VERSION: u8 = 1;

/// Decoded lease-access-token claims.
///
/// Field layout is pinned by [`LEASE_TOKEN_VERSION`]. Postcard
/// encodes the four fields in declared order with no schema
/// metadata, so the wire format is exactly:
///
/// `version:u8 || identity:[u8;32] || issued_at:varint(i64) ||
///  expires_at:varint(i64)`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseTokenClaims {
    /// Frame version. Always [`LEASE_TOKEN_VERSION`] in v0.1.
    pub version: u8,
    /// 32-byte raw ed25519 public-key encoding of the lease holder.
    pub identity: [u8; 32],
    /// Unix-seconds timestamp at issue time.
    pub issued_at: i64,
    /// Unix-seconds expiry — verify rejects when `now >= expires_at`.
    pub expires_at: i64,
}

/// Errors surfaced by [`issue`] and [`verify`].
///
/// Pass-through arm on [`crate::error::RelayError::LeaseToken`] via
/// `#[error(transparent)]`.
#[derive(Debug, Error)]
pub enum LeaseTokenError {
    /// The token string was not in `<payload>.<sig>` form, or one of
    /// the halves was not valid URL-safe base64 (no-pad).
    #[error("lease-token: malformed framing")]
    MalformedFraming,

    /// The decoded payload could not be deserialised as a
    /// [`LeaseTokenClaims`] postcard frame.
    #[error("lease-token: malformed claims: {0}")]
    MalformedClaims(String),

    /// The decoded signature was not exactly 64 bytes (raw ed25519).
    #[error("lease-token: malformed signature")]
    MalformedSignature,

    /// The claim-frame version field did not match
    /// [`LEASE_TOKEN_VERSION`].
    #[error("lease-token: unsupported version {0}")]
    UnsupportedVersion(u8),

    /// `now >= expires_at` at verify time.
    #[error("lease-token: expired")]
    Expired,

    /// The signature did not verify under the relay's
    /// [`portal_crypto::LeaseToken`] role separator. Covers tampered
    /// payload bytes, tampered signature bytes, and wrong-role
    /// signing.
    #[error("lease-token: signature invalid")]
    SignatureInvalid,

    /// Postcard serialisation failed when issuing (e.g. allocation
    /// failure under `alloc`-backed encoder).
    #[error("lease-token: encode error: {0}")]
    Encode(String),

    /// The signer raised a crypto error (e.g. payload exceeds u32
    /// bytes — should not happen for the fixed-size claims frame
    /// but the underlying API is fallible).
    #[error("lease-token: signer error: {0}")]
    Signer(String),
}

/// Issue a fresh lease-access token for `identity` expiring at
/// `expires_at`.
///
/// `signer` is the relay's borrowed [`portal_crypto::Ed25519Signer`]
/// over its loaded ed25519 identity key. The role is pinned to
/// [`portal_crypto::LeaseToken`] at the call site via turbofish.
///
/// `issued_at` is captured from [`Timestamp::now`] inside the
/// function — the caller does not pass it. This keeps clock
/// authority in one place (issue site).
///
/// # Errors
///
/// - [`LeaseTokenError::Encode`] on postcard serialisation failure.
/// - [`LeaseTokenError::Signer`] if the underlying ed25519 signer
///   raises a crypto error.
pub fn issue(
    identity: IdentityKey,
    expires_at: Timestamp,
    signer: &portal_crypto::Ed25519Signer<'_>,
) -> RelayResult<CompactString> {
    let claims = LeaseTokenClaims {
        version: LEASE_TOKEN_VERSION,
        identity: identity.0,
        issued_at: Timestamp::now().as_second(),
        expires_at: expires_at.as_second(),
    };

    let payload_bytes =
        postcard::to_allocvec(&claims).map_err(|e| LeaseTokenError::Encode(e.to_string()))?;

    let sig = signer
        .sign_with_separator::<portal_crypto::LeaseToken>(&payload_bytes)
        .map_err(|e| LeaseTokenError::Signer(e.to_string()))?;

    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_bytes);
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    let mut out = CompactString::with_capacity(payload_b64.len() + 1 + sig_b64.len());
    out.push_str(&payload_b64);
    out.push('.');
    out.push_str(&sig_b64);
    Ok(out)
}

/// Verify a lease-access token and return its decoded claims.
///
/// Validation steps, in order:
///
/// 1. Split on the single `.` separator; reject if zero or two-plus
///    dots are present.
/// 2. Base64url-decode both halves (no-pad).
/// 3. Reject signatures that are not exactly 64 bytes.
/// 4. Postcard-decode the payload as [`LeaseTokenClaims`].
/// 5. Reject unknown frame versions.
/// 6. Verify the ed25519 signature over the postcard-encoded
///    payload bytes under the [`portal_crypto::LeaseToken`]
///    domain separator.
/// 7. Reject if `now >= claims.expires_at`.
///
/// The expiry check happens **after** the signature check, so a
/// well-framed token's signature is always verified before its
/// freshness is judged. Framing / version errors short-circuit
/// before either signature or expiry runs — those failures are
/// non-cryptographic and do not feed an oracle of cryptographic
/// state. Callers that need stronger anti-oracle properties on
/// the framing path should pre-validate the token shape.
///
/// # Errors
///
/// See [`LeaseTokenError`] variants. All are pass-through onto
/// [`crate::error::RelayError::LeaseToken`].
pub fn verify(
    token: &str,
    verifier: &portal_crypto::Ed25519Verifier,
    now: Timestamp,
) -> RelayResult<LeaseTokenClaims> {
    let (payload_b64, sig_b64) = token
        .split_once('.')
        .ok_or(LeaseTokenError::MalformedFraming)?;
    // No second-`.` guard: base64url-no-pad's alphabet excludes `.`,
    // so a stray `.` in `sig_b64` would already fail the URL_SAFE_NO_PAD
    // decode below as `MalformedFraming` — a separate guard here would
    // be dead code.

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| LeaseTokenError::MalformedFraming)?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| LeaseTokenError::MalformedFraming)?;

    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| LeaseTokenError::MalformedSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_array);

    let claims: LeaseTokenClaims = postcard::from_bytes(&payload_bytes)
        .map_err(|e| LeaseTokenError::MalformedClaims(e.to_string()))?;

    if claims.version != LEASE_TOKEN_VERSION {
        return Err(LeaseTokenError::UnsupportedVersion(claims.version).into());
    }

    verifier
        .verify_with_separator::<portal_crypto::LeaseToken>(&payload_bytes, &sig)
        .map_err(|_| LeaseTokenError::SignatureInvalid)?;

    if now.as_second() >= claims.expires_at {
        return Err(LeaseTokenError::Expired.into());
    }

    Ok(claims)
}

// ---------------------------------------------------------------------------
// Inline tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only setup")]
mod tests {
    use super::*;
    use crate::error::RelayError;
    use jiff::SignedDuration;
    use portal_crypto::{
        Ed25519Signer, Ed25519Verifier, ed25519_from_seed_for_test, verifying_key,
    };

    fn fixed_now() -> Timestamp {
        // 2026-05-04 12:00:00 UTC — same anchor as the lease_registry tests.
        Timestamp::from_second(1_778_155_200).unwrap()
    }

    fn ten_minutes_after(t: Timestamp) -> Timestamp {
        t.saturating_add(SignedDuration::from_secs(600))
            .unwrap_or(Timestamp::MAX)
    }

    fn split_token(token: &str) -> (Vec<u8>, Vec<u8>) {
        let (p, s) = token.split_once('.').unwrap();
        let payload = URL_SAFE_NO_PAD.decode(p).unwrap();
        let sig = URL_SAFE_NO_PAD.decode(s).unwrap();
        (payload, sig)
    }

    fn rejoin(payload: &[u8], sig: &[u8]) -> String {
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(sig),
        )
    }

    /// AC1 + AC6: round-trip returns Ok with matching identity and
    /// `expires_at`.
    #[test]
    fn issue_then_verify_round_trip_returns_matching_claims() {
        let key = ed25519_from_seed_for_test([0x11u8; 32]);
        let signer = Ed25519Signer::new(&key);
        let verifier = Ed25519Verifier::new(verifying_key(&key));

        let identity = IdentityKey([0x42u8; 32]);
        let expires_at = ten_minutes_after(fixed_now());
        let token = issue(identity, expires_at, &signer).unwrap();

        let claims = verify(&token, &verifier, fixed_now()).unwrap();
        assert_eq!(claims.version, LEASE_TOKEN_VERSION);
        assert_eq!(claims.identity, identity.0);
        assert_eq!(claims.expires_at, expires_at.as_second());
    }

    /// AC2: `now >= expires_at` returns `LeaseTokenError::Expired`.
    #[test]
    fn verify_rejects_expired_token() {
        let key = ed25519_from_seed_for_test([0x22u8; 32]);
        let signer = Ed25519Signer::new(&key);
        let verifier = Ed25519Verifier::new(verifying_key(&key));

        let identity = IdentityKey([0x11u8; 32]);
        let expires_at = fixed_now();
        let token = issue(identity, expires_at, &signer).unwrap();

        // `now` exactly at expiry — boundary case, must reject.
        let result = verify(&token, &verifier, expires_at);
        assert!(
            matches!(
                result,
                Err(RelayError::LeaseToken(LeaseTokenError::Expired))
            ),
            "expected Expired, got: {result:?}"
        );

        // `now` strictly after expiry — also rejects.
        let later = ten_minutes_after(expires_at);
        let result_later = verify(&token, &verifier, later);
        assert!(
            matches!(
                result_later,
                Err(RelayError::LeaseToken(LeaseTokenError::Expired))
            ),
            "expected Expired (strictly after), got: {result_later:?}"
        );
    }

    /// AC3: flipping a byte in the base64-decoded payload bytes
    /// surfaces `SignatureInvalid`.
    #[test]
    fn verify_rejects_tampered_payload() {
        let key = ed25519_from_seed_for_test([0x33u8; 32]);
        let signer = Ed25519Signer::new(&key);
        let verifier = Ed25519Verifier::new(verifying_key(&key));

        let identity = IdentityKey([0xaau8; 32]);
        let token = issue(identity, ten_minutes_after(fixed_now()), &signer).unwrap();

        let (mut payload, sig) = split_token(&token);
        // Flip a byte in the middle of the identity field (offset 1
        // skips the version byte).
        payload[5] ^= 0xff;
        let tampered = rejoin(&payload, &sig);

        let result = verify(&tampered, &verifier, fixed_now());
        assert!(
            matches!(
                result,
                Err(RelayError::LeaseToken(LeaseTokenError::SignatureInvalid))
            ),
            "expected SignatureInvalid, got: {result:?}"
        );
    }

    /// AC4: flipping a byte in the base64-decoded signature bytes
    /// surfaces `SignatureInvalid`.
    #[test]
    fn verify_rejects_tampered_signature() {
        let key = ed25519_from_seed_for_test([0x44u8; 32]);
        let signer = Ed25519Signer::new(&key);
        let verifier = Ed25519Verifier::new(verifying_key(&key));

        let identity = IdentityKey([0xbbu8; 32]);
        let token = issue(identity, ten_minutes_after(fixed_now()), &signer).unwrap();

        let (payload, mut sig) = split_token(&token);
        sig[10] ^= 0x01;
        let tampered = rejoin(&payload, &sig);

        let result = verify(&tampered, &verifier, fixed_now());
        assert!(
            matches!(
                result,
                Err(RelayError::LeaseToken(LeaseTokenError::SignatureInvalid))
            ),
            "expected SignatureInvalid (tampered sig), got: {result:?}"
        );
    }

    /// AC5: a token whose payload bytes were signed under a
    /// different SEC-007 role (here `RelayDescriptor`) MUST fail
    /// verify (which always pins `<LeaseToken>` internally) as
    /// `SignatureInvalid`.
    #[test]
    fn verify_rejects_wrong_role_signature() {
        let key = ed25519_from_seed_for_test([0x55u8; 32]);
        let signer = Ed25519Signer::new(&key);
        let verifier = Ed25519Verifier::new(verifying_key(&key));

        let identity = IdentityKey([0xccu8; 32]);
        let claims = LeaseTokenClaims {
            version: LEASE_TOKEN_VERSION,
            identity: identity.0,
            issued_at: fixed_now().as_second(),
            expires_at: ten_minutes_after(fixed_now()).as_second(),
        };
        let payload_bytes = postcard::to_allocvec(&claims).unwrap();

        // Sign under a DIFFERENT role separator. The wrong-role test
        // hinges on `verify` always using `<LeaseToken>`, so any
        // other Role-implementor in `portal_crypto::separator` works
        // — `RelayDescriptor` is the most prominent.
        let wrong_sig = signer
            .sign_with_separator::<portal_crypto::RelayDescriptor>(&payload_bytes)
            .unwrap();

        let token = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&payload_bytes),
            URL_SAFE_NO_PAD.encode(wrong_sig.to_bytes()),
        );

        let result = verify(&token, &verifier, fixed_now());
        assert!(
            matches!(
                result,
                Err(RelayError::LeaseToken(LeaseTokenError::SignatureInvalid))
            ),
            "expected SignatureInvalid (wrong role), got: {result:?}"
        );
    }

    /// Defensive: malformed framing (no `.`) is rejected before any
    /// crypto path runs.
    #[test]
    fn verify_rejects_missing_dot_separator() {
        let key = ed25519_from_seed_for_test([0x66u8; 32]);
        let verifier = Ed25519Verifier::new(verifying_key(&key));

        let result = verify("not-a-valid-token", &verifier, fixed_now());
        assert!(
            matches!(
                result,
                Err(RelayError::LeaseToken(LeaseTokenError::MalformedFraming))
            ),
            "expected MalformedFraming, got: {result:?}"
        );
    }
}
