//! SIWE challenge construction and synchronous EIP-191 verification.
//!
//! [`build`] constructs an EIP-4361 [`::siwe::Message`] embedding the
//! portal-tunnel ed25519 binding statement.  [`verify_siwe`] synchronously
//! verifies a 65-byte EIP-191 signature over that message, performing domain,
//! nonce, and timestamp window checks before the cryptographic step.
//!
//! **Go reference:** `portal-tunnel/portal/auth/register_challenge.go`.

use std::str::FromStr as _;

use compact_str::CompactString;
use jiff::{SignedDuration, Timestamp};

use crate::error::PortalCryptoError;
use crate::secp256k1::address::EthAddress;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Configuration used to construct a SIWE challenge message.
///
/// A `ChallengeBuilder` is typically loaded from the relay's runtime
/// configuration and reused across multiple challenge construction calls.
#[derive(Debug, Clone)]
pub struct ChallengeBuilder {
    /// The RFC 3986 authority (host\[:port\]) of the relying party.
    pub domain: CompactString,
    /// The RFC 3986 URI identifying the resource the user is authenticating
    /// against.
    pub uri: CompactString,
    /// The EIP-155 chain ID to bind the session to.
    pub chain_id: u64,
    /// How long a challenge is valid for after `issued_at`.
    pub ttl: SignedDuration,
}

/// Output of [`build`]: a constructed SIWE message and its expiry instant.
#[derive(Debug, Clone)]
pub struct RegisterChallenge {
    /// The EIP-4361 message ready to be serialised (via `to_string()`) and
    /// sent to the client for signing.
    pub message: ::siwe::Message,
    /// The absolute timestamp at which this challenge expires.
    ///
    /// Equals `issued_at + builder.ttl`.
    pub expires_at: Timestamp,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a [`jiff::Timestamp`] to a [`::siwe::TimeStamp`] via its RFC 3339
/// string representation.
///
/// # Errors
///
/// Returns [`PortalCryptoError::Siwe`] if the jiff timestamp cannot be
/// formatted or the resulting string fails to parse as an RFC 3339 timestamp.
fn jiff_to_siwe_ts(ts: Timestamp) -> Result<::siwe::TimeStamp, PortalCryptoError> {
    // jiff::Timestamp Display produces RFC 3339 (e.g. "2021-12-07T18:28:18Z").
    let rfc3339 = ts.to_string();
    ::siwe::TimeStamp::from_str(&rfc3339)
        .map_err(|e| PortalCryptoError::Siwe(format!("timestamp conversion: {e}")))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Construct a SIWE challenge message embedding a portal-tunnel ed25519
/// binding statement.
///
/// The `statement` field of the returned [`::siwe::Message`] is:
///
/// ```text
/// Bind portal-tunnel ed25519 key {hex} for lease registration (nonce={nonce})
/// ```
///
/// where `hex` is the 64-char lowercase hex encoding of `ed25519_pk.to_bytes()`.
///
/// # Errors
///
/// Returns [`PortalCryptoError::Siwe`] if any siwe field fails to construct
/// (e.g. malformed `domain` or `uri`) or if the timestamp arithmetic overflows.
pub fn build(
    builder: &ChallengeBuilder,
    eth_address: EthAddress,
    ed25519_pk: ed25519_dalek::VerifyingKey,
    request_id: &str,
    nonce: &str,
    now: Timestamp,
) -> Result<RegisterChallenge, PortalCryptoError> {
    // Compute expiry before constructing the message so we fail fast if the
    // duration addition overflows.
    let expires_at = now
        .checked_add(builder.ttl)
        .map_err(|e| PortalCryptoError::Siwe(format!("TTL addition overflowed timestamp: {e}")))?;

    let domain = builder
        .domain
        .parse::<http::uri::Authority>()
        .map_err(|e| PortalCryptoError::Siwe(format!("invalid domain: {e}")))?;

    let uri = builder
        .uri
        .parse::<iri_string::types::UriString>()
        .map_err(|e| PortalCryptoError::Siwe(format!("invalid uri: {e}")))?;

    // Single canonical template — drift between challenge.rs and binding.rs
    // is structurally impossible because both call sites go through
    // `binding::canonical_statement` (SEC-002 anti-drift invariant).
    let statement = super::binding::canonical_statement(&ed25519_pk, nonce).into_string();

    let issued_at = jiff_to_siwe_ts(now)?;
    let expiration_time = Some(jiff_to_siwe_ts(expires_at)?);

    let message = ::siwe::Message {
        domain,
        address: *eth_address.as_bytes(),
        statement: Some(statement),
        uri,
        version: ::siwe::Version::V1,
        chain_id: builder.chain_id,
        nonce: nonce.to_owned(),
        issued_at,
        expiration_time,
        not_before: None,
        request_id: Some(request_id.to_owned()),
        resources: vec![],
    };

    Ok(RegisterChallenge {
        message,
        expires_at,
    })
}

/// Verify a 65-byte EIP-191 signature over a SIWE message.
///
/// Performs three pre-checks before the cryptographic step:
///
/// 1. `domain` matches `message.domain`.
/// 2. `nonce` matches `message.nonce`.
/// 3. `now` falls within `[issued_at, expiration_time)`.
///
/// On success, returns the [`EthAddress`] recovered from the signature.
///
/// # Errors
///
/// Returns [`PortalCryptoError::Siwe`] for any mismatch or cryptographic
/// failure.
pub fn verify_siwe(
    message: &::siwe::Message,
    signature: &[u8; 65],
    domain: &str,
    nonce: &str,
    now: Timestamp,
) -> Result<EthAddress, PortalCryptoError> {
    // 1. Domain check.
    if message.domain.as_str() != domain {
        return Err(PortalCryptoError::Siwe(format!(
            "domain mismatch: expected {domain}, got {}",
            message.domain
        )));
    }

    // 2. Nonce check.
    if message.nonce != nonce {
        return Err(PortalCryptoError::Siwe(format!(
            "nonce mismatch: expected {nonce}, got {}",
            message.nonce
        )));
    }

    // 3. Timestamp window check.
    //    Convert `now` to a siwe TimeStamp for comparison with message fields.
    let now_siwe = jiff_to_siwe_ts(now)?;
    let now_odt = *now_siwe.as_ref(); // time::OffsetDateTime

    // `issued_at <= now`
    if message.issued_at.as_ref() > &now_odt {
        return Err(PortalCryptoError::Siwe(
            "message is not yet valid (issued_at is in the future)".to_owned(),
        ));
    }

    // `now < expiration_time` (if set)
    if message
        .expiration_time
        .as_ref()
        .is_some_and(|exp| exp.as_ref() <= &now_odt)
    {
        return Err(PortalCryptoError::Siwe("message has expired".to_owned()));
    }

    // 4. Cryptographic EIP-191 verification.
    message
        .verify_eip191(signature)
        .map_err(|e| PortalCryptoError::Siwe(format!("eip191 verification failed: {e}")))?;

    Ok(EthAddress::new(message.address))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::*;
    use crate::secp256k1::address::evm_address_from_pubkey;
    use crate::secp256k1::eip191::sign_eip191_personal;
    use crate::secp256k1::key::{from_bytes_for_test, public_key};

    /// A deterministic secp256k1 scalar used across all challenge tests.
    const SECP_SCALAR: [u8; 32] = [
        0x4c, 0x08, 0x83, 0xa6, 0x91, 0x02, 0x93, 0x7d, 0x62, 0x31, 0x47, 0x1b, 0x5d, 0xbb, 0x62,
        0x04, 0xfe, 0x51, 0x29, 0x61, 0x70, 0x82, 0x79, 0x2a, 0xe4, 0x68, 0xd0, 0x1a, 0x3f, 0x36,
        0x23, 0x18,
    ];

    /// A deterministic ed25519 seed.
    const ED_SEED: [u8; 32] = [0x42u8; 32];

    fn test_builder() -> ChallengeBuilder {
        ChallengeBuilder {
            domain: "example.com".into(),
            uri: "https://example.com/register".into(),
            chain_id: 1,
            ttl: SignedDuration::from_secs(300),
        }
    }

    fn test_now() -> Timestamp {
        // 2024-01-15T12:00:00Z — fixed instant for deterministic tests.
        match "2024-01-15T12:00:00Z".parse::<Timestamp>() {
            Ok(ts) => ts,
            Err(e) => panic!("test_now: invalid timestamp literal: {e}"),
        }
    }

    fn ed25519_vk_from_seed(seed: [u8; 32]) -> ed25519_dalek::VerifyingKey {
        ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key()
    }

    fn sign_siwe_message(
        msg: &::siwe::Message,
        scalar: [u8; 32],
    ) -> Result<[u8; 65], Box<dyn std::error::Error>> {
        let key = from_bytes_for_test(scalar);
        let msg_bytes = msg.to_string();
        let sig = sign_eip191_personal(msg_bytes.as_bytes(), &key)?;
        Ok(sig)
    }

    /// Build a challenge and re-parse the serialised EIP-4361 message; all
    /// fields including the statement must survive the round-trip byte-for-byte.
    #[test]
    fn build_then_parse_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let key = from_bytes_for_test(SECP_SCALAR);
        let pk = public_key(&key)?;
        let eth_addr = evm_address_from_pubkey(&pk);
        let vk = ed25519_vk_from_seed(ED_SEED);
        let now = test_now();
        let builder = test_builder();

        let challenge = build(&builder, eth_addr, vk, "req-001", "nonce12345678", now)?;

        let serialised = challenge.message.to_string();
        let reparsed = ::siwe::Message::from_str(&serialised)
            .map_err(|e| format!("reparsed message should be valid EIP-4361: {e}"))?;

        assert_eq!(reparsed.domain, challenge.message.domain);
        assert_eq!(reparsed.address, challenge.message.address);
        assert_eq!(reparsed.statement, challenge.message.statement);
        assert_eq!(reparsed.nonce, challenge.message.nonce);
        assert_eq!(reparsed.chain_id, challenge.message.chain_id);
        assert_eq!(reparsed.version, challenge.message.version);
        Ok(())
    }

    /// Sign a valid challenge, then call `verify_siwe` with a mismatched domain;
    /// expect `PortalCryptoError::Siwe`.
    #[test]
    fn verify_with_wrong_domain_fails() -> Result<(), Box<dyn std::error::Error>> {
        let key = from_bytes_for_test(SECP_SCALAR);
        let pk = public_key(&key)?;
        let eth_addr = evm_address_from_pubkey(&pk);
        let vk = ed25519_vk_from_seed(ED_SEED);
        let now = test_now();
        let builder = test_builder();

        let challenge = build(&builder, eth_addr, vk, "req-002", "nonce12345678", now)?;
        let sig = sign_siwe_message(&challenge.message, SECP_SCALAR)?;

        let result = verify_siwe(
            &challenge.message,
            &sig,
            "wrong-domain.com", // mismatch
            "nonce12345678",
            now,
        );

        assert!(
            matches!(result, Err(PortalCryptoError::Siwe(ref msg)) if msg.contains("domain")),
            "expected domain-mismatch Siwe error, got: {result:?}"
        );
        Ok(())
    }

    /// Sign a valid challenge, then call `verify_siwe` with a mismatched nonce;
    /// expect `PortalCryptoError::Siwe`.
    #[test]
    fn verify_with_wrong_nonce_fails() -> Result<(), Box<dyn std::error::Error>> {
        let key = from_bytes_for_test(SECP_SCALAR);
        let pk = public_key(&key)?;
        let eth_addr = evm_address_from_pubkey(&pk);
        let vk = ed25519_vk_from_seed(ED_SEED);
        let now = test_now();
        let builder = test_builder();

        let challenge = build(&builder, eth_addr, vk, "req-003", "nonce12345678", now)?;
        let sig = sign_siwe_message(&challenge.message, SECP_SCALAR)?;

        let result = verify_siwe(
            &challenge.message,
            &sig,
            "example.com",
            "wrong-nonce1234", // mismatch
            now,
        );

        assert!(
            matches!(result, Err(PortalCryptoError::Siwe(ref msg)) if msg.contains("nonce")),
            "expected nonce-mismatch Siwe error, got: {result:?}"
        );
        Ok(())
    }

    /// Sign a valid challenge, then verify with a `now` past `expiration_time`;
    /// expect `PortalCryptoError::Siwe`.
    #[test]
    fn verify_with_expired_window_fails() -> Result<(), Box<dyn std::error::Error>> {
        let key = from_bytes_for_test(SECP_SCALAR);
        let pk = public_key(&key)?;
        let eth_addr = evm_address_from_pubkey(&pk);
        let vk = ed25519_vk_from_seed(ED_SEED);
        let now = test_now();
        let builder = test_builder();

        let challenge = build(&builder, eth_addr, vk, "req-004", "nonce12345678", now)?;
        let sig = sign_siwe_message(&challenge.message, SECP_SCALAR)?;

        // advance `now` well past TTL (300 s + 1 s margin)
        let future_now = challenge
            .expires_at
            .checked_add(SignedDuration::from_secs(1))
            .map_err(|e| format!("checked_add overflow in test: {e}"))?;

        let result = verify_siwe(
            &challenge.message,
            &sig,
            "example.com",
            "nonce12345678",
            future_now,
        );

        assert!(
            matches!(result, Err(PortalCryptoError::Siwe(ref msg)) if msg.contains("expired")),
            "expected expiry Siwe error, got: {result:?}"
        );
        Ok(())
    }
}
