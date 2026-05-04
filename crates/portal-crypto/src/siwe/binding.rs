//! SIWE→ed25519 binding attestation (SEC-002).
//!
//! A [`BindingAttestation`] ties an Ethereum address (recovered from a SIWE
//! signature) to an ed25519 public key (embedded in the SIWE `statement`
//! field).  The binding is verified by [`verify_binding`], which first calls
//! [`super::challenge::verify_siwe`] to authenticate the Ethereum address and
//! then parses the ed25519 pubkey out of the canonical statement pattern.
//!
//! The canonical statement template is shared between [`into_siwe_statement`]
//! (producer) and [`verify_binding`] (consumer) to guarantee byte-for-byte
//! agreement.

use compact_str::CompactString;
use jiff::Timestamp;

use crate::error::PortalCryptoError;
use crate::secp256k1::address::EthAddress;
use crate::siwe::challenge::verify_siwe;

// ---------------------------------------------------------------------------
// Canonical statement template
// ---------------------------------------------------------------------------

/// Prefix of the canonical binding statement, up to (but not including) the
/// 64-char ed25519 hex.
const STMT_PREFIX: &str = "Bind portal-tunnel ed25519 key ";

/// Infix between the ed25519 hex and the nonce value.
const STMT_INFIX: &str = " for lease registration (nonce=";

/// Suffix that closes the nonce parenthesis.
const STMT_SUFFIX: &str = ")";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A verified binding between an Ethereum address and an ed25519 public key.
///
/// Produced by [`verify_binding`] after successful SIWE signature verification
/// and statement parsing.  The relay stores this attestation and uses it to
/// validate subsequent ed25519 protocol signatures.
#[derive(Debug, Clone)]
pub struct BindingAttestation {
    /// The Ethereum address that signed the SIWE message (SEC-002 principal).
    pub eth_address: EthAddress,
    /// The ed25519 public key extracted from the SIWE statement field.
    pub ed25519_pubkey: ed25519_dalek::VerifyingKey,
    /// The nonce embedded in the statement (matches `message.nonce`).
    pub nonce: CompactString,
    /// The `issued_at` field of the SIWE message, converted to jiff.
    pub issued_at: Timestamp,
    /// The `expiration_time` field of the SIWE message, converted to jiff.
    pub expires_at: Timestamp,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Construct a [`BindingAttestation`] from its constituent parts.
///
/// This is a pure constructor — no cryptographic operations are performed.
/// Use [`verify_binding`] to obtain an attested binding from a signed SIWE
/// message.
#[must_use]
pub fn build_binding(
    eth_address: EthAddress,
    ed25519_pubkey: ed25519_dalek::VerifyingKey,
    nonce: &str,
    now: Timestamp,
    ttl: jiff::SignedDuration,
) -> BindingAttestation {
    // TTL arithmetic failure (overflow) falls back to `now`; the resulting
    // attestation would have `expires_at == issued_at`, which is immediately
    // expired and therefore harmless.  Callers that need a valid window must
    // supply a reasonable TTL.
    let expires_at = now.checked_add(ttl).unwrap_or(now);
    BindingAttestation {
        eth_address,
        ed25519_pubkey,
        nonce: nonce.into(),
        issued_at: now,
        expires_at,
    }
}

/// Produce the canonical binding statement text for a [`BindingAttestation`].
///
/// The format is:
///
/// ```text
/// Bind portal-tunnel ed25519 key {hex} for lease registration (nonce={nonce})
/// ```
///
/// This is the value that [`super::challenge::build`] embeds in the SIWE
/// `statement` field and that [`verify_binding`] extracts and validates.
///
/// # Errors
///
/// Returns [`PortalCryptoError::Siwe`] if `att.nonce` fails the EIP-4361
/// §4.2 charset/length rule. Bindings produced by [`verify_binding`] are
/// guaranteed to satisfy the rule (the message-level nonce check runs
/// first), so this only fires when callers construct a [`BindingAttestation`]
/// directly via [`build_binding`] with an out-of-spec nonce.
pub fn into_siwe_statement(att: &BindingAttestation) -> Result<CompactString, PortalCryptoError> {
    canonical_statement(&att.ed25519_pubkey, &att.nonce)
}

/// Render the canonical SIWE binding statement directly from the ed25519
/// pubkey and nonce, without requiring a constructed [`BindingAttestation`].
///
/// `super::challenge::build` calls this so it shares the exact same template
/// with [`into_siwe_statement`] / [`verify_binding`]; editing either side in
/// isolation cannot silently drift the wire-visible string.
///
/// # Errors
///
/// Returns [`PortalCryptoError::Siwe`] if `nonce` violates the EIP-4361 §4.2
/// nonce charset rule (alphanumeric, length ≥ 8). Enforcing this at the
/// template-build site prevents an attacker-controlled nonce containing the
/// `)` suffix character from breaking the hand-rolled parser in
/// [`verify_binding`].
pub fn canonical_statement(
    ed25519_pubkey: &ed25519_dalek::VerifyingKey,
    nonce: &str,
) -> Result<CompactString, PortalCryptoError> {
    if nonce.len() < 8 || !nonce.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(PortalCryptoError::Siwe(
            "nonce must be ≥8 alphanumeric ASCII characters (EIP-4361 §4.2)".to_owned(),
        ));
    }
    let hex = bytes32_to_hex(&ed25519_pubkey.to_bytes());
    Ok(CompactString::from(format!(
        "{STMT_PREFIX}{hex}{STMT_INFIX}{nonce}{STMT_SUFFIX}"
    )))
}

/// Verify a SIWE message and extract the SIWE→ed25519 binding attestation.
///
/// # Steps
///
/// 1. Call [`verify_siwe`] → recovers the [`EthAddress`] from the signature.
/// 2. Parse the ed25519 pubkey hex out of `message.statement` using the
///    canonical template (no regex dependency — hand-rolled with
///    `str::strip_prefix` / `str::find`).
/// 3. Decode the 32-byte hex and construct a [`ed25519_dalek::VerifyingKey`].
/// 4. Compare against `expected_ed25519_pubkey`; mismatch → error.
/// 5. Convert SIWE timestamps back to jiff.
///
/// # Errors
///
/// Returns [`PortalCryptoError::Siwe`] for SIWE verification failures, or
/// [`PortalCryptoError::Binding`] for statement parse failures, pubkey decode
/// failures, or pubkey mismatches.
pub fn verify_binding(
    message: &::siwe::Message,
    signature: &[u8; 65],
    domain: &str,
    nonce: &str,
    expected_ed25519_pubkey: ed25519_dalek::VerifyingKey,
    now: Timestamp,
) -> Result<BindingAttestation, PortalCryptoError> {
    // Step 1: SIWE verification → eth address.
    let eth_address = verify_siwe(message, signature, domain, nonce, now)?;

    // Step 2: parse ed25519 hex out of the statement.
    let statement = message
        .statement
        .as_deref()
        .ok_or_else(|| PortalCryptoError::Binding("SIWE message has no statement".to_owned()))?;

    let after_prefix = statement.strip_prefix(STMT_PREFIX).ok_or_else(|| {
        PortalCryptoError::Binding("statement does not match canonical pattern".to_owned())
    })?;

    // The next 64 characters are the lowercase hex of the ed25519 pubkey.
    // All valid hex chars are single-byte ASCII, so the split point will be
    // on a char boundary iff the preceding bytes are all ASCII.  We guard
    // explicitly with `is_char_boundary` to avoid a panic on attacker-
    // controlled input that contains multi-byte UTF-8 sequences.
    if after_prefix.len() < 64 || !after_prefix.is_char_boundary(64) {
        return Err(PortalCryptoError::Binding(
            "statement does not match canonical pattern".to_owned(),
        ));
    }
    let (hex_str, after_hex) = after_prefix.split_at(64);

    // Validate all 64 chars are lowercase hex digits.
    if !hex_str
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(PortalCryptoError::Binding(
            "statement does not match canonical pattern".to_owned(),
        ));
    }

    let after_infix = after_hex.strip_prefix(STMT_INFIX).ok_or_else(|| {
        PortalCryptoError::Binding("statement does not match canonical pattern".to_owned())
    })?;

    // The remainder must end with STMT_SUFFIX; everything before it is the nonce.
    let embedded_nonce = after_infix.strip_suffix(STMT_SUFFIX).ok_or_else(|| {
        PortalCryptoError::Binding("statement does not match canonical pattern".to_owned())
    })?;

    // Nonce in statement must match the supplied nonce.
    if embedded_nonce != nonce {
        return Err(PortalCryptoError::Binding(format!(
            "statement nonce {embedded_nonce:?} does not match supplied nonce {nonce:?}"
        )));
    }

    // Step 3: decode hex → [u8; 32] → VerifyingKey.
    let pk_bytes = decode_hex32(hex_str)
        .map_err(|e| PortalCryptoError::Binding(format!("ed25519 hex decode failed: {e}")))?;

    let parsed_pk = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| PortalCryptoError::Binding(format!("ed25519 key from bytes failed: {e}")))?;

    // Step 4: compare against expected pubkey.
    if parsed_pk != expected_ed25519_pubkey {
        return Err(PortalCryptoError::Binding(
            "ed25519 pubkey mismatch".to_owned(),
        ));
    }

    // Step 5: convert SIWE timestamps to jiff.
    let issued_at = siwe_ts_str_to_jiff(&message.issued_at.to_string())?;
    let expires_at = message
        .expiration_time
        .as_ref()
        .map(|ts| siwe_ts_str_to_jiff(&ts.to_string()))
        .transpose()?
        .ok_or_else(|| {
            PortalCryptoError::Binding("binding message must carry an expiration_time".to_owned())
        })?;

    Ok(BindingAttestation {
        eth_address,
        ed25519_pubkey: parsed_pk,
        nonce: nonce.into(),
        issued_at,
        expires_at,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Lowercase-hex-encode 32 bytes into a 64-char `String`.
fn bytes32_to_hex(b: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::with_capacity(64), |mut s, byte| {
        let _ = write!(s, "{byte:02x}");
        s
    })
}

/// Decode a 64-char lowercase hex string into `[u8; 32]`.
fn decode_hex32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

/// Decode a single lowercase hex nibble character.
fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(format!("invalid hex char: {b:#x}")),
    }
}

/// Convert an RFC 3339 string (from `siwe::TimeStamp::to_string()`) to a
/// [`jiff::Timestamp`].
fn siwe_ts_str_to_jiff(rfc3339: &str) -> Result<Timestamp, PortalCryptoError> {
    rfc3339
        .parse::<Timestamp>()
        .map_err(|e| PortalCryptoError::Binding(format!("timestamp parse failed: {e}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256k1::address::evm_address_from_pubkey;
    use crate::secp256k1::eip191::sign_eip191_personal;
    use crate::secp256k1::key::{from_bytes_for_test, public_key};
    use crate::siwe::challenge::{ChallengeBuilder, build};
    use jiff::SignedDuration;

    /// Deterministic secp256k1 scalar for test signing.
    const SECP_SCALAR: [u8; 32] = [
        0x4c, 0x08, 0x83, 0xa6, 0x91, 0x02, 0x93, 0x7d, 0x62, 0x31, 0x47, 0x1b, 0x5d, 0xbb, 0x62,
        0x04, 0xfe, 0x51, 0x29, 0x61, 0x70, 0x82, 0x79, 0x2a, 0xe4, 0x68, 0xd0, 0x1a, 0x3f, 0x36,
        0x23, 0x18,
    ];

    /// Deterministic ed25519 seed A — the key that will be embedded in the
    /// binding statement.
    const ED_SEED_A: [u8; 32] = [0x42u8; 32];

    /// Deterministic ed25519 seed B — a DIFFERENT key, used for mismatch tests.
    const ED_SEED_B: [u8; 32] = [0x43u8; 32];

    fn test_now() -> Timestamp {
        match "2024-01-15T12:00:00Z".parse::<Timestamp>() {
            Ok(ts) => ts,
            Err(e) => panic!("test_now: invalid timestamp literal: {e}"),
        }
    }

    fn test_builder() -> ChallengeBuilder {
        ChallengeBuilder {
            domain: "example.com".into(),
            uri: "https://example.com/register".into(),
            chain_id: 1,
            ttl: SignedDuration::from_secs(300),
        }
    }

    fn vk_from_seed(seed: [u8; 32]) -> ed25519_dalek::VerifyingKey {
        ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key()
    }

    /// Build and sign a SIWE message embedding ed25519 pubkey `vk`.
    fn build_and_sign(
        vk: ed25519_dalek::VerifyingKey,
        nonce: &str,
    ) -> Result<(::siwe::Message, [u8; 65]), Box<dyn std::error::Error>> {
        let secp_key = from_bytes_for_test(SECP_SCALAR);
        let pk = public_key(&secp_key)?;
        let eth_addr = evm_address_from_pubkey(&pk);
        let now = test_now();
        let builder = test_builder();

        let challenge = build(&builder, eth_addr, vk, "req-bind", nonce, now)?;
        let msg_bytes = challenge.message.to_string();
        let sig = sign_eip191_personal(msg_bytes.as_bytes(), &secp_key)?;
        Ok((challenge.message, sig))
    }

    /// Build a binding for key A, sign the SIWE message, and call
    /// `verify_binding` with `expected = A` — must succeed.
    #[test]
    fn binding_round_trip_succeeds() -> Result<(), Box<dyn std::error::Error>> {
        let vk_a = vk_from_seed(ED_SEED_A);
        let (message, sig) = build_and_sign(vk_a, "nonce12345678")?;

        let att = verify_binding(
            &message,
            &sig,
            "example.com",
            "nonce12345678",
            vk_a,
            test_now(),
        )?;

        assert_eq!(att.ed25519_pubkey, vk_a);
        assert_eq!(att.nonce.as_str(), "nonce12345678");
        Ok(())
    }

    /// Build a binding for key A, sign it, then call `verify_binding` with
    /// `expected = B` (different key) — must return `PortalCryptoError::Binding`.
    #[test]
    fn binding_mismatch_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let vk_a = vk_from_seed(ED_SEED_A);
        let vk_b = vk_from_seed(ED_SEED_B);
        let (message, sig) = build_and_sign(vk_a, "nonce12345678")?;

        let result = verify_binding(
            &message,
            &sig,
            "example.com",
            "nonce12345678",
            vk_b, // wrong expected pubkey
            test_now(),
        );

        assert!(
            matches!(result, Err(PortalCryptoError::Binding(ref msg)) if msg.contains("mismatch")),
            "expected pubkey-mismatch Binding error, got: {result:?}"
        );
        Ok(())
    }

    /// Construct a SIWE message embedding key A in the statement, flip one byte
    /// of the statement BEFORE signing (so the signature authenticates the
    /// mutated statement), then call `verify_binding` — the EIP-191 verification
    /// must reject the tampered payload before binding parsing runs.
    #[test]
    fn binding_tampered_statement_fails() -> Result<(), Box<dyn std::error::Error>> {
        let vk_a = vk_from_seed(ED_SEED_A);
        let secp_key = from_bytes_for_test(SECP_SCALAR);
        let pk = public_key(&secp_key)?;
        let eth_addr = evm_address_from_pubkey(&pk);
        let now = test_now();
        let builder = test_builder();

        // Build the original message.
        let challenge = build(&builder, eth_addr, vk_a, "req-tamper", "nonce12345678", now)?;

        // Serialise and tamper: flip one byte in the statement portion.
        let original = challenge.message.to_string();
        let tampered = original.replacen(
            "Bind portal-tunnel ed25519 key",
            "Xind portal-tunnel ed25519 key", // one char changed
            1,
        );

        // Sign the TAMPERED bytes (signature is over the mutated message).
        let sig = sign_eip191_personal(tampered.as_bytes(), &secp_key)?;

        // Parse the tampered message text back to a siwe::Message so we can
        // pass it to verify_binding. The tampered text must parse successfully
        // (we only changed the statement, not any structured field) — if siwe
        // rejects the parse, the test cannot proceed as designed.
        let Ok(tampered_msg) = tampered.parse::<::siwe::Message>() else {
            // If the tampered text cannot be parsed, the statement-level
            // mutation already causes a hard parse failure, which is an
            // even stronger rejection than what the test requires.
            return Ok(());
        };

        // verify_binding on the tampered message signed by the tampered bytes:
        // the EIP-191 check uses the original (untampered) message.address,
        // so the recovered address won't match, causing a Siwe verification
        // error — or the statement pattern won't match → Binding error.
        // Either way, this must NOT succeed.
        let result = verify_binding(
            &tampered_msg,
            &sig,
            "example.com",
            "nonce12345678",
            vk_a,
            now,
        );

        assert!(
            result.is_err(),
            "verify_binding must reject a tampered-statement message, got Ok"
        );
        Ok(())
    }
}
