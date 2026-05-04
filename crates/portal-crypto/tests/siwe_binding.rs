//! Integration tests for the SIWE→ed25519 binding attestation (SEC-002).
//!
//! These tests call the public `portal_crypto` API end-to-end:
//! [`portal_crypto::build_siwe_challenge`] → EIP-191 sign →
//! [`portal_crypto::verify_binding`].
//!
//! Three cases are covered:
//!
//! 1. **`binding_round_trip_succeeds`** — happy path: embed key A, sign, verify
//!    with `expected = A` → `Ok(BindingAttestation)`.
//! 2. **`binding_mismatch_fails_closed`** — embed key A, sign, verify with
//!    `expected = B` → `Err(PortalCryptoError::Binding(_))`.
//! 3. **`binding_tampered_statement_fails`** — flip one hex digit inside the
//!    64-char ed25519 pubkey hex in the statement, THEN sign the mutated text,
//!    THEN call `verify_binding` with the original expected key.  This preserves
//!    SIWE parsability (only the statement text changes) and guarantees that
//!    `verify_binding` must return `Err(PortalCryptoError::Binding(_))` because
//!    the recovered pubkey from the tampered statement does not match `expected`.
//!
//! Phase 2 B8 / U13 / SEC-002.

use jiff::{SignedDuration, Timestamp};
use portal_crypto::{
    BindingAttestation, ChallengeBuilder, EthAddress, PortalCryptoError, build_siwe_challenge,
    ed25519_from_seed_for_test, evm_address_from_pubkey, secp256k1_from_bytes_for_test,
    sign_eip191_personal, tenant_public_key, verify_binding, verifying_key,
};

// ---------------------------------------------------------------------------
// Shared test constants
// ---------------------------------------------------------------------------

/// Deterministic secp256k1 scalar for signing SIWE challenges.
const SECP_SCALAR: [u8; 32] = [
    0x4c, 0x08, 0x83, 0xa6, 0x91, 0x02, 0x93, 0x7d, 0x62, 0x31, 0x47, 0x1b, 0x5d, 0xbb, 0x62, 0x04,
    0xfe, 0x51, 0x29, 0x61, 0x70, 0x82, 0x79, 0x2a, 0xe4, 0x68, 0xd0, 0x1a, 0x3f, 0x36, 0x23, 0x18,
];

/// ed25519 seed A — the key embedded in the binding statement.
const ED_SEED_A: [u8; 32] = [0x42u8; 32];

/// ed25519 seed B — a distinct key used for the mismatch test.
const ED_SEED_B: [u8; 32] = [0x43u8; 32];

/// The canonical binding statement prefix (must match `binding.rs` `STMT_PREFIX`).
const STMT_PREFIX: &str = "Bind portal-tunnel ed25519 key ";

// ---------------------------------------------------------------------------
// Test helpers (all return Result to avoid `.expect()`)
// ---------------------------------------------------------------------------

fn test_now() -> Result<Timestamp, Box<dyn std::error::Error>> {
    Ok("2024-01-15T12:00:00Z".parse::<Timestamp>()?)
}

fn test_builder() -> ChallengeBuilder {
    ChallengeBuilder {
        domain: "example.com".into(),
        uri: "https://example.com/register".into(),
        chain_id: 1,
        ttl: SignedDuration::from_secs(300),
    }
}

/// Derive the `EthAddress` from a secp256k1 scalar.
fn eth_address_from_scalar(scalar: [u8; 32]) -> Result<EthAddress, Box<dyn std::error::Error>> {
    let key = secp256k1_from_bytes_for_test(scalar);
    let pk = tenant_public_key(&key)?;
    Ok(evm_address_from_pubkey(&pk))
}

/// Build a SIWE challenge embedding `vk`, sign it with `secp_scalar`, and
/// return the `(siwe::Message, [u8; 65])` pair.
fn build_and_sign(
    vk: ed25519_dalek::VerifyingKey,
    nonce: &str,
    secp_scalar: [u8; 32],
) -> Result<(::siwe::Message, [u8; 65]), Box<dyn std::error::Error>> {
    let eth_addr = eth_address_from_scalar(secp_scalar)?;
    let now = test_now()?;
    let builder = test_builder();

    let challenge = build_siwe_challenge(&builder, eth_addr, vk, "req-bind", nonce, now)?;

    let secp_key = secp256k1_from_bytes_for_test(secp_scalar);
    let msg_bytes = challenge.message.to_string();
    let sig = sign_eip191_personal(msg_bytes.as_bytes(), &secp_key)?;
    Ok((challenge.message, sig))
}

// ---------------------------------------------------------------------------
// Test 1: happy-path round-trip
// ---------------------------------------------------------------------------

/// Build a SIWE message embedding ed25519 pubkey A, sign with the secp256k1
/// key, verify with `expected_ed25519_pubkey = A`.  Must return a
/// [`BindingAttestation`] whose `ed25519_pubkey` matches A.
#[test]
fn binding_round_trip_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let key_a = ed25519_from_seed_for_test(ED_SEED_A);
    let vk_a = verifying_key(&key_a);

    let (message, sig) = build_and_sign(vk_a, "nonce12345678", SECP_SCALAR)?;

    let att: BindingAttestation = verify_binding(
        &message,
        &sig,
        "example.com",
        "nonce12345678",
        vk_a,
        test_now()?,
    )?;

    assert_eq!(
        att.ed25519_pubkey, vk_a,
        "attestation pubkey must match key A"
    );
    assert_eq!(att.nonce.as_str(), "nonce12345678");
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 2: expected-pubkey mismatch is rejected
// ---------------------------------------------------------------------------

/// Build a SIWE message embedding ed25519 pubkey A, sign it, then call
/// `verify_binding` with `expected_ed25519_pubkey = B` (a different key).
/// Must return `Err(PortalCryptoError::Binding(_))`.
#[test]
fn binding_mismatch_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let key_a = ed25519_from_seed_for_test(ED_SEED_A);
    let vk_a = verifying_key(&key_a);

    let key_b = ed25519_from_seed_for_test(ED_SEED_B);
    let vk_b = verifying_key(&key_b);

    let (message, sig) = build_and_sign(vk_a, "nonce12345678", SECP_SCALAR)?;

    let result = verify_binding(
        &message,
        &sig,
        "example.com",
        "nonce12345678",
        vk_b, // wrong expected pubkey
        test_now()?,
    );

    assert!(
        matches!(result, Err(PortalCryptoError::Binding(ref msg)) if msg.contains("mismatch")),
        "expected pubkey-mismatch Binding error, got: {result:?}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 3: tampered statement (hex digit flip) is rejected
// ---------------------------------------------------------------------------

/// Build a SIWE challenge embedding key A's pubkey hex in the statement, then
/// flip one hex digit inside that 64-char pubkey hex (preserving SIWE
/// parsability — only the statement text changes), sign the mutated text, and
/// call `verify_binding` with `expected = vk_a`.
///
/// The flipped digit changes the embedded pubkey, so `verify_binding` must
/// return `Err(PortalCryptoError::Binding(_))` — either because the recovered
/// pubkey doesn't match `expected`, or because the flipped bytes produce an
/// invalid curve point.
///
/// This mutation strategy is chosen specifically because it:
/// - Keeps the `"Bind portal-tunnel ed25519 key "` prefix intact (SIWE parser
///   treats `statement` as opaque text; no parse failure).
/// - Keeps the rest of the statement structure intact.
/// - Guarantees `verify_binding` reaches its ed25519 comparison step.
#[test]
fn binding_tampered_statement_fails() -> Result<(), Box<dyn std::error::Error>> {
    let key_a = ed25519_from_seed_for_test(ED_SEED_A);
    let vk_a = verifying_key(&key_a);

    let eth_addr = eth_address_from_scalar(SECP_SCALAR)?;
    let now = test_now()?;
    let builder = test_builder();

    // Build the original (untampered) challenge.
    let challenge =
        build_siwe_challenge(&builder, eth_addr, vk_a, "req-tamper", "nonce12345678", now)?;

    let original = challenge.message.to_string();

    // Locate the 64-char pubkey hex within the statement.
    // The statement is: "Bind portal-tunnel ed25519 key <64 hex chars> for ..."
    // We flip the very last hex char of the pubkey (position: prefix_len + 63).
    let prefix_pos = original
        .find(STMT_PREFIX)
        .ok_or("STMT_PREFIX not found in serialised SIWE message")?;
    let hex_start = prefix_pos + STMT_PREFIX.len();
    let hex_end = hex_start + 64;

    // Sanity: the 64 chars after the prefix must all be lowercase hex.
    let hex_slice = &original[hex_start..hex_end];
    assert!(
        hex_slice
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "expected 64 lowercase hex chars at offset {hex_start}, got: {hex_slice:?}"
    );

    // Flip the last hex digit: '0'..='e' → increment by 1; 'f' → '0'.
    let flip_pos = hex_end - 1; // byte index of last hex char in original
    let original_char = original.as_bytes()[flip_pos];
    let flipped_char = if original_char == b'f' {
        b'0'
    } else {
        original_char + 1
    };

    let tampered = format!(
        "{}{}{}",
        &original[..flip_pos],
        flipped_char as char,
        &original[flip_pos + 1..],
    );

    // The tampered text must parse as a valid siwe::Message.
    // The statement field is free-form text, so SIWE cannot reject this.
    let tampered_msg = tampered
        .parse::<::siwe::Message>()
        .map_err(|e| format!("tampered SIWE text failed to parse (unexpected): {e}"))?;

    // Sign the TAMPERED bytes with the secp256k1 key.
    let secp_key = secp256k1_from_bytes_for_test(SECP_SCALAR);
    let sig = sign_eip191_personal(tampered.as_bytes(), &secp_key)?;

    // verify_binding must fail: the embedded pubkey hex no longer matches vk_a.
    let result = verify_binding(
        &tampered_msg,
        &sig,
        "example.com",
        "nonce12345678",
        vk_a,
        now,
    );

    assert!(
        matches!(result, Err(PortalCryptoError::Binding(_))),
        "expected Binding error for tampered-hex statement, got: {result:?}"
    );
    Ok(())
}
