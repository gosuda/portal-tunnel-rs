// INVARIANT: canonical_voucher_bytes emits fixed JSON field order with Unix-nanosecond timestamps.
// Signature is 65-byte btcsuite compact recoverable secp256k1: header[1] || r[32] || s[32],
// header = 27 + 4 + recovery_id (compressed-key convention, matching Go's SignSHA256Secp256k1Compact).

use anyhow::Context;
use chrono::{DateTime, TimeDelta, Utc};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::identity::{address_from_verifying_key, normalize_evm_address};

/// Clock-skew tolerance applied when validating voucher issuance/expiry windows.
const VOUCHER_CLOCK_SKEW_TOLERANCE: TimeDelta = TimeDelta::minutes(5);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReservationVoucher {
    pub client_address: String,
    pub relay_url: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Vec::is_empty", default, with = "base64_bytes")]
    pub signature: Vec<u8>,
}

mod base64_bytes {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Canonical bytes for signing — matches Go's `ReservationVoucher.CanonicalBytes()`.
/// Fixed field order, Unix-nanosecond timestamps, no signature field.
fn canonical_voucher_bytes(v: &ReservationVoucher) -> Vec<u8> {
    format!(
        r#"{{"client_address":{ca},"relay_url":{ru},"issued_at_unix_nano":{ia},"expires_at_unix_nano":{ea}}}"#,
        ca = serde_json::to_string(&v.client_address).expect("client_address serializes"),
        ru = serde_json::to_string(&v.relay_url).expect("relay_url serializes"),
        ia = v.issued_at.timestamp_nanos_opt().unwrap_or_default(),
        ea = v.expires_at.timestamp_nanos_opt().unwrap_or_default(),
    )
    .into_bytes()
}

/// Sign `voucher` with the relay's secp256k1 private key (lowercase hex-encoded).
/// Returns the voucher with `signature` populated as 65 bytes.
pub fn sign_reservation_voucher(
    mut voucher: ReservationVoucher,
    private_key_hex: &str,
) -> anyhow::Result<ReservationVoucher> {
    voucher.signature.clear();
    let key_bytes = hex::decode(private_key_hex.trim()).context("decode voucher signing key")?;
    let signing_key = SigningKey::from_slice(&key_bytes).context("parse voucher signing key")?;
    let canonical = canonical_voucher_bytes(&voucher);
    let hash = Sha256::digest(&canonical);
    let (sig, recovery_id): (Signature, RecoveryId) = signing_key
        .sign_prehash_recoverable(&hash)
        .context("sign reservation voucher")?;
    let mut compact = [0u8; 65];
    compact[0] = 27 + 4 + recovery_id.to_byte(); // btcsuite compact header for compressed keys
    compact[1..].copy_from_slice(&sig.to_bytes());
    voucher.signature = compact.to_vec();
    Ok(voucher)
}

/// Verify a signed voucher: recover the signing key from the signature and check it matches
/// `expected_relay_address` (the relay's secp256k1 EVM-style address). Additionally enforces
/// the validity window `issued_at <= now <= expires_at` (with a small clock-skew tolerance)
/// so stale or not-yet-valid vouchers are rejected at the verifier boundary.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "exported verifier API; no production caller inside portal-relay yet (tests cover behavior)"
    )
)]
pub fn verify_reservation_voucher(
    voucher: &ReservationVoucher,
    expected_relay_address: &str,
) -> anyhow::Result<()> {
    verify_reservation_voucher_at(voucher, expected_relay_address, Utc::now())
}

/// Same as [`verify_reservation_voucher`] but uses a caller-supplied `now` for time-based
/// validity checks. Useful for tests and for verifiers with an explicit time source.
pub fn verify_reservation_voucher_at(
    voucher: &ReservationVoucher,
    expected_relay_address: &str,
    now: DateTime<Utc>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        voucher.signature.len() == 65,
        "voucher signature must be 65 bytes, got {}",
        voucher.signature.len()
    );
    // Validity-window enforcement: reject expired or not-yet-valid vouchers (with skew tolerance).
    anyhow::ensure!(
        voucher.issued_at <= voucher.expires_at,
        "voucher issued_at must not be after expires_at"
    );
    anyhow::ensure!(
        voucher.expires_at > now - VOUCHER_CLOCK_SKEW_TOLERANCE,
        "voucher is expired"
    );
    anyhow::ensure!(
        voucher.issued_at <= now + VOUCHER_CLOCK_SKEW_TOLERANCE,
        "voucher is not yet valid"
    );
    // header = 27 + 4 + recovery_id, so recovery_id = header - 31
    let header = voucher.signature[0];
    let recovery_id =
        RecoveryId::from_byte(header.wrapping_sub(31)).context("voucher recovery_id invalid")?;
    let sig =
        Signature::from_slice(&voucher.signature[1..65]).context("voucher signature bytes")?;
    let canonical = canonical_voucher_bytes(voucher);
    let hash = Sha256::digest(&canonical);
    let recovered =
        VerifyingKey::recover_from_prehash(&hash, &sig, recovery_id).context("recover key")?;
    let derived = address_from_verifying_key(&recovered);
    let derived_norm = normalize_evm_address(&derived).context("normalize recovered address")?;
    let expected_norm =
        normalize_evm_address(expected_relay_address).context("normalize expected address")?;
    anyhow::ensure!(
        derived_norm == expected_norm,
        "voucher address mismatch: recovered {derived_norm}, expected {expected_norm}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use k256::ecdsa::SigningKey;
    use rand_core_06::OsRng;

    use super::*;

    fn test_voucher(signing_key: &SigningKey) -> ReservationVoucher {
        let private_key_hex = hex::encode(signing_key.to_bytes());
        let verifying_key = signing_key.verifying_key();
        let address = address_from_verifying_key(verifying_key);
        let now = Utc::now();
        let unsigned = ReservationVoucher {
            client_address: "192.168.1.1".to_string(),
            relay_url: format!("https://{address}.example.com"),
            issued_at: now,
            expires_at: now + Duration::hours(1),
            signature: vec![],
        };
        sign_reservation_voucher(unsigned, &private_key_hex).expect("signing succeeds")
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let key = SigningKey::random(&mut OsRng);
        let voucher = test_voucher(&key);
        assert_eq!(voucher.signature.len(), 65);
        let address = address_from_verifying_key(key.verifying_key());
        verify_reservation_voucher(&voucher, &address).expect("verification succeeds");
    }

    #[test]
    fn test_verify_wrong_address_fails() {
        let key_a = SigningKey::random(&mut OsRng);
        let key_b = SigningKey::random(&mut OsRng);
        let voucher = test_voucher(&key_a);
        let address_b = address_from_verifying_key(key_b.verifying_key());
        assert!(verify_reservation_voucher(&voucher, &address_b).is_err());
    }

    #[test]
    fn test_verify_expired_voucher_fails() {
        let key = SigningKey::random(&mut OsRng);
        let private_key_hex = hex::encode(key.to_bytes());
        let address = address_from_verifying_key(key.verifying_key());
        let issued_at = Utc::now() - Duration::hours(2);
        let expires_at = issued_at + Duration::minutes(1); // expired well outside skew tolerance
        let unsigned = ReservationVoucher {
            client_address: "192.168.1.1".to_string(),
            relay_url: format!("https://{address}.example.com"),
            issued_at,
            expires_at,
            signature: vec![],
        };
        let voucher = sign_reservation_voucher(unsigned, &private_key_hex).expect("sign");
        let err = verify_reservation_voucher(&voucher, &address)
            .expect_err("expired voucher must be rejected");
        assert!(
            err.to_string().contains("expired"),
            "expected expiry error, got {err}"
        );
    }

    #[test]
    fn test_verify_not_yet_valid_voucher_fails() {
        let key = SigningKey::random(&mut OsRng);
        let private_key_hex = hex::encode(key.to_bytes());
        let address = address_from_verifying_key(key.verifying_key());
        let issued_at = Utc::now() + Duration::hours(2); // far beyond skew tolerance
        let expires_at = issued_at + Duration::hours(1);
        let unsigned = ReservationVoucher {
            client_address: "192.168.1.1".to_string(),
            relay_url: format!("https://{address}.example.com"),
            issued_at,
            expires_at,
            signature: vec![],
        };
        let voucher = sign_reservation_voucher(unsigned, &private_key_hex).expect("sign");
        let err = verify_reservation_voucher(&voucher, &address)
            .expect_err("future voucher must be rejected");
        assert!(
            err.to_string().contains("not yet valid"),
            "expected not-yet-valid error, got {err}"
        );
    }
}
