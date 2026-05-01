use anyhow::{bail, Context};
use chrono::{DateTime, Utc};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

use crate::auth::identity::normalize_evm_address;

pub fn build_register_message(
    domain: &str,
    address: &str,
    uri: &str,
    nonce: &str,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    request_id: &str,
) -> String {
    format!(
        "{domain} wants you to sign in with your Ethereum account:\n\
{address}\n\
\n\
Register a portal lease\n\
\n\
URI: {uri}\n\
Version: 1\n\
Chain ID: 1\n\
Nonce: {nonce}\n\
Issued At: {}\n\
Expiration Time: {}\n\
Request ID: {request_id}",
        issued_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    )
}

pub fn verify_personal_signature(
    message: &str,
    signature_hex: &str,
    expected_address: &str,
) -> anyhow::Result<()> {
    let signature = decode_eth_signature(signature_hex)?;
    let hash = ethereum_personal_message_hash(message.as_bytes());
    let sig = Signature::from_slice(&signature[..64]).context("parse ethereum signature")?;
    let recovery_id = recovery_id(signature[64])?;
    let key = VerifyingKey::recover_from_prehash(&hash, &sig, recovery_id)
        .context("recover ethereum signature public key")?;
    let recovered = crate::auth::identity::address_from_verifying_key(&key);
    let expected = normalize_evm_address(expected_address)?;
    if recovered != expected {
        bail!("siwe signature recovered unexpected address");
    }
    Ok(())
}

fn decode_eth_signature(signature_hex: &str) -> anyhow::Result<[u8; 65]> {
    let trimmed = signature_hex.trim().trim_start_matches("0x");
    let raw = hex::decode(trimmed).context("decode ethereum signature")?;
    if raw.len() != 65 {
        bail!("ethereum signature must be 65 bytes");
    }
    let mut out = [0u8; 65];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn recovery_id(v: u8) -> anyhow::Result<RecoveryId> {
    let normalized = match v {
        0 | 1 => v,
        27 | 28 => v - 27,
        _ => bail!("ethereum signature recovery id is invalid"),
    };
    RecoveryId::try_from(normalized).context("parse ethereum recovery id")
}

fn ethereum_personal_message_hash(message: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message);
    hasher.finalize().into()
}
