use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};

use crate::state::tls_material::KeylessSigner;

pub const RELAY_KEY_ID: &str = "relay-cert";
const ALGORITHM_ECDSA_SHA256: &str = "ECDSA_SHA256";
const ALLOWED_SKEW_SECS: i64 = 30;

#[derive(Debug, Deserialize)]
pub struct SignRequest {
    pub key_id: String,
    pub algorithm: String,
    #[serde(with = "base64_bytes")]
    pub digest: Vec<u8>,
    pub timestamp_unix: i64,
    pub nonce: String,
}

#[derive(Debug, Serialize)]
pub struct SignResponse {
    pub key_id: String,
    pub algorithm: String,
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub fn sign(req: SignRequest, signer: &KeylessSigner) -> anyhow::Result<SignResponse> {
    if req.key_id.trim().is_empty()
        || req.algorithm.trim().is_empty()
        || req.digest.is_empty()
        || req.nonce.trim().is_empty()
    {
        bail!("invalid argument: missing required field");
    }
    if req.key_id != RELAY_KEY_ID {
        bail!("permission denied: key not found");
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before unix epoch")?
        .as_secs() as i64;
    if req.timestamp_unix < now - ALLOWED_SKEW_SECS || req.timestamp_unix > now + ALLOWED_SKEW_SECS
    {
        bail!("invalid argument: request timestamp outside allowed skew");
    }

    let signature = match req.algorithm.as_str() {
        ALGORITHM_ECDSA_SHA256 => signer.sign_ecdsa_sha256(&req.digest)?,
        other => bail!("invalid argument: unsupported algorithm: {other}"),
    };

    Ok(SignResponse {
        key_id: req.key_id,
        algorithm: req.algorithm,
        signature,
    })
}

mod base64_bytes {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        STANDARD.decode(encoded).map_err(serde::de::Error::custom)
    }
}
