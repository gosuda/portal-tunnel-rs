use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::identity::{Identity, normalize_identity};
use crate::state::identity::RelayIdentity;

const LEASE_ACCESS_TOKEN_AUDIENCE: &str = "portal-sdk";
const LEASE_TOKEN_ALGORITHM: &str = "ES256K";

#[derive(Debug, Serialize, Deserialize)]
struct JwtHeader<'a> {
    alg: &'a str,
    kid: &'a str,
    typ: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseAccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: AudienceClaim,
    pub jti: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub identity: Identity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

impl AudienceClaim {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
        }
    }
}

pub fn issue_lease_access_token(
    relay: &RelayIdentity,
    issuer: &str,
    identity: &Identity,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> anyhow::Result<(String, LeaseAccessTokenClaims)> {
    let normalized_identity = normalize_identity(identity)?;
    let private_key = SigningKey::from_slice(
        &hex::decode(relay.private_key.trim()).context("decode relay private key")?,
    )
    .context("parse relay private key")?;

    let claims = LeaseAccessTokenClaims {
        iss: issuer.trim().to_string(),
        sub: normalized_identity.key(),
        aud: AudienceClaim::One(LEASE_ACCESS_TOKEN_AUDIENCE.to_string()),
        jti: random_id("tok_"),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: expires_at.timestamp(),
        identity: normalized_identity,
    };

    let header = JwtHeader {
        alg: LEASE_TOKEN_ALGORITHM,
        kid: relay.address.trim(),
        typ: "JWT",
    };
    let signing_input = format!("{}.{}", encode_json(&header)?, encode_json(&claims)?);
    let digest = Sha256::digest(signing_input.as_bytes());
    let signature: Signature = private_key
        .sign_prehash(&digest)
        .context("sign lease access token")?;
    let token = format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );
    Ok((token, claims))
}

pub fn verify_lease_access_token(
    token: &str,
    relay: &RelayIdentity,
    issuer: &str,
    now: DateTime<Utc>,
) -> anyhow::Result<LeaseAccessTokenClaims> {
    let parts = token.trim().split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        bail!("token must have three segments");
    }
    let header: serde_json::Value = decode_json(parts[0])?;
    if header.get("alg").and_then(|v| v.as_str()) != Some(LEASE_TOKEN_ALGORITHM) {
        bail!("token algorithm is invalid");
    }

    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .context("decode token signature")?;
    if signature.len() != 64 {
        bail!("invalid es256k signature length");
    }
    let public_key = VerifyingKey::from_sec1_bytes(
        &hex::decode(relay.public_key.trim()).context("decode relay public key")?,
    )
    .context("parse relay public key")?;
    let sig = Signature::from_slice(&signature).context("parse token signature")?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let digest = Sha256::digest(signing_input.as_bytes());
    public_key
        .verify_prehash(&digest, &sig)
        .context("verify token signature")?;

    let mut claims: LeaseAccessTokenClaims = decode_json(parts[1])?;
    claims.identity = normalize_identity(&claims.identity)?;
    if claims.iss != issuer.trim() {
        bail!("token issuer is invalid");
    }
    if !claims.aud.contains(LEASE_ACCESS_TOKEN_AUDIENCE) {
        bail!("token audience is invalid");
    }
    if claims.sub != claims.identity.key() {
        bail!("lease access token identity does not match subject");
    }
    let now_ts = now.timestamp();
    if claims.nbf > now_ts || claims.exp <= now_ts {
        bail!("token is not currently valid");
    }
    Ok(claims)
}

fn encode_json<T: Serialize>(value: &T) -> anyhow::Result<String> {
    let raw = serde_json::to_vec(value).context("encode jwt json")?;
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

fn decode_json<T: for<'de> Deserialize<'de>>(segment: &str) -> anyhow::Result<T> {
    let raw = URL_SAFE_NO_PAD
        .decode(segment)
        .context("decode jwt segment")?;
    serde_json::from_slice(&raw).context("decode jwt json")
}

fn random_id(prefix: &str) -> String {
    let mut buf = [0u8; 8];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut buf);
    format!("{prefix}{}", hex::encode(buf))
}
