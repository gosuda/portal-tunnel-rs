use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use k256::ecdsa::SigningKey;
use rand_core_06::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::auth::identity::{address_from_signing_key, compressed_public_key_hex};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RelayIdentity {
    pub name: String,
    pub address: String,
    pub public_key: String,
    pub private_key: String,
    pub admin_secret_key: String,
    pub wireguard_public_key: String,
    pub wireguard_private_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredRelayIdentity {
    #[serde(default)]
    name: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    private_key: String,
    #[serde(default)]
    admin_secret_key: String,
    #[serde(default)]
    wireguard_public_key: String,
    #[serde(default)]
    wireguard_private_key: String,
}

pub fn load_or_create_relay_identity(
    identity_path: &Path,
    root_host: &str,
    discovery_enabled: bool,
) -> anyhow::Result<RelayIdentity> {
    fs::create_dir_all(identity_path).with_context(|| {
        format!(
            "create relay identity directory {}",
            identity_path.display()
        )
    })?;

    let path = relay_identity_path(identity_path);
    let stored = if path.exists() {
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("read relay identity {}", path.display()))?;
        let mut stored: StoredRelayIdentity = serde_json::from_str(&raw)
            .with_context(|| format!("decode relay identity {}", path.display()))?;
        stored.name = root_host.to_string();
        populate_missing_identity_fields(stored, discovery_enabled)?
    } else {
        populate_missing_identity_fields(
            StoredRelayIdentity {
                name: root_host.to_string(),
                address: String::new(),
                public_key: String::new(),
                private_key: String::new(),
                admin_secret_key: String::new(),
                wireguard_public_key: String::new(),
                wireguard_private_key: String::new(),
            },
            discovery_enabled,
        )?
    };

    let pretty = serde_json::to_vec_pretty(&stored).context("encode relay identity")?;
    fs::write(&path, pretty).with_context(|| format!("write relay identity {}", path.display()))?;

    Ok(RelayIdentity {
        name: stored.name,
        address: stored.address,
        public_key: stored.public_key,
        private_key: stored.private_key,
        admin_secret_key: stored.admin_secret_key,
        wireguard_public_key: stored.wireguard_public_key,
        wireguard_private_key: stored.wireguard_private_key,
    })
}

fn relay_identity_path(identity_path: &Path) -> PathBuf {
    match identity_path.file_name().and_then(|name| name.to_str()) {
        Some("identity.json") => identity_path.to_path_buf(),
        _ => identity_path.join("identity.json"),
    }
}

fn populate_missing_identity_fields(
    mut stored: StoredRelayIdentity,
    discovery_enabled: bool,
) -> anyhow::Result<StoredRelayIdentity> {
    if stored.private_key.trim().is_empty() {
        let generated = generate_secp256k1_identity();
        stored.private_key = generated.private_key;
        stored.public_key = generated.public_key;
        stored.address = generated.address;
    } else {
        let resolved = resolve_private_key(&stored.private_key)?;
        if !stored.public_key.trim().is_empty()
            && !stored.public_key.eq_ignore_ascii_case(&resolved.public_key)
        {
            bail!("identity public key does not match private key");
        }
        if !stored.address.trim().is_empty()
            && !stored.address.eq_ignore_ascii_case(&resolved.address)
        {
            bail!("identity address does not match private key");
        }
        stored.private_key = resolved.private_key;
        stored.public_key = resolved.public_key;
        stored.address = resolved.address;
    }

    if stored.admin_secret_key.trim().is_empty() {
        stored.admin_secret_key = random_token();
    }

    normalize_wireguard_identity(&mut stored, discovery_enabled)?;

    Ok(stored)
}

struct GeneratedIdentity {
    address: String,
    public_key: String,
    private_key: String,
}

fn generate_secp256k1_identity() -> GeneratedIdentity {
    let signing_key = SigningKey::random(&mut OsRng);
    identity_from_signing_key(signing_key)
}

fn resolve_private_key(private_key_hex: &str) -> anyhow::Result<GeneratedIdentity> {
    let trimmed = private_key_hex.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed).context("decode secp256k1 private key")?;
    let signing_key = SigningKey::from_slice(&bytes).context("parse secp256k1 private key")?;
    Ok(identity_from_signing_key(signing_key))
}

fn identity_from_signing_key(signing_key: SigningKey) -> GeneratedIdentity {
    let public_key = compressed_public_key_hex(&signing_key);
    let private_key = hex::encode(signing_key.to_bytes());
    let address = address_from_signing_key(&signing_key);

    GeneratedIdentity {
        address,
        public_key,
        private_key,
    }
}

fn random_token() -> String {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

fn normalize_wireguard_identity(
    stored: &mut StoredRelayIdentity,
    discovery_enabled: bool,
) -> anyhow::Result<()> {
    stored.wireguard_public_key = stored.wireguard_public_key.trim().to_string();
    stored.wireguard_private_key = stored.wireguard_private_key.trim().to_string();

    if discovery_enabled && stored.wireguard_private_key.is_empty() {
        stored.wireguard_private_key = generate_wireguard_private_key();
    }

    if !stored.wireguard_private_key.is_empty() {
        let private = normalize_wireguard_private_key(&stored.wireguard_private_key)?;
        let public_key = wireguard_public_key_from_private_bytes(private);
        if !stored.wireguard_public_key.is_empty() {
            validate_wireguard_public_key(&stored.wireguard_public_key)?;
            if stored.wireguard_public_key != public_key {
                bail!("identity wireguard public key does not match private key");
            }
        }
        stored.wireguard_private_key = STANDARD.encode(private);
        stored.wireguard_public_key = public_key;
    } else if !stored.wireguard_public_key.is_empty() {
        validate_wireguard_public_key(&stored.wireguard_public_key)?;
    }

    Ok(())
}

fn generate_wireguard_private_key() -> String {
    let mut private = [0u8; 32];
    OsRng.fill_bytes(&mut private);
    clamp_wireguard_private_key(&mut private);
    STANDARD.encode(private)
}

pub(crate) fn normalize_wireguard_private_key(raw: &str) -> anyhow::Result<[u8; 32]> {
    let value = raw.trim();
    if value.is_empty() {
        bail!("wireguard private key is required");
    }

    let decoded = if value.len() == 64 && !value.contains('=') {
        hex::decode(value).context("decode wireguard private key hex")?
    } else {
        STANDARD
            .decode(value)
            .context("decode wireguard private key base64")?
    };
    let mut private: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("wireguard private key must be 32 bytes"))?;
    clamp_wireguard_private_key(&mut private);
    Ok(private)
}

fn clamp_wireguard_private_key(private: &mut [u8; 32]) {
    private[0] &= 0xf8;
    private[31] = (private[31] & 127) | 64;
}

pub(crate) fn wireguard_public_key_from_private_bytes(private: [u8; 32]) -> String {
    let secret = StaticSecret::from(private);
    let public = X25519PublicKey::from(&secret);
    STANDARD.encode(public.as_bytes())
}

pub(crate) fn validate_wireguard_public_key(raw: &str) -> anyhow::Result<()> {
    let decoded = STANDARD
        .decode(raw.trim())
        .context("wireguard_public_key must be base64 encoded")?;
    if decoded.len() != 32 {
        bail!("wireguard_public_key must be 32 bytes");
    }
    Ok(())
}

#[allow(dead_code)]
pub fn derive_wireguard_overlay_ipv4(public_key: &str) -> anyhow::Result<Ipv4Addr> {
    let decoded = STANDARD
        .decode(public_key.trim())
        .context("wireguard public key must be base64 encoded")?;
    if decoded.len() != 32 {
        bail!("wireguard public key must be 32 bytes");
    }
    let digest = Sha256::digest(decoded);
    Ok(Ipv4Addr::new(
        100,
        64 + (digest[0] & 0x3f),
        digest[1],
        1 + (digest[2] % 254),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_wireguard_private_key_and_derives_public_key() {
        let mut stored = StoredRelayIdentity {
            name: "relay.example".to_string(),
            address: String::new(),
            public_key: String::new(),
            private_key: String::new(),
            admin_secret_key: String::new(),
            wireguard_public_key: String::new(),
            wireguard_private_key:
                "0100000000000000000000000000000000000000000000000000000000000000".to_string(),
        };

        normalize_wireguard_identity(&mut stored, false).unwrap();

        assert_eq!(
            stored.wireguard_private_key,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEA="
        );
        assert_eq!(
            stored.wireguard_public_key,
            "L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q="
        );
        assert_eq!(
            derive_wireguard_overlay_ipv4(&stored.wireguard_public_key)
                .unwrap()
                .to_string(),
            "100.99.60.238"
        );
    }

    #[test]
    fn discovery_generates_wireguard_identity_material() {
        let mut stored = StoredRelayIdentity {
            name: "relay.example".to_string(),
            address: String::new(),
            public_key: String::new(),
            private_key: String::new(),
            admin_secret_key: String::new(),
            wireguard_public_key: String::new(),
            wireguard_private_key: String::new(),
        };

        normalize_wireguard_identity(&mut stored, true).unwrap();

        assert!(!stored.wireguard_private_key.is_empty());
        assert!(!stored.wireguard_public_key.is_empty());
        validate_wireguard_public_key(&stored.wireguard_public_key).unwrap();
    }
}
