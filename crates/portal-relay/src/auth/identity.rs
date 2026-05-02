use anyhow::{Context, bail};
use k256::ecdsa::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub address: String,
    #[serde(skip)]
    pub public_key: String,
    #[serde(skip)]
    pub private_key: String,
}

impl Identity {
    pub fn key(&self) -> String {
        let name = self.name.trim().to_ascii_lowercase();
        let address = self.address.trim().to_ascii_lowercase();
        if name.is_empty() && address.is_empty() {
            return String::new();
        }
        format!("{name}:{address}")
    }
}

pub fn normalize_identity(identity: &Identity) -> anyhow::Result<Identity> {
    Ok(Identity {
        name: normalize_dns_label(&identity.name)?,
        address: normalize_evm_address(&identity.address)?,
        public_key: identity.public_key.trim().to_string(),
        private_key: identity.private_key.trim().to_string(),
    })
}

pub fn lease_hostname(name: &str, root_host: &str) -> anyhow::Result<String> {
    let label = normalize_dns_label(name)?;
    let root_host = normalize_hostname(root_host);
    if root_host.is_empty() {
        bail!("root host is required");
    }
    Ok(format!("{label}.{root_host}"))
}

pub fn normalize_hostname(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub fn normalize_dns_label(raw: &str) -> anyhow::Result<String> {
    let label = sanitize_dns_label_input(raw);
    if label.is_empty() {
        bail!("name is required");
    }
    if label.contains('.') {
        bail!("name must be a single dns label");
    }
    if label.len() > 63 {
        bail!("name must be 63 characters or fewer");
    }
    if label.starts_with('-') || label.ends_with('-') {
        bail!("name must not start or end with hyphen");
    }
    if !label
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        bail!("name must contain only letters, numbers, or hyphen");
    }
    Ok(label)
}

fn sanitize_dns_label_input(raw: &str) -> String {
    let input = raw.trim().to_lowercase();
    if input.is_empty() {
        return String::new();
    }

    let mut out = String::with_capacity(input.len());
    let mut previous_hyphen = false;
    for ch in input.chars() {
        if ch == '-' || ch.is_alphanumeric() {
            out.push(ch);
            previous_hyphen = false;
            continue;
        }
        if !previous_hyphen {
            out.push('-');
            previous_hyphen = true;
        }
    }
    out.trim_matches('-').to_string()
}

pub fn normalize_evm_address(raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("address is required");
    }
    let Some(hex_part) = trimmed.strip_prefix("0x") else {
        bail!("address must start with 0x");
    };
    if hex_part.len() != 40 {
        bail!("address must be 20 bytes");
    }
    hex::decode(hex_part).context("address must be hex encoded")?;

    let lower = hex_part.to_ascii_lowercase();
    let checksummed = checksum_address_hex(&lower);
    if hex_part != lower && hex_part != hex_part.to_ascii_uppercase() && hex_part != checksummed {
        bail!("address checksum is invalid");
    }
    Ok(format!("0x{checksummed}"))
}

pub fn address_from_signing_key(signing_key: &SigningKey) -> String {
    address_from_verifying_key(signing_key.verifying_key())
}

pub fn address_from_verifying_key(verifying_key: &VerifyingKey) -> String {
    let uncompressed = verifying_key.to_encoded_point(false);
    let hash = Keccak256::digest(&uncompressed.as_bytes()[1..]);
    normalize_evm_address(&format!("0x{}", hex::encode(&hash[12..])))
        .expect("generated address must normalize")
}

pub fn compressed_public_key_hex(signing_key: &SigningKey) -> String {
    let compressed = signing_key.verifying_key().to_encoded_point(true);
    hex::encode(compressed.as_bytes())
}

fn checksum_address_hex(lower_hex: &str) -> String {
    let hash = Keccak256::digest(lower_hex.as_bytes());
    let mut out = String::with_capacity(lower_hex.len());
    for (idx, ch) in lower_hex.chars().enumerate() {
        if ch.is_ascii_digit() {
            out.push(ch);
            continue;
        }
        let mut nibble = hash[idx / 2];
        if idx % 2 == 0 {
            nibble >>= 4;
        } else {
            nibble &= 0x0f;
        }
        if nibble > 7 {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_dns_label_like_go() {
        assert_eq!(normalize_dns_label("Demo-App").unwrap(), "demo-app");
        assert_eq!(normalize_dns_label(" demo app!! ").unwrap(), "demo-app");
        assert_eq!(normalize_dns_label("deep.example").unwrap(), "deep-example");
    }

    #[test]
    fn lease_hostname_uses_normalized_name_and_root() {
        assert_eq!(
            lease_hostname("Demo-App", "Portal.Example.com").unwrap(),
            "demo-app.portal.example.com"
        );
    }

    #[test]
    fn normalizes_evm_checksum_address() {
        let normalized =
            normalize_evm_address("0x52908400098527886E0F7030069857D2E4169EE7").unwrap();
        assert_eq!(normalized, "0x52908400098527886E0F7030069857D2E4169EE7");
        assert!(normalize_evm_address("0x52908400098527886e0f7030069857D2E4169EE7").is_err());
    }
}
