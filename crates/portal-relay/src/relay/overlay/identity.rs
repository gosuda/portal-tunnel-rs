// INVARIANT: WireGuard key derivation is deterministic from RelayIdentity; IPC config matches Go runtime defaults.

use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use wireguard_control::Key as WgKey;

use crate::state::identity::{
    RelayIdentity, derive_wireguard_overlay_ipv4, normalize_wireguard_private_key,
    wireguard_public_key_from_private_bytes,
};

use super::OverlayConfig;

impl OverlayConfig {
    pub fn from_identity(identity: &RelayIdentity, listen_port: u16) -> anyhow::Result<Self> {
        if listen_port == 0 {
            bail!("wireguard listen port is invalid");
        }
        let private = normalize_wireguard_private_key(&identity.wireguard_private_key)
            .context("normalize wireguard private key")?;
        let public_key = wireguard_public_key_from_private_bytes(private);
        if !identity.wireguard_public_key.trim().is_empty()
            && identity.wireguard_public_key.trim() != public_key
        {
            bail!("identity wireguard public key does not match private key");
        }
        let overlay_ipv4 = derive_wireguard_overlay_ipv4(&public_key)?;
        Ok(Self {
            private_key: STANDARD.encode(private),
            private_key_hex: hex::encode(private),
            public_key,
            listen_port,
            overlay_ipv4,
        })
    }

    pub fn base_ipc_config(&self) -> String {
        format!(
            "private_key={}\nlisten_port={}\n",
            self.private_key_hex, self.listen_port
        )
    }
}

pub(super) fn wireguard_key_hex(raw: &str) -> anyhow::Result<String> {
    let decoded = STANDARD
        .decode(raw.trim())
        .context("wireguard key must be base64 encoded")?;
    if decoded.len() != 32 {
        bail!("wireguard key must be 32 bytes");
    }
    Ok(hex::encode(decoded))
}

pub(super) fn wireguard_key(raw: &str) -> anyhow::Result<WgKey> {
    let decoded = STANDARD
        .decode(raw.trim())
        .context("wireguard key must be base64 encoded")?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("wireguard key must be 32 bytes"))?;
    Ok(WgKey(bytes))
}
