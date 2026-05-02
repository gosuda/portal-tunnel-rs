// INVARIANT: canonical_descriptor_bytes MUST emit Go field order with Unix-nano timestamps; tcp_bps_limit serialized via go_json_float.

use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, TimeDelta, Utc};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::identity::{address_from_verifying_key, normalize_evm_address};
use crate::config::normalize_relay_url;

use super::DISCOVERY_VERSION;

pub(super) const DESCRIPTOR_TTL: TimeDelta = TimeDelta::minutes(5);
const ANNOUNCE_CLOCK_SKEW_TOLERANCE: TimeDelta = TimeDelta::minutes(5);
const ANNOUNCE_MAX_VALIDITY: TimeDelta = TimeDelta::hours(24);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayDescriptor {
    pub address: String,
    pub version: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub api_https_addr: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub wireguard_public_key: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub wireguard_port: i64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub supports_overlay: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub supports_udp: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub supports_tcp: bool,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub active_connections: i64,
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub tcp_bps: f64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

impl RelayDescriptor {
    pub fn has_overlay_peer(&self) -> bool {
        self.supports_overlay
            && !self.wireguard_public_key.trim().is_empty()
            && self.wireguard_port > 0
            && self.wireguard_port <= 65_535
    }
}

pub(super) fn validate_descriptor_freshness(
    desc: &RelayDescriptor,
    now: DateTime<Utc>,
) -> anyhow::Result<()> {
    if desc.expires_at <= now {
        bail!("relay descriptor already expired");
    }
    if desc.issued_at > now + ANNOUNCE_CLOCK_SKEW_TOLERANCE {
        bail!("relay descriptor is too far in the future");
    }
    if desc.expires_at - desc.issued_at > ANNOUNCE_MAX_VALIDITY {
        bail!("relay descriptor validity window exceeds maximum");
    }
    Ok(())
}

pub fn sign_relay_descriptor(
    mut desc: RelayDescriptor,
    private_key_hex: &str,
) -> anyhow::Result<RelayDescriptor> {
    desc.signature.clear();
    let mut desc = normalize_relay_descriptor(desc)?;
    let signing_key = SigningKey::from_slice(
        &hex::decode(private_key_hex.trim()).context("decode relay descriptor private key")?,
    )
    .context("parse relay descriptor private key")?;
    let canonical = canonical_descriptor_bytes(&desc)?;
    let hash = Sha256::digest(&canonical);
    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(&hash)
        .context("sign relay descriptor")?;
    let mut compact = [0u8; 65];
    compact[0] = 27 + 4 + recovery_id.to_byte();
    compact[1..].copy_from_slice(&signature.to_bytes());
    desc.signature = STANDARD.encode(compact);
    Ok(desc)
}

pub fn verify_relay_descriptor(mut desc: RelayDescriptor) -> anyhow::Result<RelayDescriptor> {
    if desc.signature.trim().is_empty() {
        bail!("relay descriptor is not signed");
    }
    let signature = STANDARD
        .decode(desc.signature.trim())
        .context("relay descriptor signature is invalid: base64 decode")?;
    if signature.len() != 65 {
        bail!("relay descriptor signature is invalid: compact signature length");
    }
    let header = signature[0];
    let recovery_byte = match header {
        27..=30 => header - 27,
        31..=34 => header - 31,
        _ => bail!("relay descriptor signature is invalid: recovery header"),
    };
    let recovery_id = RecoveryId::try_from(recovery_byte).context("parse recovery id")?;
    let sig = Signature::from_slice(&signature[1..]).context("parse descriptor signature")?;
    let raw_signature = desc.signature.trim().to_string();
    desc.signature.clear();
    let mut desc = normalize_relay_descriptor(desc)?;
    let canonical = canonical_descriptor_bytes(&desc)?;
    let hash = Sha256::digest(&canonical);
    let key =
        VerifyingKey::recover_from_prehash(&hash, &sig, recovery_id)
            .context("recover relay descriptor public key")?;
    let recovered = address_from_verifying_key(&key);
    if !recovered.eq_ignore_ascii_case(desc.address.trim()) {
        bail!("relay descriptor address does not match recovered signing key");
    }
    desc.signature = raw_signature;
    Ok(desc)
}

pub fn normalize_relay_descriptor(mut desc: RelayDescriptor) -> anyhow::Result<RelayDescriptor> {
    desc.address = desc.address.trim().to_string();
    desc.version = desc.version.trim().to_string();
    desc.api_https_addr = desc.api_https_addr.trim().to_string();
    desc.wireguard_public_key = desc.wireguard_public_key.trim().to_string();
    desc.signature = desc.signature.trim().to_string();
    if desc.version.is_empty() {
        desc.version = DISCOVERY_VERSION.to_string();
    }
    desc.issued_at = desc.issued_at.with_timezone(&Utc);
    desc.expires_at = desc.expires_at.with_timezone(&Utc);

    if !desc.api_https_addr.is_empty() {
        desc.api_https_addr =
            normalize_relay_url(&desc.api_https_addr).context("normalize api https addr")?;
    }
    if !desc.address.is_empty() {
        desc.address = normalize_evm_address(&desc.address).context("normalize address")?;
    }
    if !desc.wireguard_public_key.is_empty() {
        validate_wireguard_public_key(&desc.wireguard_public_key)?;
    }

    if desc.wireguard_port < 0 || desc.wireguard_port > 65_535 {
        bail!("wireguard_port is invalid");
    }
    if desc.active_connections < 0 {
        bail!("active_connections is invalid");
    }
    if desc.tcp_bps < 0.0 || !desc.tcp_bps.is_finite() {
        bail!("tcp_bps is invalid");
    }

    match () {
        () if desc.address.is_empty() => bail!("address is required"),
        () if desc.version != DISCOVERY_VERSION => {
            bail!("unsupported relay descriptor version {:?}", desc.version)
        }
        () if desc.api_https_addr.is_empty() => bail!("api_https_addr is required"),
        () if desc.supports_overlay && desc.wireguard_public_key.is_empty() => {
            bail!("wireguard_public_key is required when supports_overlay is set")
        }
        () if desc.supports_overlay && desc.wireguard_port == 0 => {
            bail!("wireguard_port is required when supports_overlay is set")
        }
        () if !desc.supports_overlay
            && (!desc.wireguard_public_key.is_empty() || desc.wireguard_port != 0) =>
        {
            bail!("supports_overlay is required when wireguard metadata is set")
        }
        () if desc.expires_at.timestamp_nanos_opt().is_none() => {
            bail!("expires_at is required")
        }
        () if desc.issued_at > desc.expires_at => bail!("issued_at must be before expires_at"),
        () => {}
    }

    Ok(desc)
}

fn validate_wireguard_public_key(raw: &str) -> anyhow::Result<()> {
    let decoded = STANDARD
        .decode(raw.trim())
        .context("wireguard_public_key must be base64 encoded")?;
    if decoded.len() != 32 {
        bail!("wireguard_public_key must be 32 bytes");
    }
    Ok(())
}

pub fn canonical_descriptor_bytes(desc: &RelayDescriptor) -> anyhow::Result<Vec<u8>> {
    let issued_at_unix_nano = desc
        .issued_at
        .timestamp_nanos_opt()
        .context("issued_at out of range")?;
    let expires_at_unix_nano = desc
        .expires_at
        .timestamp_nanos_opt()
        .context("expires_at out of range")?;
    let json = format!(
        concat!(
            "{{",
            "\"address\":{},",
            "\"version\":{},",
            "\"issued_at_unix_nano\":{},",
            "\"expires_at_unix_nano\":{},",
            "\"api_https_addr\":{},",
            "\"wireguard_public_key\":{},",
            "\"wireguard_port\":{},",
            "\"supports_overlay\":{},",
            "\"supports_udp\":{},",
            "\"supports_tcp\":{},",
            "\"active_connections\":{},",
            "\"tcp_bps\":{}",
            "}}"
        ),
        json_string(desc.address.trim()),
        json_string(desc.version.trim()),
        issued_at_unix_nano,
        expires_at_unix_nano,
        json_string(desc.api_https_addr.trim()),
        json_string(desc.wireguard_public_key.trim()),
        desc.wireguard_port,
        desc.supports_overlay,
        desc.supports_udp,
        desc.supports_tcp,
        desc.active_connections,
        go_json_float(desc.tcp_bps),
    );
    Ok(json.into_bytes())
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("json string serialization cannot fail")
}

fn go_json_float(value: f64) -> String {
    if !value.is_finite() {
        return "0".to_string();
    }

    let abs = value.abs();
    if abs != 0.0 && !(1e-6..1e21).contains(&abs) {
        let raw = format!("{value:e}");
        if let Some((mantissa, exponent)) = raw.split_once('e') {
            let exponent = if exponent.starts_with('-') || exponent.starts_with('+') {
                exponent.to_string()
            } else {
                format!("+{exponent}")
            };
            return format!("{mantissa}e{exponent}");
        }
        return raw;
    }

    format!("{value}")
}

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

fn is_zero_f64(value: &f64) -> bool {
    *value == 0.0
}
