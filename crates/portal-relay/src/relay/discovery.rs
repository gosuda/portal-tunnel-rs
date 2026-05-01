use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{bail, Context};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, TimeDelta, Utc};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};
use url::Url;

use crate::api::paths::{PATH_DISCOVERY, PATH_DISCOVERY_ANNOUNCE};
use crate::auth::identity::{address_from_verifying_key, normalize_evm_address};
use crate::config::normalize_relay_url;
use crate::relay::bridge::RelayMetrics;
use crate::relay::overlay::OverlayDiscoveryInfo;
use crate::state::identity::RelayIdentity;

pub const DISCOVERY_VERSION: &str = "7";
pub const DISCOVERY_POLL_INTERVAL: Duration = Duration::from_secs(30);
const PORTAL_RELAY_REGISTRY_URL: &str =
    "https://raw.githubusercontent.com/gosuda/portal-tunnel/main/registry.json";
const DESCRIPTOR_TTL: TimeDelta = TimeDelta::minutes(5);
const DISCOVERY_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const ANNOUNCE_CLOCK_SKEW_TOLERANCE: TimeDelta = TimeDelta::minutes(5);
const ANNOUNCE_MAX_VALIDITY: TimeDelta = TimeDelta::hours(24);
const MAX_ANNOUNCED_RELAYS: usize = 1024;

pub struct DiscoveryState {
    relay: RelayIdentity,
    portal_url: String,
    bootstraps: Mutex<Vec<String>>,
    registry_bootstraps_loaded: Mutex<bool>,
    supports_udp: bool,
    supports_tcp: bool,
    overlay: Option<OverlayDiscoveryInfo>,
    metrics: std::sync::Arc<RelayMetrics>,
    client: reqwest::Client,
    relays: Mutex<HashMap<String, RelayDescriptor>>,
}

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

#[derive(Debug, Serialize, Deserialize)]
pub struct DiscoveryResponse {
    pub protocol_version: String,
    pub generated_at: DateTime<Utc>,
    pub relays: Vec<RelayDescriptor>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiscoveryAnnounceRequest {
    #[serde(default)]
    pub protocol_version: String,
    pub descriptor: RelayDescriptor,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiscoveryAnnounceResponse {
    pub protocol_version: String,
    pub accepted: bool,
}

#[derive(Debug, Default)]
pub struct DiscoveryRefreshStats {
    pub polled: usize,
    pub announced: usize,
    pub failures: usize,
}

impl DiscoveryState {
    #[cfg(test)]
    pub fn new(
        relay: RelayIdentity,
        portal_url: String,
        bootstraps: Vec<String>,
        supports_udp: bool,
        supports_tcp: bool,
    ) -> Self {
        Self::new_with_metrics(
            relay,
            portal_url,
            bootstraps,
            supports_udp,
            supports_tcp,
            std::sync::Arc::new(RelayMetrics::default()),
        )
    }

    #[cfg(test)]
    pub fn new_with_metrics(
        relay: RelayIdentity,
        portal_url: String,
        bootstraps: Vec<String>,
        supports_udp: bool,
        supports_tcp: bool,
        metrics: std::sync::Arc<RelayMetrics>,
    ) -> Self {
        Self::new_with_metrics_and_overlay(
            relay,
            portal_url,
            bootstraps,
            supports_udp,
            supports_tcp,
            metrics,
            None,
        )
    }

    pub fn new_with_metrics_and_overlay(
        relay: RelayIdentity,
        portal_url: String,
        bootstraps: Vec<String>,
        supports_udp: bool,
        supports_tcp: bool,
        metrics: std::sync::Arc<RelayMetrics>,
        overlay: Option<OverlayDiscoveryInfo>,
    ) -> Self {
        Self {
            relay,
            portal_url,
            bootstraps: Mutex::new(bootstraps),
            registry_bootstraps_loaded: Mutex::new(false),
            supports_udp,
            supports_tcp,
            overlay,
            metrics,
            client: reqwest::Client::builder()
                .timeout(DISCOVERY_REQUEST_TIMEOUT)
                .http1_only()
                .build()
                .expect("reqwest client configuration is valid"),
            relays: Mutex::new(HashMap::new()),
        }
    }

    pub fn response(&self, now: DateTime<Utc>) -> anyhow::Result<DiscoveryResponse> {
        let self_descriptor = self.self_descriptor(now)?;
        let mut relays = vec![self_descriptor];
        let mut stored = self.relays.lock().expect("discovery relays lock poisoned");
        stored.retain(|_, desc| desc.expires_at > now);
        relays.extend(stored.values().cloned());
        relays.sort_by(|a, b| a.api_https_addr.cmp(&b.api_https_addr));
        Ok(DiscoveryResponse {
            protocol_version: DISCOVERY_VERSION.to_string(),
            generated_at: now,
            relays,
        })
    }

    #[allow(dead_code)]
    pub fn overlay_peers(&self, now: DateTime<Utc>) -> Vec<RelayDescriptor> {
        let mut stored = self.relays.lock().expect("discovery relays lock poisoned");
        stored.retain(|_, desc| desc.expires_at > now);
        let mut peers = stored
            .values()
            .filter(|desc| desc.has_overlay_peer())
            .cloned()
            .collect::<Vec<_>>();
        peers.sort_by(|a, b| {
            a.wireguard_public_key
                .cmp(&b.wireguard_public_key)
                .then_with(|| a.api_https_addr.cmp(&b.api_https_addr))
        });
        peers
    }

    pub fn announce(
        &self,
        req: DiscoveryAnnounceRequest,
        now: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        if !req.protocol_version.trim().is_empty() && req.protocol_version != DISCOVERY_VERSION {
            bail!(
                "announce protocol mismatch: relay={:?} client={:?}",
                DISCOVERY_VERSION,
                req.protocol_version
            );
        }
        let desc = verify_relay_descriptor(req.descriptor)?;
        validate_descriptor_freshness(&desc, now)?;
        if desc.api_https_addr == self.portal_url {
            bail!("self-announce rejected: descriptor matches receiving relay url");
        }

        match self.upsert_descriptor(desc, now, false) {
            UpsertResult::Accepted | UpsertResult::Ignored => Ok(()),
            UpsertResult::Rejected => {
                bail!("announced descriptor rejected by rollback or takeover guard")
            }
        }
    }

    pub async fn refresh_once(&self) -> anyhow::Result<DiscoveryRefreshStats> {
        let mut stats = DiscoveryRefreshStats::default();
        self.ensure_registry_bootstraps().await;
        let self_descriptor = self.self_descriptor(Utc::now())?;

        for target in self.poll_targets(Utc::now()) {
            match self.fetch_discovery(&target).await {
                Ok(resp) => match self.apply_response(Some(&target), resp, Utc::now()) {
                    Ok(changed) => {
                        stats.polled += 1;
                        if changed {
                            debug!(%target, "relay discovery set changed");
                        }
                    }
                    Err(err) => {
                        stats.failures += 1;
                        warn!(%target, error = %err, "relay discovery response rejected");
                    }
                },
                Err(err) => {
                    stats.failures += 1;
                    warn!(%target, error = %err, "relay discovery poll failed");
                }
            }
        }

        for target in self.bootstrap_targets() {
            if target == self.portal_url {
                continue;
            }
            match self.announce_self(&target, &self_descriptor).await {
                Ok(()) => stats.announced += 1,
                Err(err) => {
                    stats.failures += 1;
                    warn!(%target, error = %err, "relay discovery announce failed");
                }
            }
        }

        Ok(stats)
    }

    pub fn apply_response(
        &self,
        target_url: Option<&str>,
        resp: DiscoveryResponse,
        now: DateTime<Utc>,
    ) -> anyhow::Result<bool> {
        if resp.protocol_version != DISCOVERY_VERSION {
            bail!(
                "relay discovery protocol version mismatch: relay={:?} client={:?}",
                resp.protocol_version,
                DISCOVERY_VERSION
            );
        }

        let target_url = target_url.map(str::trim).filter(|url| !url.is_empty());
        let mut changed = false;
        let mut target_found = target_url.is_none();
        for descriptor in resp.relays {
            let desc = match verify_relay_descriptor(descriptor) {
                Ok(desc) => desc,
                Err(err) => {
                    debug!(error = %err, "relay discovery descriptor rejected");
                    continue;
                }
            };
            if let Err(err) = validate_descriptor_freshness(&desc, now) {
                debug!(relay = %desc.api_https_addr, error = %err, "stale relay discovery descriptor ignored");
                continue;
            }
            if Some(desc.api_https_addr.as_str()) == target_url {
                target_found = true;
            }
            if desc.api_https_addr == self.portal_url {
                continue;
            }
            let authoritative = Some(desc.api_https_addr.as_str()) == target_url;
            if self.upsert_descriptor(desc, now, authoritative) == UpsertResult::Accepted {
                changed = true;
            }
        }

        if !target_found {
            bail!("target relay descriptor missing from relays");
        }
        Ok(changed)
    }

    pub fn self_descriptor(&self, now: DateTime<Utc>) -> anyhow::Result<RelayDescriptor> {
        let overlay = self.overlay.as_ref();
        sign_relay_descriptor(
            RelayDescriptor {
                address: self.relay.address.clone(),
                version: DISCOVERY_VERSION.to_string(),
                issued_at: now,
                expires_at: now + DESCRIPTOR_TTL,
                api_https_addr: self.portal_url.clone(),
                wireguard_public_key: overlay
                    .map(|overlay| overlay.public_key.clone())
                    .unwrap_or_default(),
                wireguard_port: overlay
                    .map(|overlay| i64::from(overlay.listen_port))
                    .unwrap_or_default(),
                supports_overlay: overlay.is_some(),
                supports_udp: self.supports_udp,
                supports_tcp: self.supports_tcp,
                active_connections: self.metrics.active_connection_count(),
                tcp_bps: self.metrics.current_tcp_bps(now),
                signature: String::new(),
            },
            &self.relay.private_key,
        )
    }

    fn bootstrap_targets(&self) -> Vec<String> {
        self.bootstraps
            .lock()
            .expect("discovery bootstraps lock poisoned")
            .iter()
            .filter(|url| *url != &self.portal_url)
            .cloned()
            .collect()
    }

    fn poll_targets(&self, now: DateTime<Utc>) -> Vec<String> {
        let mut out = self.bootstrap_targets();
        let mut relays = self.relays.lock().expect("discovery relays lock poisoned");
        relays.retain(|_, desc| desc.expires_at > now);
        for relay_url in relays.keys() {
            if relay_url != &self.portal_url && !out.contains(relay_url) {
                out.push(relay_url.clone());
            }
        }
        out.sort();
        out
    }

    async fn fetch_discovery(&self, relay_url: &str) -> anyhow::Result<DiscoveryResponse> {
        let url = api_url(relay_url, PATH_DISCOVERY)?;
        self.get_enveloped(&url).await
    }

    async fn announce_self(
        &self,
        relay_url: &str,
        descriptor: &RelayDescriptor,
    ) -> anyhow::Result<()> {
        let url = api_url(relay_url, PATH_DISCOVERY_ANNOUNCE)?;
        let req = DiscoveryAnnounceRequest {
            protocol_version: DISCOVERY_VERSION.to_string(),
            descriptor: descriptor.clone(),
        };
        let _: DiscoveryAnnounceResponse = self.post_enveloped(&url, &req).await?;
        Ok(())
    }

    async fn get_enveloped<T>(&self, url: &str) -> anyhow::Result<T>
    where
        T: DeserializeOwned,
    {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?
            .error_for_status()
            .with_context(|| format!("GET {url} status"))?;
        decode_envelope(resp).await
    }

    async fn post_enveloped<T, B>(&self, url: &str, body: &B) -> anyhow::Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let resp = self
            .client
            .post(url)
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?
            .error_for_status()
            .with_context(|| format!("POST {url} status"))?;
        decode_envelope(resp).await
    }

    fn upsert_descriptor(
        &self,
        desc: RelayDescriptor,
        now: DateTime<Utc>,
        allow_cross_identity_takeover: bool,
    ) -> UpsertResult {
        let relay_url = desc.api_https_addr.clone();
        if relay_url.is_empty() {
            return UpsertResult::Rejected;
        }
        let mut relays = self.relays.lock().expect("discovery relays lock poisoned");
        if let Some(existing) = relays.get(&relay_url) {
            if existing.address != desc.address
                && existing.expires_at > now
                && !allow_cross_identity_takeover
            {
                return UpsertResult::Rejected;
            }
            if existing.issued_at > desc.issued_at {
                return UpsertResult::Ignored;
            }
            if existing.issued_at == desc.issued_at && existing.signature == desc.signature {
                return UpsertResult::Ignored;
            }
        }
        relays.insert(relay_url, desc);
        self.enforce_cap_locked(&mut relays);
        UpsertResult::Accepted
    }

    fn enforce_cap_locked(&self, relays: &mut HashMap<String, RelayDescriptor>) {
        let bootstraps = self
            .bootstraps
            .lock()
            .expect("discovery bootstraps lock poisoned")
            .clone();
        while relays.len() > MAX_ANNOUNCED_RELAYS {
            let Some(remove_url) = relays
                .iter()
                .filter(|(url, _)| !bootstraps.contains(url))
                .min_by_key(|(_, desc)| desc.issued_at)
                .map(|(url, _)| url.clone())
            else {
                break;
            };
            relays.remove(&remove_url);
        }
    }

    async fn ensure_registry_bootstraps(&self) {
        {
            let mut loaded = self
                .registry_bootstraps_loaded
                .lock()
                .expect("discovery registry bootstrap lock poisoned");
            if *loaded {
                return;
            }
            *loaded = true;
        }

        match self.fetch_relay_registry().await {
            Ok(relays) if !relays.is_empty() => match self.merge_bootstraps(&relays) {
                Ok(changed) if changed => debug!("relay discovery registry bootstraps merged"),
                Ok(_) => {}
                Err(err) => warn!(error = %err, "relay discovery registry bootstraps rejected"),
            },
            Ok(_) => {}
            Err(err) => debug!(error = %err, "relay discovery registry fetch failed"),
        }
    }

    async fn fetch_relay_registry(&self) -> anyhow::Result<Vec<String>> {
        #[derive(Deserialize)]
        struct RelayRegistryResponse {
            #[serde(default)]
            relays: Vec<String>,
        }

        let resp = self
            .client
            .get(PORTAL_RELAY_REGISTRY_URL)
            .send()
            .await
            .context("GET relay registry")?
            .error_for_status()
            .context("GET relay registry status")?;
        let registry = resp
            .json::<RelayRegistryResponse>()
            .await
            .context("decode relay registry")?;
        crate::config::normalize_relay_urls(&registry.relays).context("normalize registry relays")
    }

    fn merge_bootstraps(&self, relays: &[String]) -> anyhow::Result<bool> {
        let relays = crate::config::normalize_relay_urls(relays)?;
        let mut changed = false;
        let mut bootstraps = self
            .bootstraps
            .lock()
            .expect("discovery bootstraps lock poisoned");
        for relay in relays {
            if relay == self.portal_url || bootstraps.contains(&relay) {
                continue;
            }
            bootstraps.push(relay);
            changed = true;
        }
        Ok(changed)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum UpsertResult {
    Accepted,
    Ignored,
    Rejected,
}

#[derive(Debug, Deserialize)]
struct ApiEnvelopeResponse<T> {
    data: Option<T>,
    error: Option<ApiEnvelopeError>,
    ok: bool,
}

#[derive(Debug, Deserialize)]
struct ApiEnvelopeError {
    code: String,
    message: String,
}

async fn decode_envelope<T>(resp: reqwest::Response) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    let envelope = resp
        .json::<ApiEnvelopeResponse<T>>()
        .await
        .context("decode api envelope")?;
    if envelope.ok {
        return envelope.data.context("api envelope missing data");
    }
    let message = envelope
        .error
        .map(|err| format!("{}: {}", err.code, err.message))
        .unwrap_or_else(|| "api request failed".to_string());
    bail!(message)
}

fn api_url(relay_url: &str, path: &str) -> anyhow::Result<String> {
    let mut url =
        Url::parse(relay_url.trim()).with_context(|| format!("parse relay url {relay_url:?}"))?;
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

fn validate_descriptor_freshness(desc: &RelayDescriptor, now: DateTime<Utc>) -> anyhow::Result<()> {
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
    let (signature, recovery_id) = signing_key
        .sign_digest_recoverable(Sha256::new_with_prefix(&canonical))
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
    let key =
        VerifyingKey::recover_from_digest(Sha256::new_with_prefix(&canonical), &sig, recovery_id)
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
        _ if desc.address.is_empty() => bail!("address is required"),
        _ if desc.version != DISCOVERY_VERSION => {
            bail!("unsupported relay descriptor version {:?}", desc.version)
        }
        _ if desc.api_https_addr.is_empty() => bail!("api_https_addr is required"),
        _ if desc.supports_overlay && desc.wireguard_public_key.is_empty() => {
            bail!("wireguard_public_key is required when supports_overlay is set")
        }
        _ if desc.supports_overlay && desc.wireguard_port == 0 => {
            bail!("wireguard_port is required when supports_overlay is set")
        }
        _ if !desc.supports_overlay
            && (!desc.wireguard_public_key.is_empty() || desc.wireguard_port != 0) =>
        {
            bail!("supports_overlay is required when wireguard metadata is set")
        }
        _ if desc.expires_at.timestamp_nanos_opt().is_none() => {
            bail!("expires_at is required")
        }
        _ if desc.issued_at > desc.expires_at => bail!("issued_at must be before expires_at"),
        _ => {}
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
    #[derive(Serialize)]
    struct Canonical<'a> {
        address: &'a str,
        version: &'a str,
        issued_at_unix_nano: i64,
        expires_at_unix_nano: i64,
        api_https_addr: &'a str,
        wireguard_public_key: &'a str,
        wireguard_port: i64,
        supports_overlay: bool,
        supports_udp: bool,
        supports_tcp: bool,
        active_connections: i64,
        tcp_bps: serde_json::Value,
    }

    serde_json::to_vec(&Canonical {
        address: desc.address.trim(),
        version: desc.version.trim(),
        issued_at_unix_nano: desc
            .issued_at
            .timestamp_nanos_opt()
            .context("issued_at out of range")?,
        expires_at_unix_nano: desc
            .expires_at
            .timestamp_nanos_opt()
            .context("expires_at out of range")?,
        api_https_addr: desc.api_https_addr.trim(),
        wireguard_public_key: desc.wireguard_public_key.trim(),
        wireguard_port: desc.wireguard_port,
        supports_overlay: desc.supports_overlay,
        supports_udp: desc.supports_udp,
        supports_tcp: desc.supports_tcp,
        active_connections: desc.active_connections,
        tcp_bps: go_json_float(desc.tcp_bps),
    })
    .context("encode canonical relay descriptor")
}

fn go_json_float(value: f64) -> serde_json::Value {
    if value.is_finite() && value.fract() == 0.0 {
        return serde_json::Value::Number(serde_json::Number::from(value as i64));
    }
    serde_json::Number::from_f64(value)
        .map(serde_json::Value::Number)
        .unwrap_or_else(|| serde_json::Value::Number(serde_json::Number::from(0)))
}

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

fn is_zero_f64(value: &f64) -> bool {
    *value == 0.0
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use k256::ecdsa::SigningKey;
    use rand_core::OsRng;

    use super::*;
    use crate::auth::identity::address_from_signing_key;

    fn test_relay_identity(key: &SigningKey, name: &str) -> RelayIdentity {
        RelayIdentity {
            name: name.to_string(),
            address: address_from_signing_key(key),
            public_key: hex::encode(key.verifying_key().to_encoded_point(true)),
            private_key: hex::encode(key.to_bytes()),
            admin_secret_key: "admin".to_string(),
            wireguard_public_key: String::new(),
            wireguard_private_key: String::new(),
        }
    }

    fn signed_descriptor(key: &SigningKey, url: &str, issued_at: DateTime<Utc>) -> RelayDescriptor {
        sign_relay_descriptor(
            RelayDescriptor {
                address: address_from_signing_key(key),
                version: DISCOVERY_VERSION.to_string(),
                issued_at,
                expires_at: issued_at + DESCRIPTOR_TTL,
                api_https_addr: url.to_string(),
                wireguard_public_key: String::new(),
                wireguard_port: 0,
                supports_overlay: false,
                supports_udp: false,
                supports_tcp: true,
                active_connections: 0,
                tcp_bps: 0.0,
                signature: String::new(),
            },
            &hex::encode(key.to_bytes()),
        )
        .unwrap()
    }

    fn signed_overlay_descriptor(
        key: &SigningKey,
        url: &str,
        issued_at: DateTime<Utc>,
    ) -> RelayDescriptor {
        sign_relay_descriptor(
            RelayDescriptor {
                address: address_from_signing_key(key),
                version: DISCOVERY_VERSION.to_string(),
                issued_at,
                expires_at: issued_at + DESCRIPTOR_TTL,
                api_https_addr: url.to_string(),
                wireguard_public_key: "L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q=".to_string(),
                wireguard_port: 51820,
                supports_overlay: true,
                supports_udp: false,
                supports_tcp: true,
                active_connections: 0,
                tcp_bps: 0.0,
                signature: String::new(),
            },
            &hex::encode(key.to_bytes()),
        )
        .unwrap()
    }

    #[test]
    fn canonical_descriptor_uses_go_field_order_and_unix_nano() {
        let desc = RelayDescriptor {
            address: "0xabc".to_string(),
            version: "7".to_string(),
            issued_at: Utc.timestamp_opt(1, 2).unwrap(),
            expires_at: Utc.timestamp_opt(3, 4).unwrap(),
            api_https_addr: "https://relay.example".to_string(),
            wireguard_public_key: String::new(),
            wireguard_port: 0,
            supports_overlay: false,
            supports_udp: true,
            supports_tcp: false,
            active_connections: 0,
            tcp_bps: 0.0,
            signature: String::new(),
        };

        assert_eq!(
            String::from_utf8(canonical_descriptor_bytes(&desc).unwrap()).unwrap(),
            "{\"address\":\"0xabc\",\"version\":\"7\",\"issued_at_unix_nano\":1000000002,\"expires_at_unix_nano\":3000000004,\"api_https_addr\":\"https://relay.example\",\"wireguard_public_key\":\"\",\"wireguard_port\":0,\"supports_overlay\":false,\"supports_udp\":true,\"supports_tcp\":false,\"active_connections\":0,\"tcp_bps\":0}"
        );
    }

    #[test]
    fn signs_and_verifies_relay_descriptor() {
        let key = SigningKey::random(&mut OsRng);
        let address = address_from_signing_key(&key);
        let desc = RelayDescriptor {
            address: address.clone(),
            version: DISCOVERY_VERSION.to_string(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + DESCRIPTOR_TTL,
            api_https_addr: "https://relay.example".to_string(),
            wireguard_public_key: String::new(),
            wireguard_port: 0,
            supports_overlay: false,
            supports_udp: false,
            supports_tcp: true,
            active_connections: 0,
            tcp_bps: 0.0,
            signature: String::new(),
        };
        let signed = sign_relay_descriptor(desc, &hex::encode(key.to_bytes())).unwrap();
        let verified = verify_relay_descriptor(signed).unwrap();
        assert_eq!(verified.address, address);
    }

    #[test]
    fn self_descriptor_advertises_overlay_when_runtime_info_is_available() {
        let key = SigningKey::random(&mut OsRng);
        let now = Utc::now();
        let discovery = DiscoveryState::new_with_metrics_and_overlay(
            test_relay_identity(&key, "localhost"),
            "https://self.example".to_string(),
            Vec::new(),
            false,
            true,
            std::sync::Arc::new(RelayMetrics::default()),
            Some(OverlayDiscoveryInfo {
                public_key: "L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q=".to_string(),
                listen_port: 51821,
            }),
        );

        let desc = discovery.self_descriptor(now).unwrap();
        let verified = verify_relay_descriptor(desc).unwrap();

        assert!(verified.supports_overlay);
        assert_eq!(
            verified.wireguard_public_key,
            "L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q="
        );
        assert_eq!(verified.wireguard_port, 51821);
    }

    #[test]
    fn discovery_response_applies_verified_descriptors() {
        let self_key = SigningKey::random(&mut OsRng);
        let peer_key = SigningKey::random(&mut OsRng);
        let now = Utc::now();
        let discovery = DiscoveryState::new(
            test_relay_identity(&self_key, "localhost"),
            "https://self.example".to_string(),
            vec!["https://bootstrap.example".to_string()],
            false,
            true,
        );
        let peer = signed_descriptor(&peer_key, "https://peer.example", now);

        let changed = discovery
            .apply_response(
                Some("https://peer.example"),
                DiscoveryResponse {
                    protocol_version: DISCOVERY_VERSION.to_string(),
                    generated_at: now,
                    relays: vec![peer],
                },
                now,
            )
            .unwrap();

        assert!(changed);
        assert!(discovery
            .relays
            .lock()
            .expect("discovery relays lock poisoned")
            .contains_key("https://peer.example"));
        assert_eq!(
            discovery.poll_targets(now),
            vec![
                "https://bootstrap.example".to_string(),
                "https://peer.example".to_string(),
            ]
        );
    }

    #[test]
    fn registry_bootstraps_merge_with_explicit_bootstraps() {
        let self_key = SigningKey::random(&mut OsRng);
        let discovery = DiscoveryState::new(
            test_relay_identity(&self_key, "localhost"),
            "https://self.example".to_string(),
            vec!["https://explicit.example".to_string()],
            false,
            true,
        );

        let changed = discovery
            .merge_bootstraps(&[
                "https://registry.example/path".to_string(),
                "https://explicit.example".to_string(),
                "https://self.example".to_string(),
            ])
            .unwrap();

        assert!(changed);
        assert_eq!(
            discovery.bootstrap_targets(),
            vec![
                "https://explicit.example".to_string(),
                "https://registry.example".to_string(),
            ]
        );
    }

    #[test]
    fn overlay_peers_returns_fresh_overlay_descriptors() {
        let self_key = SigningKey::random(&mut OsRng);
        let overlay_key = SigningKey::random(&mut OsRng);
        let direct_key = SigningKey::random(&mut OsRng);
        let now = Utc::now();
        let discovery = DiscoveryState::new(
            test_relay_identity(&self_key, "localhost"),
            "https://self.example".to_string(),
            Vec::new(),
            false,
            true,
        );
        let overlay_peer = signed_overlay_descriptor(&overlay_key, "https://overlay.example", now);
        let direct_peer = signed_descriptor(&direct_key, "https://direct.example", now);

        discovery
            .apply_response(
                None,
                DiscoveryResponse {
                    protocol_version: DISCOVERY_VERSION.to_string(),
                    generated_at: now,
                    relays: vec![direct_peer, overlay_peer.clone()],
                },
                now,
            )
            .unwrap();

        let peers = discovery.overlay_peers(now);

        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].api_https_addr, overlay_peer.api_https_addr);
        assert!(peers[0].has_overlay_peer());
    }

    #[test]
    fn discovery_response_requires_authoritative_target_descriptor() {
        let self_key = SigningKey::random(&mut OsRng);
        let peer_key = SigningKey::random(&mut OsRng);
        let now = Utc::now();
        let discovery = DiscoveryState::new(
            test_relay_identity(&self_key, "localhost"),
            "https://self.example".to_string(),
            Vec::new(),
            false,
            true,
        );
        let peer = signed_descriptor(&peer_key, "https://other.example", now);

        let err = discovery
            .apply_response(
                Some("https://peer.example"),
                DiscoveryResponse {
                    protocol_version: DISCOVERY_VERSION.to_string(),
                    generated_at: now,
                    relays: vec![peer],
                },
                now,
            )
            .unwrap_err();

        assert!(err
            .to_string()
            .contains("target relay descriptor missing from relays"));
    }
}
