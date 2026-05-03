use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::bail;
use chrono::{DateTime, Utc};

use crate::relay::bridge::RelayMetrics;
use crate::relay::overlay::OverlayDiscoveryInfo;
use crate::state::identity::RelayIdentity;

use super::descriptor::{
    DESCRIPTOR_TTL, RelayDescriptor, sign_relay_descriptor, validate_descriptor_freshness,
};
use super::{
    DISCOVERY_VERSION, DiscoveryAnnounceRequest, DiscoveryResponse, DiscoveryState, UpsertResult,
};

const DISCOVERY_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

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
            announce_limiter: super::AnnounceLimiter::new(),
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
        let desc = super::descriptor::verify_relay_descriptor(req.descriptor)?;
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
                family: String::new(),
                subnet16: String::new(),
                supports_reservation: false,
            },
            &self.relay.private_key,
        )
    }
}
