use std::collections::HashMap;

use chrono::{DateTime, Utc};
use tracing::{debug, warn};

use super::descriptor::{RelayDescriptor, validate_descriptor_freshness};
use super::{DiscoveryRefreshStats, DiscoveryState, UpsertResult};

pub(super) const MAX_ANNOUNCED_RELAYS: usize = 1024;

impl DiscoveryState {
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
        resp: super::DiscoveryResponse,
        now: DateTime<Utc>,
    ) -> anyhow::Result<bool> {
        use anyhow::bail;

        if resp.protocol_version != super::DISCOVERY_VERSION {
            bail!(
                "relay discovery protocol version mismatch: relay={:?} client={:?}",
                resp.protocol_version,
                super::DISCOVERY_VERSION
            );
        }

        let target_url = target_url.map(str::trim).filter(|url| !url.is_empty());
        let mut changed = false;
        let mut target_found = target_url.is_none();
        for descriptor in resp.relays {
            let desc = match super::descriptor::verify_relay_descriptor(descriptor) {
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

    pub(super) fn bootstrap_targets(&self) -> Vec<String> {
        self.bootstraps
            .lock()
            .expect("discovery bootstraps lock poisoned")
            .iter()
            .filter(|url| *url != &self.portal_url)
            .cloned()
            .collect()
    }

    pub(super) fn poll_targets(&self, now: DateTime<Utc>) -> Vec<String> {
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

    pub(super) fn upsert_descriptor(
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
}
