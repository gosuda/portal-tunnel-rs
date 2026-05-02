// PRE: explicit_bootstraps known. POST: registry-fetched relays merge in without duplicates.

use anyhow::Context;
use serde::Deserialize;
use tracing::{debug, warn};

use super::DiscoveryState;

const PORTAL_RELAY_REGISTRY_URL: &str =
    "https://raw.githubusercontent.com/gosuda/portal-tunnel/main/registry.json";

impl DiscoveryState {
    pub(super) async fn ensure_registry_bootstraps(&self) {
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

    pub(super) fn merge_bootstraps(&self, relays: &[String]) -> anyhow::Result<bool> {
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
