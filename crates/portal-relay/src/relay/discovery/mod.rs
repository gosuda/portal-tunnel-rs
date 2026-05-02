use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::relay::bridge::RelayMetrics;
use crate::relay::overlay::OverlayDiscoveryInfo;
use crate::state::identity::RelayIdentity;

pub mod announce_limiter;
pub mod descriptor;
pub mod http_client;
pub mod refresh;
pub mod registry_bootstrap;
pub mod service;

#[cfg(test)]
mod tests;

pub use announce_limiter::AnnounceLimiter;
pub use descriptor::{RelayDescriptor, canonical_descriptor_bytes, verify_relay_descriptor};

// sign_relay_descriptor is test-only: service.rs imports from super::descriptor directly;
// external callers (api/mod.rs, relay/hop.rs) use it only in #[cfg(test)] modules.
#[cfg(test)]
pub use descriptor::sign_relay_descriptor;

pub const DISCOVERY_VERSION: &str = "7";
pub const DISCOVERY_POLL_INTERVAL: Duration = Duration::from_secs(30);

pub struct DiscoveryState {
    pub(super) relay: RelayIdentity,
    pub(super) portal_url: String,
    pub(super) bootstraps: Mutex<Vec<String>>,
    pub(super) registry_bootstraps_loaded: Mutex<bool>,
    pub(super) supports_udp: bool,
    pub(super) supports_tcp: bool,
    pub(super) overlay: Option<OverlayDiscoveryInfo>,
    pub(super) metrics: std::sync::Arc<RelayMetrics>,
    pub(super) client: reqwest::Client,
    pub(super) relays: Mutex<HashMap<String, RelayDescriptor>>,
    pub(crate) announce_limiter: AnnounceLimiter,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, PartialEq, Eq)]
pub(super) enum UpsertResult {
    Accepted,
    Ignored,
    Rejected,
}
