use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::auth::identity::Identity;
use crate::policy::PolicyRuntime;
use crate::relay::bridge::RelayMetrics;
use crate::relay::stream::RelayStream;
use crate::relay::tcp_port::TcpPortRuntime;
use crate::relay::udp_datagram::UdpDatagramRuntime;
use crate::state::identity::RelayIdentity;

use self::port_allocator::PortAllocator;
use self::util::is_zero;

pub mod admit;
pub mod error;
pub mod hop_routes;
pub mod lifecycle;
pub mod lookup;
pub mod port_allocator;
pub mod register;
pub mod util;
pub mod views;

#[cfg(test)]
mod tests;

pub use error::{CleanupStats, LeaseError};

const DEFAULT_LEASE_TTL: Duration = Duration::from_secs(30);
const DEFAULT_REGISTER_CHALLENGE_TTL: Duration = Duration::from_secs(2 * 60);
const DEFAULT_PORT_RESERVATION_GRACE: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LeaseMetadata {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub owner: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub thumbnail: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hide: bool,
}

impl LeaseMetadata {
    pub fn is_empty(&self) -> bool {
        self.description.is_empty()
            && self.owner.is_empty()
            && self.thumbnail.is_empty()
            && self.tags.is_empty()
            && !self.hide
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterChallengeRequest {
    pub identity: Identity,
    #[serde(default)]
    pub metadata: LeaseMetadata,
    #[serde(default)]
    pub ttl: i64,
    #[serde(default)]
    pub udp_enabled: bool,
    #[serde(default)]
    pub tcp_enabled: bool,
    #[serde(default)]
    pub hop_token: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterChallengeResponse {
    pub challenge_id: String,
    pub expires_at: DateTime<Utc>,
    pub siwe_message: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub challenge_id: String,
    pub siwe_message: String,
    pub siwe_signature: String,
    #[serde(default)]
    pub reported_ip: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub identity: Identity,
    pub expires_at: DateTime<Utc>,
    pub hostname: String,
    pub access_token: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub keyless_url: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub sni_port: u16,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub udp_addr: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub udp_enabled: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tcp_addr: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub tcp_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct LeaseView {
    #[serde(rename = "Name", skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(rename = "ExpiresAt")]
    pub expires_at: DateTime<Utc>,
    #[serde(rename = "FirstSeenAt")]
    pub first_seen_at: DateTime<Utc>,
    #[serde(rename = "LastSeenAt")]
    pub last_seen_at: DateTime<Utc>,
    #[serde(rename = "Hostname")]
    pub hostname: String,
    #[serde(rename = "UDPEnabled")]
    pub udp_enabled: bool,
    #[serde(rename = "TCPEnabled")]
    pub tcp_enabled: bool,
    #[serde(rename = "TCPAddr", skip_serializing_if = "String::is_empty")]
    pub tcp_addr: String,
    #[serde(rename = "Metadata")]
    pub metadata: LeaseMetadata,
    #[serde(rename = "Ready")]
    pub ready: usize,
}

#[derive(Debug, Serialize)]
pub struct AdminLeaseView {
    #[serde(flatten)]
    pub lease: LeaseView,
    pub identity_key: String,
    #[serde(rename = "Address")]
    pub address: String,
    #[serde(rename = "BPS")]
    pub bps: i64,
    #[serde(rename = "ClientIP")]
    pub client_ip: String,
    #[serde(rename = "ReportedIP")]
    pub reported_ip: String,
    #[serde(rename = "IsApproved")]
    pub is_approved: bool,
    #[serde(rename = "IsBanned")]
    pub is_banned: bool,
    #[serde(rename = "IsDenied")]
    pub is_denied: bool,
    #[serde(rename = "IsIPBanned")]
    pub is_ip_banned: bool,
}

#[derive(Debug, Deserialize)]
pub struct RenewRequest {
    pub access_token: String,
    #[serde(default)]
    pub ttl: i64,
    #[serde(default)]
    pub reported_ip: String,
}

#[derive(Debug, Serialize)]
pub struct RenewResponse {
    pub expires_at: DateTime<Utc>,
    pub access_token: String,
}

#[derive(Debug, Deserialize)]
pub struct UnregisterRequest {
    pub access_token: String,
}

#[derive(Debug, Clone)]
struct RegisterChallenge {
    expires_at: DateTime<Utc>,
    request: RegisterChallengeRequest,
    siwe_message: String,
}

#[derive(Clone)]
struct LeaseRecord {
    identity: Identity,
    hostname: String,
    metadata: LeaseMetadata,
    expires_at: DateTime<Utc>,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    client_ip: String,
    reported_ip: String,
    hop_token: String,
    stream: Arc<RelayStream>,
    udp_runtime: Option<Arc<UdpDatagramRuntime>>,
    tcp_runtime: Option<Arc<TcpPortRuntime>>,
    udp_port: Option<u16>,
    tcp_port: Option<u16>,
}

#[derive(Clone)]
struct HopRouteRecord {
    identity: Identity,
    hostname: String,
    metadata: LeaseMetadata,
    expires_at: DateTime<Utc>,
    first_seen_at: DateTime<Utc>,
    hop_token: String,
    next_overlay_ipv4: String,
    next_token: String,
}

#[derive(Default)]
struct LeaseRegistryInner {
    challenges: HashMap<String, RegisterChallenge>,
    leases: HashMap<String, LeaseRecord>,
    hop_routes: HashMap<String, HopRouteRecord>,
}

pub struct LeaseRegistry {
    root_host: String,
    relay: RelayIdentity,
    issuer: String,
    policy: Arc<PolicyRuntime>,
    metrics: Arc<RelayMetrics>,
    sni_port: Mutex<u16>,
    udp_enabled: bool,
    udp_ports: Mutex<PortAllocator>,
    tcp_enabled: bool,
    tcp_ports: Mutex<PortAllocator>,
    inner: Mutex<LeaseRegistryInner>,
}

pub struct LeaseRegistryConfig {
    pub root_host: String,
    pub relay: RelayIdentity,
    pub issuer: String,
    pub sni_port: u16,
    pub udp_enabled: bool,
    pub tcp_enabled: bool,
    pub min_port: u16,
    pub max_port: u16,
    pub policy: Arc<PolicyRuntime>,
    pub metrics: Arc<RelayMetrics>,
}

pub struct BridgeTarget {
    pub stream: Arc<RelayStream>,
    pub identity_key: String,
    pub policy: Arc<PolicyRuntime>,
}

pub enum HopRelayTarget {
    Direct(BridgeTarget),
    NextHop(NextHopTarget),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextHopTarget {
    pub overlay_ipv4: String,
    pub token: String,
}

impl LeaseRegistry {
    pub fn new(cfg: LeaseRegistryConfig) -> Self {
        Self {
            root_host: cfg.root_host,
            relay: cfg.relay,
            issuer: cfg.issuer,
            policy: cfg.policy,
            metrics: cfg.metrics,
            sni_port: Mutex::new(cfg.sni_port),
            udp_enabled: cfg.udp_enabled,
            udp_ports: Mutex::new(PortAllocator::new(
                cfg.min_port,
                cfg.max_port,
                DEFAULT_PORT_RESERVATION_GRACE,
            )),
            tcp_enabled: cfg.tcp_enabled,
            tcp_ports: Mutex::new(PortAllocator::new(
                cfg.min_port,
                cfg.max_port,
                DEFAULT_PORT_RESERVATION_GRACE,
            )),
            inner: Mutex::new(LeaseRegistryInner::default()),
        }
    }

    pub fn set_sni_port(&self, port: u16) {
        *self.sni_port.lock().expect("sni port lock poisoned") = port;
    }

    pub(super) fn sni_port(&self) -> u16 {
        *self.sni_port.lock().expect("sni port lock poisoned")
    }
}
