use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::auth::identity::{lease_hostname, normalize_identity, Identity};
use crate::auth::lease_token::{
    issue_lease_access_token, verify_lease_access_token, LeaseAccessTokenClaims,
};
use crate::auth::siwe::{build_register_message, verify_personal_signature};
use crate::policy::PolicyRuntime;
use crate::relay::bridge::RelayMetrics;
use crate::relay::hop::{owner_address_from_hop_route, HopRoute};
use crate::relay::stream::RelayStream;
use crate::relay::tcp_port::TcpPortRuntime;
use crate::relay::udp_datagram::UdpDatagramRuntime;
use crate::state::identity::{derive_wireguard_overlay_ipv4, RelayIdentity};

const DEFAULT_LEASE_TTL: Duration = Duration::from_secs(30);
const DEFAULT_REGISTER_CHALLENGE_TTL: Duration = Duration::from_secs(120);
const DEFAULT_PORT_RESERVATION_GRACE: Duration = Duration::from_secs(300);

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
#[allow(dead_code)]
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

#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("{0}")]
    InvalidRequest(String),
    #[error("feature unavailable")]
    FeatureUnavailable,
    #[error("hostname conflict")]
    HostnameConflict,
    #[error("lease not found")]
    LeaseNotFound,
    #[error("lease is not approved for routing")]
    LeaseRejected,
    #[error("request denied because source IP is banned")]
    IpBanned,
    #[error("udp disabled")]
    UdpDisabled,
    #[error("udp capacity exceeded")]
    UdpCapacityExceeded,
    #[error("no udp ports available")]
    UdpPortExhausted,
    #[error("tcp port disabled")]
    TcpPortDisabled,
    #[error("no tcp ports available")]
    TcpPortExhausted,
    #[error("tcp port capacity exceeded")]
    TcpPortCapacityExceeded,
    #[error("transport mismatch")]
    TransportMismatch,
    #[error("unauthorized")]
    Unauthorized,
}

impl LeaseError {
    pub fn status_code(&self) -> hyper::StatusCode {
        match self {
            LeaseError::FeatureUnavailable => hyper::StatusCode::SERVICE_UNAVAILABLE,
            LeaseError::HostnameConflict => hyper::StatusCode::CONFLICT,
            LeaseError::LeaseNotFound => hyper::StatusCode::NOT_FOUND,
            LeaseError::LeaseRejected => hyper::StatusCode::FORBIDDEN,
            LeaseError::IpBanned => hyper::StatusCode::FORBIDDEN,
            LeaseError::UdpDisabled => hyper::StatusCode::FORBIDDEN,
            LeaseError::UdpCapacityExceeded => hyper::StatusCode::SERVICE_UNAVAILABLE,
            LeaseError::UdpPortExhausted => hyper::StatusCode::SERVICE_UNAVAILABLE,
            LeaseError::TcpPortDisabled => hyper::StatusCode::FORBIDDEN,
            LeaseError::TcpPortExhausted => hyper::StatusCode::SERVICE_UNAVAILABLE,
            LeaseError::TcpPortCapacityExceeded => hyper::StatusCode::SERVICE_UNAVAILABLE,
            LeaseError::TransportMismatch => hyper::StatusCode::CONFLICT,
            LeaseError::Unauthorized => hyper::StatusCode::FORBIDDEN,
            LeaseError::InvalidRequest(_) => hyper::StatusCode::BAD_REQUEST,
        }
    }

    pub fn api_code(&self) -> &'static str {
        match self {
            LeaseError::FeatureUnavailable => "feature_unavailable",
            LeaseError::HostnameConflict => "hostname_conflict",
            LeaseError::LeaseNotFound => "lease_not_found",
            LeaseError::LeaseRejected => "lease_rejected",
            LeaseError::IpBanned => "ip_banned",
            LeaseError::UdpDisabled => "udp_disabled",
            LeaseError::UdpCapacityExceeded => "udp_capacity_exceeded",
            LeaseError::UdpPortExhausted => "udp_port_exhausted",
            LeaseError::TcpPortDisabled => "tcp_port_disabled",
            LeaseError::TcpPortExhausted => "tcp_port_exhausted",
            LeaseError::TcpPortCapacityExceeded => "tcp_port_capacity_exceeded",
            LeaseError::TransportMismatch => "transport_mismatch",
            LeaseError::Unauthorized => "unauthorized",
            LeaseError::InvalidRequest(_) => "invalid_request",
        }
    }
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

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CleanupStats {
    pub challenges: usize,
    pub leases: usize,
    pub hop_routes: usize,
}

impl CleanupStats {
    pub fn is_empty(self) -> bool {
        self.challenges == 0 && self.leases == 0 && self.hop_routes == 0
    }
}

#[derive(Default)]
struct LeaseRegistryInner {
    challenges: HashMap<String, RegisterChallenge>,
    leases: HashMap<String, LeaseRecord>,
    hop_routes: HashMap<String, HopRouteRecord>,
}

#[derive(Clone)]
#[allow(dead_code)]
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

    pub fn issue_register_challenge(
        &self,
        req: RegisterChallengeRequest,
        domain: &str,
        register_uri: &str,
        client_ip: String,
    ) -> Result<RegisterChallengeResponse, LeaseError> {
        if self.policy.is_ip_banned(&client_ip) {
            return Err(LeaseError::IpBanned);
        }
        if !req.hop_token.trim().is_empty() && (req.udp_enabled || req.tcp_enabled) {
            return Err(LeaseError::TransportMismatch);
        }
        if req.udp_enabled && !self.udp_enabled {
            return Err(LeaseError::FeatureUnavailable);
        }
        if req.udp_enabled && !self.policy.udp_policy().enabled {
            return Err(LeaseError::UdpDisabled);
        }
        if req.tcp_enabled && !self.tcp_enabled {
            return Err(LeaseError::TcpPortDisabled);
        }
        if req.tcp_enabled && !self.policy.tcp_port_policy().enabled {
            return Err(LeaseError::TcpPortDisabled);
        }

        let identity = normalize_identity(&req.identity)
            .map_err(|err| LeaseError::InvalidRequest(err.to_string()))?;
        let now = Utc::now();
        let expires_at = now
            + chrono::Duration::from_std(DEFAULT_REGISTER_CHALLENGE_TTL)
                .expect("static duration must convert");
        let challenge_id = random_id("rch_");
        let nonce = random_nonce();
        let siwe_message = build_register_message(
            domain,
            &identity.address,
            register_uri,
            &nonce,
            now,
            expires_at,
            &challenge_id,
        );

        let challenge = RegisterChallenge {
            expires_at,
            request: RegisterChallengeRequest {
                identity,
                metadata: req.metadata,
                ttl: req.ttl,
                udp_enabled: req.udp_enabled,
                tcp_enabled: req.tcp_enabled,
                hop_token: req.hop_token.trim().to_string(),
            },
            siwe_message: siwe_message.clone(),
        };

        self.inner
            .lock()
            .expect("lease registry lock poisoned")
            .challenges
            .insert(challenge_id.clone(), challenge);

        Ok(RegisterChallengeResponse {
            challenge_id,
            expires_at,
            siwe_message,
        })
    }

    pub fn register(
        &self,
        req: RegisterRequest,
        client_ip: String,
    ) -> Result<RegisterResponse, LeaseError> {
        let challenge = self.consume_verified_challenge(&req)?;
        let identity = challenge.request.identity;
        let identity_key = identity.key();
        let hostname = lease_hostname(&identity.name, &self.root_host)
            .map_err(|err| LeaseError::InvalidRequest(err.to_string()))?;
        let now = Utc::now();
        let expires_at = now + lease_ttl(challenge.request.ttl);
        let udp_requested = challenge.request.udp_enabled;
        let tcp_requested = challenge.request.tcp_enabled;
        let hop_token = challenge.request.hop_token.trim().to_string();
        if !hop_token.is_empty() && (udp_requested || tcp_requested) {
            return Err(LeaseError::TransportMismatch);
        }
        if self.policy.is_ip_banned(&client_ip) {
            return Err(LeaseError::IpBanned);
        }
        if udp_requested && !self.policy.udp_policy().enabled {
            return Err(LeaseError::UdpDisabled);
        }
        if tcp_requested && !self.policy.tcp_port_policy().enabled {
            return Err(LeaseError::TcpPortDisabled);
        }
        let (access_token, _) =
            issue_lease_access_token(&self.relay, &self.issuer, &identity, expires_at, now)
                .map_err(|err| LeaseError::InvalidRequest(err.to_string()))?;

        let mut inner = self.inner.lock().expect("lease registry lock poisoned");
        let mut active_udp_leases = 0usize;
        let mut active_tcp_leases = 0usize;
        for (existing_key, existing) in &inner.leases {
            if existing.expires_at > now && existing_key != &identity_key {
                if existing.udp_runtime.is_some() {
                    active_udp_leases += 1;
                }
                if existing.tcp_runtime.is_some() {
                    active_tcp_leases += 1;
                }
            }
            if hop_token.is_empty()
                && existing.hop_token.is_empty()
                && existing.hostname == hostname
                && existing_key != &identity_key
                && existing.expires_at > now
            {
                return Err(LeaseError::HostnameConflict);
            }
            if !hop_token.is_empty()
                && existing.expires_at > now
                && existing_key != &identity_key
                && existing.hop_token == hop_token
            {
                return Err(LeaseError::InvalidRequest("hop token conflict".to_string()));
            }
        }
        let mut replaced_hop_routes = Vec::new();
        if hop_token.is_empty() {
            for (key, existing) in &inner.hop_routes {
                if existing.expires_at <= now || existing.hostname != hostname {
                    continue;
                }
                if existing.identity.key() != identity_key {
                    return Err(LeaseError::HostnameConflict);
                }
                replaced_hop_routes.push(key.clone());
            }
        } else {
            for existing in inner.hop_routes.values() {
                if existing.expires_at > now && existing.hop_token == hop_token {
                    return Err(LeaseError::InvalidRequest("hop token conflict".to_string()));
                }
            }
        }
        if udp_requested {
            let max = self.policy.udp_policy().max_leases;
            if max > 0 && active_udp_leases >= max {
                return Err(LeaseError::UdpCapacityExceeded);
            }
        }
        if tcp_requested {
            let max = self.policy.tcp_port_policy().max_leases;
            if max > 0 && active_tcp_leases >= max {
                return Err(LeaseError::TcpPortCapacityExceeded);
            }
        }

        let stream = RelayStream::new();
        let mut udp_port = None;
        let udp_runtime = if udp_requested {
            let port = self
                .udp_ports
                .lock()
                .expect("udp port allocator lock poisoned")
                .allocate(&identity.name)
                .ok_or(LeaseError::UdpPortExhausted)?;
            match UdpDatagramRuntime::start(port) {
                Ok(runtime) => {
                    udp_port = Some(port);
                    Some(Arc::new(runtime))
                }
                Err(err) => {
                    self.udp_ports
                        .lock()
                        .expect("udp port allocator lock poisoned")
                        .release(port);
                    return Err(LeaseError::InvalidRequest(err.to_string()));
                }
            }
        } else {
            None
        };
        let udp_addr = udp_runtime
            .as_ref()
            .map(|runtime| format!("{}:{}", self.root_host, runtime.port()))
            .unwrap_or_default();

        let mut tcp_port = None;
        let tcp_runtime = if tcp_requested {
            let port = self
                .tcp_ports
                .lock()
                .expect("tcp port allocator lock poisoned")
                .allocate(&identity.name)
                .ok_or(LeaseError::TcpPortExhausted)?;
            match TcpPortRuntime::start(
                port,
                Arc::clone(&stream),
                identity_key.clone(),
                Arc::clone(&self.policy),
                Arc::clone(&self.metrics),
            ) {
                Ok(runtime) => {
                    tcp_port = Some(port);
                    Some(Arc::new(runtime))
                }
                Err(err) => {
                    self.tcp_ports
                        .lock()
                        .expect("tcp port allocator lock poisoned")
                        .release(port);
                    if let Some(port) = udp_port {
                        self.udp_ports
                            .lock()
                            .expect("udp port allocator lock poisoned")
                            .release(port);
                    }
                    return Err(LeaseError::InvalidRequest(err.to_string()));
                }
            }
        } else {
            None
        };
        let tcp_addr = tcp_runtime
            .as_ref()
            .map(|runtime| format!("{}:{}", self.root_host, runtime.port()))
            .unwrap_or_default();

        let replaced = inner.leases.insert(
            identity_key,
            LeaseRecord {
                identity: identity.clone(),
                hostname: hostname.clone(),
                metadata: challenge.request.metadata,
                expires_at,
                first_seen_at: now,
                last_seen_at: now,
                client_ip: client_ip.clone(),
                reported_ip: req.reported_ip,
                hop_token,
                stream,
                udp_runtime,
                tcp_runtime,
                udp_port,
                tcp_port,
            },
        );
        for key in replaced_hop_routes {
            inner.hop_routes.remove(&key);
        }
        drop(inner);
        if let Some(record) = replaced {
            self.release_record_ports(&record);
            self.policy.remove_identity_ip(&record.identity.key());
        }
        self.policy
            .register_identity_ip(&identity.key(), &client_ip);

        Ok(RegisterResponse {
            identity,
            expires_at,
            hostname,
            access_token,
            keyless_url: String::new(),
            sni_port: if udp_requested { self.sni_port() } else { 0 },
            udp_addr,
            udp_enabled: udp_requested,
            tcp_addr,
            tcp_enabled: tcp_requested,
        })
    }

    pub fn renew(&self, req: RenewRequest, client_ip: String) -> Result<RenewResponse, LeaseError> {
        if self.policy.is_ip_banned(&client_ip) {
            return Err(LeaseError::IpBanned);
        }
        let claims = self.verify_token(&req.access_token)?;
        let identity_key = claims.identity.key();
        let now = Utc::now();
        let expires_at = now + lease_ttl(req.ttl);

        let identity = {
            let mut inner = self.inner.lock().expect("lease registry lock poisoned");
            let lease = inner
                .leases
                .get_mut(&identity_key)
                .ok_or(LeaseError::LeaseNotFound)?;
            lease.expires_at = expires_at;
            lease.last_seen_at = now;
            lease.client_ip = client_ip.clone();
            lease.reported_ip = req.reported_ip;
            lease.identity.clone()
        };

        let (access_token, _) =
            issue_lease_access_token(&self.relay, &self.issuer, &identity, expires_at, now)
                .map_err(|err| LeaseError::InvalidRequest(err.to_string()))?;
        self.policy.register_identity_ip(&identity_key, &client_ip);
        Ok(RenewResponse {
            expires_at,
            access_token,
        })
    }

    pub fn unregister(&self, req: UnregisterRequest) -> Result<(), LeaseError> {
        let claims = self.verify_token(&req.access_token)?;
        let removed = self
            .inner
            .lock()
            .expect("lease registry lock poisoned")
            .leases
            .remove(&claims.identity.key());
        match removed {
            Some(record) => {
                self.release_record_ports(&record);
                self.policy.remove_identity_ip(&record.identity.key());
                Ok(())
            }
            None => Err(LeaseError::LeaseNotFound),
        }
    }

    pub fn cleanup_expired(&self, now: DateTime<Utc>) -> CleanupStats {
        let mut removed_leases = Vec::new();
        let mut stats = CleanupStats::default();
        {
            let mut inner = self.inner.lock().expect("lease registry lock poisoned");

            let previous_challenges = inner.challenges.len();
            inner
                .challenges
                .retain(|_, challenge| challenge.expires_at > now);
            stats.challenges = previous_challenges.saturating_sub(inner.challenges.len());

            let expired_lease_keys: Vec<String> = inner
                .leases
                .iter()
                .filter_map(|(key, lease)| (lease.expires_at <= now).then_some(key.clone()))
                .collect();
            stats.leases = expired_lease_keys.len();
            for key in expired_lease_keys {
                if let Some(record) = inner.leases.remove(&key) {
                    removed_leases.push(record);
                }
            }

            let previous_hop_routes = inner.hop_routes.len();
            inner.hop_routes.retain(|_, route| route.expires_at > now);
            stats.hop_routes = previous_hop_routes.saturating_sub(inner.hop_routes.len());
        }

        for record in removed_leases {
            self.release_record_ports(&record);
            self.policy.remove_identity_ip(&record.identity.key());
        }
        stats
    }

    pub fn register_hop_route(
        &self,
        route: HopRoute,
        now: DateTime<Utc>,
    ) -> Result<(), LeaseError> {
        let owner_address = owner_address_from_hop_route(&route)
            .map_err(|err| LeaseError::InvalidRequest(err.to_string()))?;
        let match_hostname = crate::auth::identity::normalize_hostname(&route.match_hostname);
        let match_token = route.match_token.trim().to_string();
        let forward_token = route.forward_token.trim().to_string();
        if route.expires_at <= now {
            return Err(LeaseError::InvalidRequest(
                "route expiry must be in the future".to_string(),
            ));
        }
        if match_hostname.is_empty() && match_token.is_empty() {
            return Err(LeaseError::InvalidRequest(
                "hostname or token matcher is required".to_string(),
            ));
        }
        if !match_hostname.is_empty() && !match_token.is_empty() {
            return Err(LeaseError::InvalidRequest(
                "hostname and token matchers are mutually exclusive".to_string(),
            ));
        }
        if !route.forward_relay.has_overlay_peer() {
            return Err(LeaseError::InvalidRequest(
                "forward relay wireguard overlay metadata is required".to_string(),
            ));
        }
        if forward_token.is_empty() {
            return Err(LeaseError::InvalidRequest(
                "forward token is required".to_string(),
            ));
        }
        let next_overlay_ipv4 =
            derive_wireguard_overlay_ipv4(&route.forward_relay.wireguard_public_key)
                .map_err(|err| {
                    LeaseError::InvalidRequest(format!("forward relay overlay ipv4: {err}"))
                })?
                .to_string();
        let name = match_hostname
            .split_once('.')
            .map(|(label, _)| label.to_string())
            .unwrap_or_default();
        let record = HopRouteRecord {
            identity: Identity {
                name,
                address: owner_address,
                public_key: String::new(),
                private_key: String::new(),
            },
            hostname: match_hostname,
            metadata: route.metadata,
            first_seen_at: route.first_seen_at,
            expires_at: route.expires_at,
            hop_token: match_token,
            next_overlay_ipv4,
            next_token: forward_token,
        };
        let key = hop_route_record_key(&record);
        let mut inner = self.inner.lock().expect("lease registry lock poisoned");
        if !record.hostname.is_empty() {
            for existing in inner.leases.values() {
                if existing.expires_at > now
                    && existing.hop_token.is_empty()
                    && existing.hostname == record.hostname
                {
                    return Err(LeaseError::HostnameConflict);
                }
            }
            for existing in inner.hop_routes.values() {
                if existing.expires_at > now
                    && existing.hostname == record.hostname
                    && existing.identity.address != record.identity.address
                {
                    return Err(LeaseError::HostnameConflict);
                }
            }
        }
        if !record.hop_token.is_empty() {
            for existing in inner.leases.values() {
                if existing.expires_at > now && existing.hop_token == record.hop_token {
                    return Err(LeaseError::InvalidRequest("hop token conflict".to_string()));
                }
            }
            for existing in inner.hop_routes.values() {
                if existing.expires_at > now
                    && existing.hop_token == record.hop_token
                    && existing.identity.address != record.identity.address
                {
                    return Err(LeaseError::InvalidRequest("hop token conflict".to_string()));
                }
            }
        }
        inner.hop_routes.insert(key, record);
        Ok(())
    }

    pub fn delete_hop_route(&self, route: &HopRoute) -> Result<(), LeaseError> {
        let owner_address = owner_address_from_hop_route(route)
            .map_err(|err| LeaseError::InvalidRequest(err.to_string()))?;
        let hostname = crate::auth::identity::normalize_hostname(&route.match_hostname);
        let token = route.match_token.trim();
        let mut inner = self.inner.lock().expect("lease registry lock poisoned");
        let key = if !hostname.is_empty() {
            format!("host:{hostname}:{}", owner_address.to_ascii_lowercase())
        } else if !token.is_empty() {
            format!("token:{token}:{}", owner_address.to_ascii_lowercase())
        } else {
            return Ok(());
        };
        inner.hop_routes.remove(&key);
        Ok(())
    }

    pub fn admit_connect(&self, token: &str) -> Result<Arc<RelayStream>, LeaseError> {
        let claims = self.verify_token(token)?;
        let now = Utc::now();
        let inner = self.inner.lock().expect("lease registry lock poisoned");
        let lease = inner
            .leases
            .get(&claims.identity.key())
            .ok_or(LeaseError::LeaseNotFound)?;
        if lease.expires_at <= now {
            return Err(LeaseError::LeaseNotFound);
        }
        if !self
            .policy
            .is_identity_routable(&claims.identity.key(), &lease.client_ip)
        {
            return Err(LeaseError::LeaseRejected);
        }
        Ok(Arc::clone(&lease.stream))
    }

    pub fn admit_datagram(&self, token: &str) -> Result<Arc<UdpDatagramRuntime>, LeaseError> {
        let claims = self.verify_token(token)?;
        let now = Utc::now();
        let inner = self.inner.lock().expect("lease registry lock poisoned");
        let lease = inner
            .leases
            .get(&claims.identity.key())
            .ok_or(LeaseError::LeaseNotFound)?;
        if lease.expires_at <= now {
            return Err(LeaseError::LeaseNotFound);
        }
        if !self
            .policy
            .is_identity_routable(&claims.identity.key(), &lease.client_ip)
        {
            return Err(LeaseError::LeaseRejected);
        }
        lease
            .udp_runtime
            .as_ref()
            .map(Arc::clone)
            .ok_or(LeaseError::TransportMismatch)
    }

    pub fn lookup_stream(&self, hostname: &str) -> Option<BridgeTarget> {
        let hostname = crate::auth::identity::normalize_hostname(hostname);
        let wildcard = one_level_wildcard_hostname(&hostname);
        let now = Utc::now();
        let inner = self.inner.lock().expect("lease registry lock poisoned");
        inner
            .leases
            .values()
            .find(|lease| {
                lease.hop_token.is_empty()
                    && lease.hostname == hostname
                    && lease.expires_at > now
                    && self
                        .policy
                        .is_identity_routable(&lease.identity.key(), &lease.client_ip)
            })
            .or_else(|| {
                wildcard.as_ref().and_then(|wildcard| {
                    inner.leases.values().find(|lease| {
                        lease.hop_token.is_empty()
                            && lease.hostname == *wildcard
                            && lease.expires_at > now
                            && self
                                .policy
                                .is_identity_routable(&lease.identity.key(), &lease.client_ip)
                    })
                })
            })
            .map(|lease| BridgeTarget {
                stream: Arc::clone(&lease.stream),
                identity_key: lease.identity.key(),
                policy: Arc::clone(&self.policy),
            })
    }

    pub fn lookup_next_hop(&self, hostname: &str) -> Option<NextHopTarget> {
        let hostname = crate::auth::identity::normalize_hostname(hostname);
        let wildcard = one_level_wildcard_hostname(&hostname);
        let now = Utc::now();
        let inner = self.inner.lock().expect("lease registry lock poisoned");
        inner
            .hop_routes
            .values()
            .find(|route| {
                route.hostname == hostname
                    && route.expires_at > now
                    && !route.next_overlay_ipv4.is_empty()
                    && !route.next_token.is_empty()
            })
            .or_else(|| {
                wildcard.as_ref().and_then(|wildcard| {
                    inner.hop_routes.values().find(|route| {
                        route.hostname == *wildcard
                            && route.expires_at > now
                            && !route.next_overlay_ipv4.is_empty()
                            && !route.next_token.is_empty()
                    })
                })
            })
            .map(|route| NextHopTarget {
                overlay_ipv4: route.next_overlay_ipv4.clone(),
                token: route.next_token.clone(),
            })
    }

    pub fn lookup_hop_token(&self, token: &str) -> Option<HopRelayTarget> {
        let token = token.trim();
        if token.is_empty() {
            return None;
        }
        let now = Utc::now();
        let inner = self.inner.lock().expect("lease registry lock poisoned");
        if let Some(lease) = inner.leases.values().find(|lease| {
            lease.hop_token == token
                && lease.expires_at > now
                && self
                    .policy
                    .is_identity_routable(&lease.identity.key(), &lease.client_ip)
        }) {
            return Some(HopRelayTarget::Direct(BridgeTarget {
                stream: Arc::clone(&lease.stream),
                identity_key: lease.identity.key(),
                policy: Arc::clone(&self.policy),
            }));
        }

        inner
            .hop_routes
            .values()
            .find(|route| {
                route.hop_token == token
                    && route.expires_at > now
                    && !route.next_overlay_ipv4.is_empty()
                    && !route.next_token.is_empty()
            })
            .map(|route| {
                HopRelayTarget::NextHop(NextHopTarget {
                    overlay_ipv4: route.next_overlay_ipv4.clone(),
                    token: route.next_token.clone(),
                })
            })
    }

    pub async fn public_leases(&self) -> Vec<LeaseView> {
        let now = Utc::now();
        let (leases, routes): (Vec<LeaseRecord>, Vec<HopRouteRecord>) = {
            let inner = self.inner.lock().expect("lease registry lock poisoned");
            let leases = inner
                .leases
                .values()
                .filter(|lease| {
                    lease.hop_token.is_empty()
                        && !lease.hostname.is_empty()
                        && lease.expires_at > now
                        && !lease.metadata.hide
                        && self
                            .policy
                            .is_identity_routable(&lease.identity.key(), &lease.client_ip)
                })
                .cloned()
                .collect();
            let routes = inner
                .hop_routes
                .values()
                .filter(|route| {
                    route.hop_token.is_empty()
                        && !route.hostname.is_empty()
                        && route.expires_at > now
                        && !route.metadata.hide
                        && !route.next_overlay_ipv4.is_empty()
                        && !route.next_token.is_empty()
                })
                .cloned()
                .collect();
            (leases, routes)
        };

        let mut out = Vec::with_capacity(leases.len() + routes.len());
        for lease in leases {
            let ready = lease.stream.ready_count().await;
            let idle_for = now.signed_duration_since(lease.last_seen_at);
            if ready == 0 && idle_for >= ChronoDuration::minutes(3) {
                continue;
            }
            out.push(LeaseView {
                name: lease.identity.name,
                expires_at: lease.expires_at,
                first_seen_at: lease.first_seen_at,
                last_seen_at: lease.last_seen_at,
                hostname: lease.hostname.clone(),
                udp_enabled: lease.udp_runtime.is_some(),
                tcp_enabled: lease.tcp_runtime.is_some(),
                tcp_addr: lease
                    .tcp_port
                    .map(|port| format!("{}:{port}", lease.hostname))
                    .unwrap_or_default(),
                metadata: lease.metadata,
                ready,
            });
        }
        for route in routes {
            out.push(LeaseView {
                name: route.identity.name,
                expires_at: route.expires_at,
                first_seen_at: route.first_seen_at,
                last_seen_at: route.first_seen_at,
                hostname: route.hostname,
                udp_enabled: false,
                tcp_enabled: false,
                tcp_addr: String::new(),
                metadata: route.metadata,
                ready: 1,
            });
        }
        out
    }

    pub async fn admin_leases(&self) -> Vec<AdminLeaseView> {
        let now = Utc::now();
        let records: Vec<(String, LeaseRecord)> = {
            let inner = self.inner.lock().expect("lease registry lock poisoned");
            inner
                .leases
                .iter()
                .filter(|(_, lease)| lease.expires_at > now)
                .map(|(key, lease)| (key.clone(), lease.clone()))
                .collect()
        };

        let mut out = Vec::with_capacity(records.len());
        for (identity_key, lease) in records {
            let ready = lease.stream.ready_count().await;
            let status = self.policy.identity_status(&identity_key, &lease.client_ip);
            out.push(AdminLeaseView {
                lease: LeaseView {
                    name: lease.identity.name.clone(),
                    expires_at: lease.expires_at,
                    first_seen_at: lease.first_seen_at,
                    last_seen_at: lease.last_seen_at,
                    hostname: lease.hostname.clone(),
                    udp_enabled: lease.udp_runtime.is_some(),
                    tcp_enabled: lease.tcp_runtime.is_some(),
                    tcp_addr: lease
                        .tcp_port
                        .map(|port| format!("{}:{}", lease.hostname, port))
                        .unwrap_or_default(),
                    metadata: lease.metadata.clone(),
                    ready,
                },
                identity_key,
                address: lease.identity.address,
                bps: status.bps,
                client_ip: lease.client_ip,
                reported_ip: lease.reported_ip,
                is_approved: status.is_approved,
                is_banned: status.is_banned,
                is_denied: status.is_denied,
                is_ip_banned: status.is_ip_banned,
            });
        }
        out
    }

    pub fn verify_token(&self, token: &str) -> Result<LeaseAccessTokenClaims, LeaseError> {
        verify_lease_access_token(token, &self.relay, &self.issuer, Utc::now())
            .map_err(|_| LeaseError::Unauthorized)
    }

    fn consume_verified_challenge(
        &self,
        req: &RegisterRequest,
    ) -> Result<RegisterChallenge, LeaseError> {
        let challenge_id = req.challenge_id.trim();
        if challenge_id.is_empty() {
            return Err(LeaseError::InvalidRequest(
                "register challenge not found".to_string(),
            ));
        }

        let challenge = self
            .inner
            .lock()
            .expect("lease registry lock poisoned")
            .challenges
            .remove(challenge_id)
            .ok_or_else(|| {
                LeaseError::InvalidRequest("register challenge not found".to_string())
            })?;

        let now = Utc::now();
        if challenge.expires_at <= now {
            return Err(LeaseError::InvalidRequest(
                "register challenge expired".to_string(),
            ));
        }
        if req.siwe_message.trim() != challenge.siwe_message {
            return Err(LeaseError::InvalidRequest(
                "siwe message does not match register challenge".to_string(),
            ));
        }
        verify_personal_signature(
            &challenge.siwe_message,
            &req.siwe_signature,
            &challenge.request.identity.address,
        )
        .map_err(|_| LeaseError::Unauthorized)?;
        Ok(challenge)
    }

    fn sni_port(&self) -> u16 {
        *self.sni_port.lock().expect("sni port lock poisoned")
    }

    fn release_record_ports(&self, record: &LeaseRecord) {
        if let Some(port) = record.udp_port {
            self.udp_ports
                .lock()
                .expect("udp port allocator lock poisoned")
                .release(port);
        }
        if let Some(port) = record.tcp_port {
            self.tcp_ports
                .lock()
                .expect("tcp port allocator lock poisoned")
                .release(port);
        }
    }
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

struct PortAllocator {
    available: VecDeque<u16>,
    in_use: HashMap<u16, String>,
    reserved: HashMap<String, PortReservation>,
    grace: Duration,
}

#[derive(Clone, Copy)]
struct PortReservation {
    port: u16,
    expires_at: Instant,
}

impl PortAllocator {
    fn new(min_port: u16, max_port: u16, grace: Duration) -> Self {
        let available = if min_port > 0 && max_port >= min_port {
            (min_port..=max_port).collect()
        } else {
            VecDeque::new()
        };
        Self {
            available,
            in_use: HashMap::new(),
            reserved: HashMap::new(),
            grace,
        }
    }

    fn allocate(&mut self, owner: &str) -> Option<u16> {
        self.cleanup_expired(Instant::now());
        if let Some(reservation) = self.reserved.remove(owner) {
            self.in_use.insert(reservation.port, owner.to_string());
            return Some(reservation.port);
        }
        let port = self.available.pop_front()?;
        self.in_use.insert(port, owner.to_string());
        Some(port)
    }

    fn release(&mut self, port: u16) {
        let Some(owner) = self.in_use.remove(&port) else {
            return;
        };
        if let Some(previous) = self.reserved.insert(
            owner,
            PortReservation {
                port,
                expires_at: Instant::now() + self.grace,
            },
        ) {
            self.sorted_insert(previous.port);
        }
        self.cleanup_expired(Instant::now());
    }

    fn cleanup_expired(&mut self, now: Instant) {
        let expired: Vec<String> = self
            .reserved
            .iter()
            .filter_map(|(owner, reservation)| {
                (now > reservation.expires_at).then_some(owner.clone())
            })
            .collect();
        for owner in expired {
            if let Some(reservation) = self.reserved.remove(&owner) {
                self.sorted_insert(reservation.port);
            }
        }
    }

    fn sorted_insert(&mut self, port: u16) {
        let idx = self
            .available
            .iter()
            .position(|candidate| *candidate >= port)
            .unwrap_or(self.available.len());
        self.available.insert(idx, port);
    }
}

fn lease_ttl(seconds: i64) -> chrono::Duration {
    if seconds > 0 {
        return chrono::Duration::seconds(seconds);
    }
    chrono::Duration::from_std(DEFAULT_LEASE_TTL).expect("static duration must convert")
}

fn random_id(prefix: &str) -> String {
    let mut buf = [0u8; 8];
    OsRng.fill_bytes(&mut buf);
    format!("{prefix}{}", hex::encode(buf))
}

fn random_nonce() -> String {
    let mut buf = [0u8; 8];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

fn is_zero(value: &u16) -> bool {
    *value == 0
}

fn hop_route_record_key(record: &HopRouteRecord) -> String {
    let owner = record.identity.address.to_ascii_lowercase();
    if !record.hostname.is_empty() {
        return format!("host:{}:{owner}", record.hostname);
    }
    format!("token:{}:{owner}", record.hop_token)
}

fn one_level_wildcard_hostname(hostname: &str) -> Option<String> {
    let (first, rest) = hostname.split_once('.')?;
    if first.is_empty() || rest.is_empty() || rest.contains("..") {
        return None;
    }
    Some(format!("*.{rest}"))
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::SigningKey;
    use rand_core::OsRng;

    use super::*;
    use crate::auth::identity::{address_from_signing_key, compressed_public_key_hex};
    use crate::relay::discovery::{RelayDescriptor, DISCOVERY_VERSION};

    #[test]
    fn issues_and_verifies_lease_token() {
        let signing_key = SigningKey::random(&mut OsRng);
        let relay = RelayIdentity {
            name: "localhost".to_string(),
            address: address_from_signing_key(&signing_key),
            public_key: compressed_public_key_hex(&signing_key),
            private_key: hex::encode(signing_key.to_bytes()),
            admin_secret_key: "admin".to_string(),
            wireguard_public_key: String::new(),
            wireguard_private_key: String::new(),
        };
        let identity = Identity {
            name: "demo".to_string(),
            address: relay.address.clone(),
            public_key: String::new(),
            private_key: String::new(),
        };
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(30);
        let (token, claims) =
            issue_lease_access_token(&relay, "https://localhost:4017", &identity, expires_at, now)
                .unwrap();
        assert_eq!(
            claims.sub,
            "demo:".to_string() + &relay.address.to_ascii_lowercase()
        );

        let verified =
            verify_lease_access_token(&token, &relay, "https://localhost:4017", now).unwrap();
        assert_eq!(verified.identity.name, "demo");
    }

    #[test]
    fn port_allocator_keeps_sticky_reservation() {
        let mut allocator = PortAllocator::new(5000, 5001, Duration::from_secs(300));
        let alice = allocator.allocate("alice").unwrap();
        assert_eq!(alice, 5000);
        allocator.release(alice);

        let bob = allocator.allocate("bob").unwrap();
        assert_eq!(bob, 5001);
        let alice_again = allocator.allocate("alice").unwrap();
        assert_eq!(alice_again, 5000);
    }

    #[test]
    fn cleanup_expired_removes_registry_records() {
        let signing_key = SigningKey::random(&mut OsRng);
        let relay = RelayIdentity {
            name: "localhost".to_string(),
            address: address_from_signing_key(&signing_key),
            public_key: compressed_public_key_hex(&signing_key),
            private_key: hex::encode(signing_key.to_bytes()),
            admin_secret_key: "admin".to_string(),
            wireguard_public_key: String::new(),
            wireguard_private_key: String::new(),
        };
        let policy_path = std::env::temp_dir().join(format!("portal-policy-{}", random_id("")));
        let policy = Arc::new(PolicyRuntime::load(&policy_path, false, false).unwrap());
        let registry = LeaseRegistry::new(LeaseRegistryConfig {
            root_host: "localhost".to_string(),
            relay,
            issuer: "https://localhost:4017".to_string(),
            sni_port: 443,
            udp_enabled: false,
            tcp_enabled: false,
            min_port: 0,
            max_port: 0,
            policy,
            metrics: Arc::new(RelayMetrics::default()),
        });
        let now = Utc::now();
        let expired = now - chrono::Duration::seconds(1);
        let identity = Identity {
            name: "demo".to_string(),
            address: "0x0000000000000000000000000000000000000001".to_string(),
            public_key: String::new(),
            private_key: String::new(),
        };
        let hop_record = HopRouteRecord {
            identity: identity.clone(),
            hostname: "hop.localhost".to_string(),
            metadata: LeaseMetadata::default(),
            expires_at: expired,
            first_seen_at: expired,
            hop_token: String::new(),
            next_overlay_ipv4: "100.64.0.10".to_string(),
            next_token: "hpt_next".to_string(),
        };
        registry
            .inner
            .lock()
            .expect("lease registry lock poisoned")
            .challenges
            .insert(
                "rch_expired".to_string(),
                RegisterChallenge {
                    expires_at: expired,
                    request: RegisterChallengeRequest {
                        identity: identity.clone(),
                        metadata: LeaseMetadata::default(),
                        ttl: 0,
                        udp_enabled: false,
                        tcp_enabled: false,
                        hop_token: String::new(),
                    },
                    siwe_message: String::new(),
                },
            );
        registry
            .inner
            .lock()
            .expect("lease registry lock poisoned")
            .leases
            .insert(
                identity.key(),
                LeaseRecord {
                    identity: identity.clone(),
                    hostname: "demo.localhost".to_string(),
                    metadata: LeaseMetadata::default(),
                    expires_at: expired,
                    first_seen_at: expired,
                    last_seen_at: expired,
                    client_ip: "127.0.0.1".to_string(),
                    reported_ip: String::new(),
                    hop_token: String::new(),
                    stream: RelayStream::new(),
                    udp_runtime: None,
                    tcp_runtime: None,
                    udp_port: None,
                    tcp_port: None,
                },
            );
        registry
            .inner
            .lock()
            .expect("lease registry lock poisoned")
            .hop_routes
            .insert(hop_route_record_key(&hop_record), hop_record);

        assert_eq!(
            registry.cleanup_expired(now),
            CleanupStats {
                challenges: 1,
                leases: 1,
                hop_routes: 1,
            }
        );

        let inner = registry.inner.lock().expect("lease registry lock poisoned");
        assert!(inner.challenges.is_empty());
        assert!(inner.leases.is_empty());
        assert!(inner.hop_routes.is_empty());
    }

    #[test]
    fn register_hop_route_rejects_active_direct_hostname_conflict() {
        let signing_key = SigningKey::random(&mut OsRng);
        let relay = RelayIdentity {
            name: "localhost".to_string(),
            address: address_from_signing_key(&signing_key),
            public_key: compressed_public_key_hex(&signing_key),
            private_key: hex::encode(signing_key.to_bytes()),
            admin_secret_key: "admin".to_string(),
            wireguard_public_key: String::new(),
            wireguard_private_key: String::new(),
        };
        let policy_path = std::env::temp_dir().join(format!("portal-policy-{}", random_id("")));
        let registry = LeaseRegistry::new(LeaseRegistryConfig {
            root_host: "localhost".to_string(),
            relay,
            issuer: "https://localhost:4017".to_string(),
            sni_port: 443,
            udp_enabled: false,
            tcp_enabled: false,
            min_port: 0,
            max_port: 0,
            policy: Arc::new(PolicyRuntime::load(&policy_path, false, false).unwrap()),
            metrics: Arc::new(RelayMetrics::default()),
        });
        let now = Utc::now();
        let identity = Identity {
            name: "demo".to_string(),
            address: "0x0000000000000000000000000000000000000001".to_string(),
            public_key: String::new(),
            private_key: String::new(),
        };
        registry
            .inner
            .lock()
            .expect("lease registry lock poisoned")
            .leases
            .insert(
                identity.key(),
                LeaseRecord {
                    identity,
                    hostname: "demo.localhost".to_string(),
                    metadata: LeaseMetadata::default(),
                    expires_at: now + chrono::Duration::seconds(30),
                    first_seen_at: now,
                    last_seen_at: now,
                    client_ip: "127.0.0.1".to_string(),
                    reported_ip: String::new(),
                    hop_token: String::new(),
                    stream: RelayStream::new(),
                    udp_runtime: None,
                    tcp_runtime: None,
                    udp_port: None,
                    tcp_port: None,
                },
            );

        let owner = SigningKey::random(&mut OsRng);
        let route = HopRoute {
            owner_public_key: hex::encode(owner.verifying_key().to_encoded_point(true)),
            relay_url: "https://localhost:4017".to_string(),
            match_hostname: "demo.localhost".to_string(),
            match_token: String::new(),
            metadata: LeaseMetadata::default(),
            forward_relay: test_overlay_descriptor(now),
            forward_token: "hpt_next".to_string(),
            first_seen_at: now,
            expires_at: now + chrono::Duration::seconds(30),
            signature: String::new(),
        };

        assert!(matches!(
            registry.register_hop_route(route, now),
            Err(LeaseError::HostnameConflict)
        ));
    }

    #[test]
    fn lookup_next_hop_returns_active_hop_route_target() {
        let registry = test_registry();
        let now = Utc::now();
        let identity = Identity {
            name: "demo".to_string(),
            address: "0x0000000000000000000000000000000000000001".to_string(),
            public_key: String::new(),
            private_key: String::new(),
        };
        let active_record = HopRouteRecord {
            identity: identity.clone(),
            hostname: "demo.localhost".to_string(),
            metadata: LeaseMetadata::default(),
            expires_at: now + chrono::Duration::seconds(30),
            first_seen_at: now,
            hop_token: String::new(),
            next_overlay_ipv4: "100.64.0.10".to_string(),
            next_token: "hpt_next".to_string(),
        };
        let expired_record = HopRouteRecord {
            identity,
            hostname: "expired.localhost".to_string(),
            metadata: LeaseMetadata::default(),
            expires_at: now - chrono::Duration::seconds(1),
            first_seen_at: now,
            hop_token: String::new(),
            next_overlay_ipv4: "100.64.0.11".to_string(),
            next_token: "hpt_expired".to_string(),
        };
        let mut inner = registry.inner.lock().expect("lease registry lock poisoned");
        inner
            .hop_routes
            .insert(hop_route_record_key(&active_record), active_record);
        inner
            .hop_routes
            .insert(hop_route_record_key(&expired_record), expired_record);
        drop(inner);

        assert_eq!(
            registry.lookup_next_hop(" Demo.Localhost. "),
            Some(NextHopTarget {
                overlay_ipv4: "100.64.0.10".to_string(),
                token: "hpt_next".to_string(),
            })
        );
        assert_eq!(registry.lookup_next_hop("expired.localhost"), None);
    }

    #[test]
    fn lookup_next_hop_matches_one_level_wildcard_route() {
        let registry = test_registry();
        let now = Utc::now();
        let wildcard_record = HopRouteRecord {
            identity: Identity {
                name: "*".to_string(),
                address: "0x0000000000000000000000000000000000000001".to_string(),
                public_key: String::new(),
                private_key: String::new(),
            },
            hostname: "*.localhost".to_string(),
            metadata: LeaseMetadata::default(),
            expires_at: now + chrono::Duration::seconds(30),
            first_seen_at: now,
            hop_token: String::new(),
            next_overlay_ipv4: "100.64.0.12".to_string(),
            next_token: "hpt_wildcard".to_string(),
        };
        registry
            .inner
            .lock()
            .expect("lease registry lock poisoned")
            .hop_routes
            .insert(hop_route_record_key(&wildcard_record), wildcard_record);

        assert_eq!(
            registry.lookup_next_hop("app.localhost"),
            Some(NextHopTarget {
                overlay_ipv4: "100.64.0.12".to_string(),
                token: "hpt_wildcard".to_string(),
            })
        );
        assert_eq!(registry.lookup_next_hop("deep.app.localhost"), None);
    }

    #[test]
    fn lookup_hop_token_returns_direct_hop_lease() {
        let registry = test_registry();
        let now = Utc::now();
        let identity = Identity {
            name: "demo".to_string(),
            address: "0x0000000000000000000000000000000000000001".to_string(),
            public_key: String::new(),
            private_key: String::new(),
        };
        let identity_key = identity.key();
        registry
            .inner
            .lock()
            .expect("lease registry lock poisoned")
            .leases
            .insert(
                identity_key,
                LeaseRecord {
                    identity,
                    hostname: "demo.localhost".to_string(),
                    metadata: LeaseMetadata::default(),
                    expires_at: now + chrono::Duration::seconds(30),
                    first_seen_at: now,
                    last_seen_at: now,
                    client_ip: "127.0.0.1".to_string(),
                    reported_ip: String::new(),
                    hop_token: "hpt_exit".to_string(),
                    stream: RelayStream::new(),
                    udp_runtime: None,
                    tcp_runtime: None,
                    udp_port: None,
                    tcp_port: None,
                },
            );

        let Some(HopRelayTarget::Direct(target)) = registry.lookup_hop_token(" hpt_exit ") else {
            panic!("expected direct hop target");
        };
        assert_eq!(
            target.identity_key,
            "demo:0x0000000000000000000000000000000000000001"
        );
    }

    #[test]
    fn lookup_hop_token_returns_middle_next_hop_route() {
        let registry = test_registry();
        let now = Utc::now();
        let route = HopRouteRecord {
            identity: Identity {
                name: String::new(),
                address: "0x0000000000000000000000000000000000000001".to_string(),
                public_key: String::new(),
                private_key: String::new(),
            },
            hostname: String::new(),
            metadata: LeaseMetadata::default(),
            expires_at: now + chrono::Duration::seconds(30),
            first_seen_at: now,
            hop_token: "hpt_middle".to_string(),
            next_overlay_ipv4: "100.64.0.20".to_string(),
            next_token: "hpt_next".to_string(),
        };
        registry
            .inner
            .lock()
            .expect("lease registry lock poisoned")
            .hop_routes
            .insert(hop_route_record_key(&route), route);

        assert!(matches!(
            registry.lookup_hop_token("hpt_middle"),
            Some(HopRelayTarget::NextHop(NextHopTarget {
                overlay_ipv4,
                token,
            })) if overlay_ipv4 == "100.64.0.20" && token == "hpt_next"
        ));
        assert!(registry.lookup_hop_token("").is_none());
    }

    #[test]
    fn lookup_stream_returns_identity_bps_limit() {
        let signing_key = SigningKey::random(&mut OsRng);
        let relay = RelayIdentity {
            name: "localhost".to_string(),
            address: address_from_signing_key(&signing_key),
            public_key: compressed_public_key_hex(&signing_key),
            private_key: hex::encode(signing_key.to_bytes()),
            admin_secret_key: "admin".to_string(),
            wireguard_public_key: String::new(),
            wireguard_private_key: String::new(),
        };
        let policy_path = std::env::temp_dir().join(format!("portal-policy-{}", random_id("")));
        let policy = Arc::new(PolicyRuntime::load(&policy_path, false, false).unwrap());
        let registry = LeaseRegistry::new(LeaseRegistryConfig {
            root_host: "localhost".to_string(),
            relay,
            issuer: "https://localhost:4017".to_string(),
            sni_port: 443,
            udp_enabled: false,
            tcp_enabled: false,
            min_port: 0,
            max_port: 0,
            policy: Arc::clone(&policy),
            metrics: Arc::new(RelayMetrics::default()),
        });
        let identity = Identity {
            name: "demo".to_string(),
            address: "0x0000000000000000000000000000000000000001".to_string(),
            public_key: String::new(),
            private_key: String::new(),
        };
        let identity_key = identity.key();
        policy.set_identity_bps(&identity_key, 4096);
        registry
            .inner
            .lock()
            .expect("lease registry lock poisoned")
            .leases
            .insert(
                identity_key,
                LeaseRecord {
                    identity,
                    hostname: "demo.localhost".to_string(),
                    metadata: LeaseMetadata::default(),
                    expires_at: Utc::now() + chrono::Duration::seconds(30),
                    first_seen_at: Utc::now(),
                    last_seen_at: Utc::now(),
                    client_ip: "127.0.0.1".to_string(),
                    reported_ip: String::new(),
                    hop_token: String::new(),
                    stream: RelayStream::new(),
                    udp_runtime: None,
                    tcp_runtime: None,
                    udp_port: None,
                    tcp_port: None,
                },
            );

        let target = registry.lookup_stream("demo.localhost").unwrap();
        assert_eq!(
            target.identity_key,
            "demo:0x0000000000000000000000000000000000000001"
        );
        assert_eq!(
            target.policy.identity_status(&target.identity_key, "").bps,
            4096
        );
    }

    #[test]
    #[ignore]
    fn verifies_go_v218_issued_lease_token() {
        let token = std::env::var("GO_V218_TOKEN").expect("GO_V218_TOKEN is required");
        let relay = RelayIdentity {
            name: "localhost".to_string(),
            address: "0xrelay".to_string(),
            public_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .to_string(),
            private_key: "0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            admin_secret_key: "admin".to_string(),
            wireguard_public_key: String::new(),
            wireguard_private_key: String::new(),
        };
        let claims =
            verify_lease_access_token(&token, &relay, "https://localhost:4017", Utc::now())
                .expect("Go v2.1.8 token must verify in Rust");
        assert_eq!(
            claims.sub,
            "demo:0x000000000000000000000000000000000000dead"
        );
        assert_eq!(claims.identity.name, "demo");
        assert_eq!(
            claims.identity.address,
            "0x000000000000000000000000000000000000dEaD"
        );
    }

    #[test]
    fn one_level_wildcard_candidate_uses_only_leftmost_label() {
        assert_eq!(
            one_level_wildcard_hostname("app.example.com").as_deref(),
            Some("*.example.com")
        );
        assert_eq!(
            one_level_wildcard_hostname("deep.app.example.com").as_deref(),
            Some("*.app.example.com")
        );
        assert!(one_level_wildcard_hostname("example").is_none());
    }

    fn test_registry() -> LeaseRegistry {
        let signing_key = SigningKey::random(&mut OsRng);
        let relay = RelayIdentity {
            name: "localhost".to_string(),
            address: address_from_signing_key(&signing_key),
            public_key: compressed_public_key_hex(&signing_key),
            private_key: hex::encode(signing_key.to_bytes()),
            admin_secret_key: "admin".to_string(),
            wireguard_public_key: String::new(),
            wireguard_private_key: String::new(),
        };
        let policy_path = std::env::temp_dir().join(format!("portal-policy-{}", random_id("")));
        LeaseRegistry::new(LeaseRegistryConfig {
            root_host: "localhost".to_string(),
            relay,
            issuer: "https://localhost:4017".to_string(),
            sni_port: 443,
            udp_enabled: false,
            tcp_enabled: false,
            min_port: 0,
            max_port: 0,
            policy: Arc::new(PolicyRuntime::load(&policy_path, false, false).unwrap()),
            metrics: Arc::new(RelayMetrics::default()),
        })
    }

    fn test_overlay_descriptor(now: DateTime<Utc>) -> RelayDescriptor {
        RelayDescriptor {
            address: "0x0000000000000000000000000000000000000002".to_string(),
            version: DISCOVERY_VERSION.to_string(),
            issued_at: now,
            expires_at: now + chrono::Duration::minutes(5),
            api_https_addr: "https://forward.example".to_string(),
            wireguard_public_key: "L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q=".to_string(),
            wireguard_port: 51820,
            supports_overlay: true,
            supports_udp: false,
            supports_tcp: true,
            active_connections: 0,
            tcp_bps: 0.0,
            signature: String::new(),
        }
    }
}
