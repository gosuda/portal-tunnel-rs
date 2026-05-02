// INVARIANT: a register call MUST consume the challenge nonce exactly once and MUST allocate exactly one TCP+UDP port pair via PortAllocator.

use std::sync::Arc;

use chrono::Utc;

use crate::auth::identity::{lease_hostname, normalize_identity};
use crate::auth::lease_token::issue_lease_access_token;
use crate::auth::siwe::{build_register_message, verify_personal_signature};
use crate::relay::stream::RelayStream;
use crate::relay::tcp_port::TcpPortRuntime;
use crate::relay::udp_datagram::UdpDatagramRuntime;

use super::util::{lease_ttl, random_id, random_nonce};
use super::{
    DEFAULT_REGISTER_CHALLENGE_TTL, LeaseError, LeaseRecord, LeaseRegistry, RegisterChallenge,
    RegisterChallengeRequest, RegisterChallengeResponse, RegisterRequest, RegisterResponse,
};

impl LeaseRegistry {
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

    pub(super) fn consume_verified_challenge(
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
}
