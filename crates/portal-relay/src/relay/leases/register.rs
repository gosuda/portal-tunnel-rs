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

        // ── Lock 1: validation only, no I/O ─────────────────────────────────
        {
            let inner = self.inner.lock().expect("lease registry lock poisoned");
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
            if hop_token.is_empty() {
                for existing in inner.hop_routes.values() {
                    if existing.expires_at <= now || existing.hostname != hostname {
                        continue;
                    }
                    if existing.identity.key() != identity_key {
                        return Err(LeaseError::HostnameConflict);
                    }
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
        } // ── Lock 1 released ─────────────────────────────────────────────────

        // ── I/O outside the lock ─────────────────────────────────────────────
        // Runtimes are stored in Options so they can be moved into LeaseRecord
        // (via `.take()`) on the success path while remaining droppable on the
        // conflict rollback path — satisfying Rust's single-owner guarantee.
        let stream = RelayStream::new();
        let mut udp_port: Option<u16> = None;
        let mut udp_runtime: Option<Arc<UdpDatagramRuntime>> = if udp_requested {
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
            .map(|r| format!("{}:{}", self.root_host, r.port()))
            .unwrap_or_default();

        let mut tcp_port: Option<u16> = None;
        let mut tcp_runtime: Option<Arc<TcpPortRuntime>> = if tcp_requested {
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
                    // Drop udp_runtime before releasing the port so the socket closes first.
                    drop(udp_runtime.take());
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
            .map(|r| format!("{}:{}", self.root_host, r.port()))
            .unwrap_or_default();

        // ── Lock 2: TOCTOU recheck + commit (single lock scope) ─────────────
        //
        // All TOCTOU conflict checks, hop_routes collection, lease insertion, and
        // hop_route removal happen inside one `inner` lock acquisition so the
        // recheck and commit are atomic with respect to concurrent registrations.
        //
        // Pattern: accumulate conflict into a local during read-only loops (borrows
        // end at `break`), then after all loops end act on it — either return `Err`
        // or commit and return the displaced `LeaseRecord` from `HashMap::insert`.
        // The whole block evaluates to `Result<Option<LeaseRecord>, LeaseError>`.
        let lock2: Result<Option<LeaseRecord>, LeaseError> = {
            let mut inner = self.inner.lock().expect("lease registry lock poisoned");

            // Scan leases for TOCTOU hostname / hop_token conflicts.
            let mut conflict: Option<LeaseError> = None;
            for (existing_key, existing) in &inner.leases {
                if hop_token.is_empty()
                    && existing.hop_token.is_empty()
                    && existing.hostname == hostname
                    && existing_key != &identity_key
                    && existing.expires_at > now
                {
                    conflict = Some(LeaseError::HostnameConflict);
                    break;
                }
                if !hop_token.is_empty()
                    && existing.expires_at > now
                    && existing_key != &identity_key
                    && existing.hop_token == hop_token
                {
                    conflict = Some(LeaseError::InvalidRequest("hop token conflict".to_string()));
                    break;
                }
            }

            // Scan hop_routes for TOCTOU conflicts (only if no lease conflict yet).
            if conflict.is_none() {
                if hop_token.is_empty() {
                    for existing in inner.hop_routes.values() {
                        if existing.expires_at <= now || existing.hostname != hostname {
                            continue;
                        }
                        if existing.identity.key() != identity_key {
                            conflict = Some(LeaseError::HostnameConflict);
                            break;
                        }
                    }
                } else {
                    for existing in inner.hop_routes.values() {
                        if existing.expires_at > now && existing.hop_token == hop_token {
                            conflict =
                                Some(LeaseError::InvalidRequest("hop token conflict".to_string()));
                            break;
                        }
                    }
                }
            }

            // All iterator borrows have ended — safe to mutate `inner` now.
            if let Some(err) = conflict {
                Err(err)
            } else {
                // Collect displaced own hop_routes (recomputed under this lock).
                let mut replaced_hop_routes: Vec<String> = Vec::new();
                if hop_token.is_empty() {
                    for (key, existing) in &inner.hop_routes {
                        if existing.expires_at <= now || existing.hostname != hostname {
                            continue;
                        }
                        if existing.identity.key() == identity_key {
                            replaced_hop_routes.push(key.clone());
                        }
                    }
                }

                // Commit: move runtimes into the record via `.take()` so the
                // Options remain droppable in the rollback arm of the outer match.
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
                        udp_runtime: udp_runtime.take(),
                        tcp_runtime: tcp_runtime.take(),
                        udp_port,
                        tcp_port,
                    },
                );
                for key in replaced_hop_routes {
                    inner.hop_routes.remove(&key);
                }
                Ok(replaced)
            }
        }; // ── Lock 2 released ──────────────────────────────────────────────

        // On TOCTOU conflict: runtimes are still Some (`.take()` was not reached),
        // so drop them before releasing port numbers to close sockets first.
        let replaced = match lock2 {
            Ok(r) => r,
            Err(err) => {
                drop(udp_runtime);
                drop(tcp_runtime);
                if let Some(port) = udp_port {
                    self.udp_ports
                        .lock()
                        .expect("udp port allocator lock poisoned")
                        .release(port);
                }
                if let Some(port) = tcp_port {
                    self.tcp_ports
                        .lock()
                        .expect("tcp port allocator lock poisoned")
                        .release(port);
                }
                return Err(err);
            }
        };

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
