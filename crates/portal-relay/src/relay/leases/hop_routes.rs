// INVARIANT: hop-route key is canonical_lower(hostname); active direct hostnames may NOT collide with hop-routes.

use chrono::{DateTime, Utc};

use crate::auth::identity::Identity;
use crate::relay::hop::{HopRoute, owner_address_from_hop_route};
use crate::state::identity::derive_wireguard_overlay_ipv4;

use super::{HopRouteRecord, LeaseError, LeaseRegistry};

impl LeaseRegistry {
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
}

pub(super) fn hop_route_record_key(record: &HopRouteRecord) -> String {
    let owner = record.identity.address.to_ascii_lowercase();
    if !record.hostname.is_empty() {
        return format!("host:{}:{owner}", record.hostname);
    }
    format!("token:{}:{owner}", record.hop_token)
}

pub(super) fn one_level_wildcard_hostname(hostname: &str) -> Option<String> {
    let (first, rest) = hostname.split_once('.')?;
    if first.is_empty() || rest.is_empty() || rest.contains("..") {
        return None;
    }
    Some(format!("*.{rest}"))
}
