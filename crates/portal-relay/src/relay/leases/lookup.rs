// INVARIANT: one-level-wildcard candidate uses ONLY the leftmost label (Go parity, see tests).

use std::sync::Arc;

use chrono::Utc;

use super::hop_routes::one_level_wildcard_hostname;
use super::{BridgeTarget, HopRelayTarget, LeaseRegistry, NextHopTarget};

impl LeaseRegistry {
    pub fn thumbnail_eligible(&self, hostname: &str) -> bool {
        let hostname = crate::auth::identity::normalize_hostname(hostname);
        if hostname.is_empty() {
            return false;
        }
        let wildcard = one_level_wildcard_hostname(&hostname);
        let now = Utc::now();
        let inner = self.inner.lock().expect("lease registry lock poisoned");
        inner.leases.values().any(|lease| {
            lease.hop_token.is_empty()
                && !lease.hostname.is_empty()
                && (lease.hostname == hostname
                    || wildcard.as_deref() == Some(lease.hostname.as_str()))
                && lease.expires_at > now
                && !lease.metadata.hide
                && lease.metadata.thumbnail.trim().is_empty()
                && self
                    .policy
                    .is_identity_routable(&lease.identity.key(), &lease.client_ip)
        })
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
}
