// PRE: caller holds &LeaseRegistry. POST: cleanup_expired releases every port whose lease.expires_at <= now.

use chrono::{DateTime, Utc};

use crate::auth::lease_token::issue_lease_access_token;

use super::util::lease_ttl;
use super::{
    CleanupStats, LeaseError, LeaseRecord, LeaseRegistry, RenewRequest, RenewResponse,
    UnregisterRequest,
};

impl LeaseRegistry {
    pub fn renew(&self, req: RenewRequest, client_ip: String) -> Result<RenewResponse, LeaseError> {
        if self.policy.is_ip_banned(&client_ip) {
            return Err(LeaseError::IpBanned);
        }
        let claims = self.verify_token(&req.access_token)?;
        let identity_key = claims.identity.key();
        let now = Utc::now();
        let expires_at = now + lease_ttl(req.ttl);

        // Single critical section: lookup + token issuance + state mutation + policy update.
        // Token issuance (ECDSA) is fast CPU-only work — holding the lock is safe.
        // If issuance fails the `?` exits before any mutations, leaving state pristine.
        // policy.register_identity_ip acquires only the policy-internal mutex; no lease-lock
        // re-entry possible, so lock ordering (LEASE → POLICY) is safe.
        let access_token = {
            let mut inner = self.inner.lock().expect("lease registry lock poisoned");
            let lease = inner
                .leases
                .get_mut(&identity_key)
                .ok_or(LeaseError::LeaseNotFound)?;
            let (access_token, _) = issue_lease_access_token(
                &self.relay,
                &self.issuer,
                &lease.identity,
                expires_at,
                now,
            )
            .map_err(|err| LeaseError::InvalidRequest(err.to_string()))?;
            lease.expires_at = expires_at;
            lease.last_seen_at = now;
            lease.client_ip.clone_from(&client_ip);
            lease.reported_ip = req.reported_ip;
            self.policy.register_identity_ip(&identity_key, &client_ip);
            access_token
        };

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

    pub(super) fn release_record_ports(&self, record: &LeaseRecord) {
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
