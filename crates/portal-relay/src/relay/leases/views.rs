use chrono::{Duration as ChronoDuration, Utc};

use super::{AdminLeaseView, LeaseRegistry, LeaseView};

impl LeaseRegistry {
    pub async fn public_leases(&self) -> Vec<LeaseView> {
        let now = Utc::now();
        let (leases, routes) = {
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
                .collect::<Vec<_>>();
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
                .collect::<Vec<_>>();
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
        let records: Vec<(String, super::LeaseRecord)> = {
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
}
