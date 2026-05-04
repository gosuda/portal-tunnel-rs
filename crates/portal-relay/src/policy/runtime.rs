//! `PolicyRuntime` — aggregator over the workspace's policy sub-modules.
//!
//! Phase 5 B5 lands the minimum viable shape: `IpFilter` +
//! `ProxyTrust`. Subsequent batches extend with:
//!
//! - `Approver` — identity approval (auto / manual / banned).
//! - `BpsManager` — bandwidth throttling (per-identity governor).
//! - R10 reputation engine (Phase 5 B7).

use crate::policy::ip_filter::IpFilter;
use crate::policy::proxy_trust::ProxyTrust;

/// Aggregator over the relay's policy surfaces. `Clone`-able so the
/// axum routers can each carry a handle.
#[derive(Clone, Default)]
pub struct PolicyRuntime {
    /// IP-keyed ban list.
    pub ip_filter: IpFilter,
    /// Trusted-proxy + client-IP extractor.
    pub proxy_trust: ProxyTrust,
}

impl PolicyRuntime {
    /// Construct an empty policy runtime (no IPs banned, no proxies
    /// trusted).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct with a pre-populated IP filter.
    #[must_use]
    pub fn with_ip_filter(mut self, filter: IpFilter) -> Self {
        self.ip_filter = filter;
        self
    }

    /// Construct with a pre-populated trusted-proxy list.
    #[must_use]
    pub fn with_proxy_trust(mut self, trust: ProxyTrust) -> Self {
        self.proxy_trust = trust;
        self
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only setup")]
mod tests {
    use super::*;

    #[test]
    fn default_runtime_has_empty_filter_and_no_trusted_proxies() {
        let runtime = PolicyRuntime::new();
        assert!(runtime.ip_filter.is_empty());
        // ProxyTrust::is_trusted on an arbitrary IP must be false.
        assert!(
            !runtime
                .proxy_trust
                .is_trusted(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        );
    }

    #[test]
    fn builder_attaches_filter_and_trust() {
        let filter = IpFilter::new();
        filter.ban("9.9.9.9".parse().unwrap());
        let trust = ProxyTrust::from_trusted_ips(vec!["10.0.0.1".parse().unwrap()]);
        let runtime = PolicyRuntime::new()
            .with_ip_filter(filter)
            .with_proxy_trust(trust);
        assert_eq!(runtime.ip_filter.len(), 1);
        assert!(
            runtime
                .proxy_trust
                .is_trusted("10.0.0.1".parse().unwrap())
        );
    }
}
