//! `PolicyRuntime` — aggregator over the workspace's policy sub-modules.
//!
//! Phase 5 B3 lands the minimum viable shape: `IpFilter` +
//! `ProxyTrust`. The Phase 5 plan's U6 unit additionally sketched
//! two surfaces that were narrowed-out at land time and remain
//! follow-up work:
//!
//! - `Approver` — identity approval (auto / manual / banned).
//! - `BpsManager` — bandwidth throttling (per-identity governor).
//!
//! The R10 reputation engine lives as a sibling module
//! ([`crate::policy::reputation`]) rather than an extension of this
//! aggregator; see this crate's `lib.rs` for current Phase 5 status.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::policy::ip_filter::IpFilter;
use crate::policy::proxy_trust::ProxyTrust;
use crate::reload::ReloadHandle;

/// Aggregator over the relay's policy surfaces. `Clone`-able so the
/// axum routers can each carry a handle.
///
/// Hot-reload integration: a `with_reload_handle`-attached
/// [`ReloadHandle`] makes the operator-managed ban list (per
/// [`crate::config::RuntimeConfig::ip_ban_list`]) consulted by
/// [`Self::is_ip_banned`] alongside the in-memory [`IpFilter`].
/// Construction without `with_reload_handle` leaves
/// [`Self::is_ip_banned`] reading only the in-memory filter — preserves
/// the iter-123 default-construction back-compat.
#[derive(Clone, Default)]
pub struct PolicyRuntime {
    /// IP-keyed in-memory ban list (dynamic; mutated via
    /// [`IpFilter::ban`] / [`IpFilter::unban`]).
    pub ip_filter: IpFilter,
    /// Trusted-proxy + client-IP extractor.
    pub proxy_trust: ProxyTrust,
    /// Optional handle to the workspace's hot-reload primitive. When
    /// present, [`Self::is_ip_banned`] also consults
    /// [`crate::config::RuntimeConfig::ip_ban_list`] from the most
    /// recent `ArcSwap` snapshot.
    reload: Option<Arc<ReloadHandle>>,
}

impl PolicyRuntime {
    /// Construct an empty policy runtime (no IPs banned, no proxies
    /// trusted, no reload handle).
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

    /// Attach a [`ReloadHandle`]. Once attached,
    /// [`Self::is_ip_banned`] reads
    /// [`crate::config::RuntimeConfig::ip_ban_list`] from the
    /// hot-reloaded snapshot in addition to the in-memory
    /// [`IpFilter`].
    #[must_use]
    pub fn with_reload_handle(mut self, handle: Arc<ReloadHandle>) -> Self {
        self.reload = Some(handle);
        self
    }

    /// Check whether `ip` is banned by any configured source.
    ///
    /// Reads in this order:
    /// 1. The in-memory [`IpFilter`] (dynamic bans set via
    ///    [`IpFilter::ban`]).
    /// 2. If a [`ReloadHandle`] is attached, the
    ///    [`crate::config::RuntimeConfig::ip_ban_list`] from the
    ///    most recent hot-reloaded snapshot (operator-managed
    ///    static bans).
    ///
    /// Hoare invariant: returns `true` if either source bans `ip`;
    /// returns `false` only when both sources agree `ip` is not
    /// banned (or when only the [`IpFilter`] source is configured
    /// and it does not ban `ip`).
    ///
    /// Cost: the in-memory [`IpFilter`] check is a hash lookup
    /// (canonicalisation plus `papaya::HashMap::contains_key`).
    /// The reload-side check loads an `ArcSwap` snapshot and does a
    /// `Vec::contains`, which is `O(N)` over the operator's ban
    /// list (typically small at v0.1 scale; future iteration may
    /// switch the storage to a `HashSet<IpAddr>` if `N` grows).
    #[must_use]
    pub fn is_ip_banned(&self, ip: IpAddr) -> bool {
        if self.ip_filter.is_ip_banned(SocketAddr::new(ip, 0)) {
            return true;
        }
        self.reload
            .as_ref()
            .is_some_and(|handle| handle.current().ip_ban_list.contains(&ip))
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only setup")]
mod tests {
    use std::path::PathBuf;

    use compact_str::CompactString;

    use super::*;
    use crate::config::{RelayServerConfig, RuntimeConfig};

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
        assert!(runtime.proxy_trust.is_trusted("10.0.0.1".parse().unwrap()));
    }

    fn sample_bootstrap() -> RelayServerConfig {
        RelayServerConfig::new(
            CompactString::from("relay-edge-01"),
            PathBuf::from("/var/lib/portal-relay"),
            PathBuf::from("/etc/portal-relay/api-https.key"),
            PathBuf::from("/etc/portal-relay/keyless.key"),
            PathBuf::from("/etc/portal-relay/quic-id.key"),
        )
    }

    fn sample_reload_handle(runtime: RuntimeConfig) -> Arc<ReloadHandle> {
        Arc::new(ReloadHandle::new(sample_bootstrap(), runtime))
    }

    #[test]
    fn is_ip_banned_no_reload_handle_consults_only_filter() {
        let filter = IpFilter::new();
        filter.ban("9.9.9.9".parse().unwrap());
        let runtime = PolicyRuntime::new().with_ip_filter(filter);

        assert!(runtime.is_ip_banned("9.9.9.9".parse().unwrap()));
        assert!(!runtime.is_ip_banned("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn is_ip_banned_reload_only_with_no_filter_bans() {
        let handle = sample_reload_handle(RuntimeConfig {
            bps_per_identity: 0,
            ip_ban_list: vec!["10.0.0.1".parse().unwrap()],
        });
        let runtime = PolicyRuntime::new().with_reload_handle(handle);

        assert!(runtime.is_ip_banned("10.0.0.1".parse().unwrap()));
        assert!(!runtime.is_ip_banned("9.9.9.9".parse().unwrap()));
    }

    #[test]
    fn is_ip_banned_filter_only_with_empty_reload_ban_list() {
        let filter = IpFilter::new();
        filter.ban("9.9.9.9".parse().unwrap());
        let handle = sample_reload_handle(RuntimeConfig::default());
        let runtime = PolicyRuntime::new()
            .with_ip_filter(filter)
            .with_reload_handle(handle);

        assert!(runtime.is_ip_banned("9.9.9.9".parse().unwrap()));
        assert!(!runtime.is_ip_banned("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn is_ip_banned_neither_source_returns_false() {
        let handle = sample_reload_handle(RuntimeConfig::default());
        let runtime = PolicyRuntime::new().with_reload_handle(handle);

        assert!(!runtime.is_ip_banned("9.9.9.9".parse().unwrap()));
        assert!(!runtime.is_ip_banned("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn is_ip_banned_either_source_returns_true() {
        let filter = IpFilter::new();
        filter.ban("9.9.9.9".parse().unwrap());
        let handle = sample_reload_handle(RuntimeConfig {
            bps_per_identity: 0,
            ip_ban_list: vec!["10.0.0.1".parse().unwrap()],
        });
        let runtime = PolicyRuntime::new()
            .with_ip_filter(filter)
            .with_reload_handle(handle);

        assert!(runtime.is_ip_banned("9.9.9.9".parse().unwrap()));
        assert!(runtime.is_ip_banned("10.0.0.1".parse().unwrap()));
    }
}
