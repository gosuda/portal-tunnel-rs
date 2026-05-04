//! `IpFilter` — IP-keyed ban list.
//!
//! Lock-free `papaya::HashSet<IpAddr>` of banned IPs. Every lookup
//! canonicalizes the inbound address via [`crate::listeners::
//! canonicalize_source`] before consulting the table — the R12-canon
//! invariant is enforced at the call site, not in the caller.

use std::net::IpAddr;
use std::sync::Arc;

use papaya::HashMap;

use crate::listeners::canonicalize_source;

/// IP-keyed ban list. Cloning the filter is cheap (single `Arc` bump).
#[derive(Clone, Default)]
pub struct IpFilter {
    inner: Arc<HashMap<IpAddr, ()>>,
}

impl IpFilter {
    /// Construct an empty filter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `ip` to the ban list. Idempotent.
    pub fn ban(&self, ip: IpAddr) {
        let canon = canonicalize_ip(ip);
        self.inner.pin().insert(canon, ());
    }

    /// Remove `ip` from the ban list. Idempotent.
    pub fn unban(&self, ip: IpAddr) {
        let canon = canonicalize_ip(ip);
        self.inner.pin().remove(&canon);
    }

    /// Whether the supplied socket address is banned. Canonicalizes
    /// IPv4-mapped IPv6 to bare-IPv4 BEFORE lookup per R12-canon.
    #[must_use]
    pub fn is_ip_banned(&self, addr: std::net::SocketAddr) -> bool {
        let canonical = canonicalize_source(addr);
        self.inner.pin().contains_key(&canonical.ip())
    }

    /// Number of banned IPs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.pin().len()
    }

    /// Whether the ban list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.pin().is_empty()
    }
}

/// Wrapper around `portal_net::canonicalize_ip` so the IP-only branch
/// of the policy code uses the same helper as the socket-addr branch
/// without having to construct a fake port.
#[must_use]
const fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    portal_net::canonicalize_ip(ip)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only setup")]
mod tests {
    use super::*;

    #[test]
    fn ban_then_query_v4_returns_true() {
        let filter = IpFilter::new();
        filter.ban("1.2.3.4".parse().unwrap());
        let addr: std::net::SocketAddr = "1.2.3.4:9000".parse().unwrap();
        assert!(filter.is_ip_banned(addr));
    }

    #[test]
    fn ban_v4_then_query_v4_mapped_v6_canonicalizes_to_match() {
        let filter = IpFilter::new();
        filter.ban("1.2.3.4".parse().unwrap());
        // Inbound address arrives as v4-mapped v6 (::ffff:1.2.3.4)
        // because the dual-stack listener accepted it; the filter
        // MUST canonicalize and find the v4 ban.
        let addr: std::net::SocketAddr = "[::ffff:1.2.3.4]:9000".parse().unwrap();
        assert!(filter.is_ip_banned(addr), "v4-mapped v6 must hit v4 ban");
    }

    #[test]
    fn unbanned_ip_returns_false() {
        let filter = IpFilter::new();
        let addr: std::net::SocketAddr = "1.2.3.4:9000".parse().unwrap();
        assert!(!filter.is_ip_banned(addr));
    }

    #[test]
    fn unban_removes_entry() {
        let filter = IpFilter::new();
        let ip: IpAddr = "5.6.7.8".parse().unwrap();
        filter.ban(ip);
        assert_eq!(filter.len(), 1);
        filter.unban(ip);
        assert_eq!(filter.len(), 0);
    }

    #[test]
    fn ban_v4_mapped_canonicalizes_storage() {
        let filter = IpFilter::new();
        // Banning the v4-mapped form should canonicalize on insert
        // so a subsequent query of the bare-v4 form hits.
        filter.ban("::ffff:9.10.11.12".parse().unwrap());
        let addr: std::net::SocketAddr = "9.10.11.12:9000".parse().unwrap();
        assert!(filter.is_ip_banned(addr));
    }
}
