//! `ProxyTrust` — extract the canonicalized client IP from a request,
//! honoring `X-Forwarded-For` / `X-Real-IP` only when the immediate
//! peer is a configured trusted proxy.
//!
//! The output is always passed through R12-canon.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::listeners::canonicalize_source;

/// Trusted-proxy CIDR list.
///
/// CIDRs are not parsed in v0.1 — instead, configure exact IP
/// addresses. The v0.1 reverse-proxy guidance is a single hop in
/// front, e.g., a load balancer with a known IP. Phase 5 B6+ extends
/// to CIDR ranges if operator demand surfaces.
#[derive(Clone, Default)]
pub struct ProxyTrust {
    /// Set of exactly-trusted upstream proxy IPs. If `remote_addr.ip()`
    /// is in this set, `extract_client_ip` consults the request's
    /// forwarding headers; otherwise it returns `remote_addr` unchanged.
    trusted: Arc<Vec<IpAddr>>,
}

impl ProxyTrust {
    /// Construct an empty trust list (no proxies trusted; every
    /// request returns its `remote_addr` after R12-canon).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a trust list from a vector of exact upstream IPs.
    #[must_use]
    pub fn from_trusted_ips(trusted: Vec<IpAddr>) -> Self {
        let canonical: Vec<IpAddr> = trusted.into_iter().map(portal_net::canonicalize_ip).collect();
        Self {
            trusted: Arc::new(canonical),
        }
    }

    /// Whether `ip` is a trusted upstream proxy.
    #[must_use]
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        let canon = portal_net::canonicalize_ip(ip);
        self.trusted.contains(&canon)
    }

    /// Extract the canonicalized client IP for the request.
    ///
    /// Contract (single-hop trusted-proxy semantics):
    ///
    /// 1. If `remote_addr` is NOT a trusted proxy, return
    ///    `canonicalize_source(remote_addr).ip()`. Forwarding
    ///    headers are ignored entirely — they are attacker-controlled
    ///    when the immediate peer is untrusted.
    /// 2. If `remote_addr` IS a trusted proxy, look at the **first
    ///    non-empty token** of `X-Forwarded-For` only:
    ///    - if it parses as an `IpAddr`, return it canonicalized;
    ///    - otherwise (malformed first hop) skip XFF entirely and
    ///      fall through to step 3. We deliberately do NOT scan
    ///      later XFF tokens: that would let a client prepend
    ///      garbage and have an attacker-chosen later token
    ///      accepted through the trusted proxy chain.
    /// 3. Fall back to `X-Real-IP` (canonicalized) if it parses.
    /// 4. Final fallback: the canonicalized `remote_addr`.
    ///
    /// Header values are passed in via `forwarded_for` / `real_ip`
    /// arguments rather than by inspecting an `http::HeaderMap` so
    /// this module stays decoupled from any specific HTTP framework.
    /// The eventual axum middleware extracts the headers and calls
    /// this function.
    #[must_use]
    pub fn extract_client_ip(
        &self,
        remote_addr: SocketAddr,
        forwarded_for: Option<&str>,
        real_ip: Option<&str>,
    ) -> IpAddr {
        let canonical_remote = canonicalize_source(remote_addr).ip();
        if !self.is_trusted(canonical_remote) {
            return canonical_remote;
        }
        // Step 2: first non-empty XFF token only. Malformed first
        // hop = drop XFF entirely; do NOT scan later tokens.
        if let Some(xff) = forwarded_for
            && let Some(first) = xff.split(',').map(str::trim).find(|s| !s.is_empty())
            && let Ok(parsed) = first.parse::<IpAddr>()
        {
            return portal_net::canonicalize_ip(parsed);
        }
        // Step 3: X-Real-IP fallback.
        if let Some(real) = real_ip
            && let Ok(parsed) = real.trim().parse::<IpAddr>()
        {
            return portal_net::canonicalize_ip(parsed);
        }
        // Step 4: remote_addr fallback.
        canonical_remote
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only setup")]
mod tests {
    use super::*;

    #[test]
    fn untrusted_remote_returns_canonical_remote() {
        let pt = ProxyTrust::new();
        let remote: SocketAddr = "5.6.7.8:9000".parse().unwrap();
        let got = pt.extract_client_ip(remote, Some("1.1.1.1"), None);
        assert_eq!(got, "5.6.7.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn trusted_remote_uses_xff_first_entry() {
        let pt = ProxyTrust::from_trusted_ips(vec!["10.0.0.1".parse().unwrap()]);
        let remote: SocketAddr = "10.0.0.1:9000".parse().unwrap();
        let got = pt.extract_client_ip(remote, Some("1.1.1.1, 10.0.0.1"), None);
        assert_eq!(got, "1.1.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn trusted_remote_falls_back_to_real_ip_when_xff_empty() {
        let pt = ProxyTrust::from_trusted_ips(vec!["10.0.0.1".parse().unwrap()]);
        let remote: SocketAddr = "10.0.0.1:9000".parse().unwrap();
        let got = pt.extract_client_ip(remote, None, Some("2.2.2.2"));
        assert_eq!(got, "2.2.2.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn trusted_remote_with_v4_mapped_v6_xff_canonicalizes() {
        let pt = ProxyTrust::from_trusted_ips(vec!["10.0.0.1".parse().unwrap()]);
        let remote: SocketAddr = "10.0.0.1:9000".parse().unwrap();
        let got = pt.extract_client_ip(remote, Some("::ffff:3.3.3.3"), None);
        assert_eq!(got, "3.3.3.3".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn trusted_remote_with_invalid_xff_falls_back_to_remote() {
        let pt = ProxyTrust::from_trusted_ips(vec!["10.0.0.1".parse().unwrap()]);
        let remote: SocketAddr = "10.0.0.1:9000".parse().unwrap();
        let got = pt.extract_client_ip(remote, Some("not-an-ip"), None);
        assert_eq!(got, "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn trusted_proxy_via_v4_mapped_v6_remote_is_recognized() {
        let pt = ProxyTrust::from_trusted_ips(vec!["10.0.0.1".parse().unwrap()]);
        // Remote arrives as v4-mapped v6 because the dual-stack
        // listener accepted it. ProxyTrust must canonicalize before
        // checking the trust list.
        let remote: SocketAddr = "[::ffff:10.0.0.1]:9000".parse().unwrap();
        let got = pt.extract_client_ip(remote, Some("4.4.4.4"), None);
        assert_eq!(got, "4.4.4.4".parse::<IpAddr>().unwrap());
    }
}
