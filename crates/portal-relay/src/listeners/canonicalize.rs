//! R12 canonicalization helper.
//!
//! Wraps [`portal_net::dual_stack::canonicalize_socket`] under the
//! portal-relay path so policy modules can call
//! `crate::listeners::canonicalize_source(addr)` per the workspace
//! R12-canon contract: every IP-keyed surface MUST canonicalize
//! IPv4-mapped IPv6 (`::ffff:0:0/96`) BEFORE policy lookup.
//!
//! The single owner of the canonicalization logic is `portal-net`;
//! this re-export gives policy / api / discovery callers a shorter
//! local path while keeping the behavior single-sourced.

use std::net::SocketAddr;

/// Canonicalize a peer socket address: IPv4-mapped IPv6 (`::ffff:*`)
/// is unwrapped to its bare-IPv4 form; all other addresses are
/// returned unchanged.
///
/// MUST be called BEFORE any policy / ACL / governor lookup. The
/// CI ast-grep scan (Phase 5 U3 deliverable) enforces this on
/// `policy/`, `api/`, `discovery/` source files.
#[must_use]
pub const fn canonicalize_source(addr: SocketAddr) -> SocketAddr {
    portal_net::canonicalize_socket(addr)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only literal SocketAddr parses")]
mod tests {
    use super::*;

    #[test]
    fn v4_mapped_v6_unwraps_to_v4() {
        let mapped: SocketAddr = "[::ffff:1.2.3.4]:5000".parse().unwrap();
        let canon = canonicalize_source(mapped);
        assert!(canon.is_ipv4(), "v4-mapped v6 must canonicalize to v4");
        assert_eq!(canon.port(), 5000);
    }

    #[test]
    fn pure_v6_unchanged() {
        let v6: SocketAddr = "[2001:db8::1]:5000".parse().unwrap();
        assert_eq!(canonicalize_source(v6), v6);
    }

    #[test]
    fn pure_v4_unchanged() {
        let v4: SocketAddr = "1.2.3.4:5000".parse().unwrap();
        assert_eq!(canonicalize_source(v4), v4);
    }
}
