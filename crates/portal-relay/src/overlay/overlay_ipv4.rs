//! Overlay IPv4 address derivation (Phase 6b/B U7).
//!
//! Derives a stable IPv4 address from a `WireGuard` X25519 public key.
//! The v0.1 implementation maps the first three bytes of the public key
//! into the `100.64.0.0/10` CGNAT range (`100.64.0.0` – `100.127.255.255`).
//! This range is reserved by RFC 6598 and is the conventional choice for
//! `WireGuard` overlay networks.
//!
//! ## Go-reference fidelity
//!
//! The exact Go upstream algorithm (`utils.DeriveWireGuardOverlayIPv4`)
//! was not present in the pinned `portal-tunnel/` reference at U7 land
//! time.  The Rust implementation below produces a deterministic mapping.
//! A follow-up reconciliation pass will align the algorithm byte-for-byte
//! with the Go reference once the source function is located or documented.

use std::net::Ipv4Addr;

/// Derive an overlay IPv4 address from a 32-byte `WireGuard` public key.
///
/// The address is produced by mapping the first three key bytes into the
/// `100.64.0.0/10` range:
///
/// - `octet[0]` → `100`
/// - `octet[1]` → `64 + (public_key[0] & 0x3F)`  (gives `64..=127`)
/// - `octet[2]` → `public_key[1]`
/// - `octet[3]` → `public_key[2]`
///
/// Collision detection and rejection is handled upstream by
/// [`super::peer_sync::apply_peers`](crate::overlay::peer_sync).
#[must_use]
pub const fn derive_overlay_ipv4(public_key: &[u8; 32]) -> Ipv4Addr {
    Ipv4Addr::new(
        100,
        64 + (public_key[0] & 0x3F),
        public_key[1],
        public_key[2],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Derivation is deterministic: same key → same address.
    #[test]
    fn deterministic_from_public_key() {
        let key = [1u8; 32];
        let a = derive_overlay_ipv4(&key);
        let b = derive_overlay_ipv4(&key);
        assert_eq!(a, b);
    }

    /// Derived address lives inside 100.64.0.0/10.
    #[test]
    fn address_in_cgnat_range() {
        let key = [2u8; 32];
        let addr = derive_overlay_ipv4(&key);
        let octets = addr.octets();
        assert_eq!(octets[0], 100);
        assert!((64..=127).contains(&octets[1]));
    }

    /// Different keys produce different addresses (no trivial collision
    /// on the test vectors).
    #[test]
    fn distinct_keys_distinct_addresses() {
        let a = derive_overlay_ipv4(&[1u8; 32]);
        let b = derive_overlay_ipv4(&[2u8; 32]);
        assert_ne!(a, b);
    }
}
