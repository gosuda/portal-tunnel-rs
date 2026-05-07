//! Peer-sync logic (Phase 6b/B U7).
//!
//! Translates a greenfield peer descriptor into [`PeerConfig`] entries,
//! applying the self-skip and overlay-IPv4 collision rules from the Go
//! reference (`overlay.go:202-222`).
//!
//! ## `RelayDescriptor` gap
//!
//! `portal_wire::RelayDescriptor` does not currently carry a `WireGuard`
//! public key (U7 land-time data contract).  The translation therefore
//! operates on a crate-local [`OverlayPeerDescriptor`] that supplies the
//! missing field.  When `portal-wire` is extended with a WG key field,
//! this module will be updated to consume the wire type directly.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::{
    error::OverlayError,
    overlay_ipv4::derive_overlay_ipv4,
    wg_device::{AllowedIp, PeerConfig},
};
use secrecy::ExposeSecret;

/// Local peer descriptor used while `portal-wire::RelayDescriptor` lacks
/// a `WireGuard` public-key field.
///
/// Phase 6b/B U7 — this type is a stop-gap.  It carries every field
/// `peer_sync` needs to build a [`PeerConfig`] plus the overlay-IPv4
/// derivation input.
#[derive(Debug)]
pub struct OverlayPeerDescriptor {
    /// X25519 static public key (32 bytes).
    pub wg_public_key: [u8; 32],

    /// Optional remote endpoint.
    pub endpoint: Option<SocketAddr>,

    /// Persistent-keepalive interval in seconds.
    pub persistent_keepalive_secs: Option<u16>,

    /// Optional pre-shared key.
    pub preshared_key: Option<secrecy::SecretBox<[u8; 32]>>,
}

/// Convert a slice of peer descriptors into validated [`PeerConfig`]
/// entries, applying the self-skip and collision rules.
///
/// # Rules
///
/// 1. **Self-skip** — any descriptor whose `wg_public_key` equals
///    `own_public_key` is dropped (matches Go `overlay.go:213-215`).
/// 2. **Collision detection** — two descriptors that derive to the same
///    overlay IPv4 address produce `Err(OverlayError::PeerConfig)`;
///    the previous peer set is left untouched.
///
/// # Errors
///
/// Returns [`OverlayError::PeerConfig`] on collision or on any
/// [`AllowedIp::new`] validation failure.
pub fn descriptors_to_peer_configs(
    descriptors: &[OverlayPeerDescriptor],
    own_public_key: &[u8; 32],
) -> Result<Vec<PeerConfig>, OverlayError> {
    let mut seen_overlay_ips = std::collections::HashSet::<Ipv4Addr>::new();
    let mut configs = Vec::with_capacity(descriptors.len());

    for desc in descriptors {
        // Rule 1: self-skip
        if desc.wg_public_key == *own_public_key {
            continue;
        }

        let overlay_ip = derive_overlay_ipv4(&desc.wg_public_key);

        // Rule 2: collision detection
        if !seen_overlay_ips.insert(overlay_ip) {
            return Err(OverlayError::PeerConfig(format!(
                "overlay IPv4 collision: {overlay_ip} derived from multiple peers"
            )));
        }

        let allowed_ip = AllowedIp::new(IpAddr::V4(overlay_ip), 32)?;
        let preshared_key = desc
            .preshared_key
            .as_ref()
            .map(|k| secrecy::SecretBox::new(Box::new(*k.expose_secret())));
        let config = PeerConfig {
            public_key: desc.wg_public_key,
            allowed_ips: vec![allowed_ip],
            endpoint: desc.endpoint,
            persistent_keepalive_secs: desc.persistent_keepalive_secs,
            preshared_key,
        };
        configs.push(config);
    }

    Ok(configs)
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test-only: deterministic inputs, panic on failure is the desired behavior"
)]
mod tests {
    use super::*;

    fn dummy_desc(pub_key: [u8; 32]) -> OverlayPeerDescriptor {
        OverlayPeerDescriptor {
            wg_public_key: pub_key,
            endpoint: None,
            persistent_keepalive_secs: None,
            preshared_key: None,
        }
    }

    /// Self-skip: descriptor matching own key is dropped.
    #[test]
    fn self_skip_drops_own_key() {
        let own = [1u8; 32];
        let configs = descriptors_to_peer_configs(&[dummy_desc([2u8; 32]), dummy_desc(own)], &own)
            .expect("valid descriptors");
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].public_key, [2u8; 32]);
    }

    /// Collision: two descriptors deriving to the same overlay IP are refused.
    #[test]
    fn collision_returns_error() {
        let own = [0u8; 32];
        // Two keys that happen to collide on overlay IP — using the same
        // key guarantees collision.
        let err =
            descriptors_to_peer_configs(&[dummy_desc([5u8; 32]), dummy_desc([5u8; 32])], &own)
                .expect_err("collision must be refused");
        assert!(matches!(err, OverlayError::PeerConfig(_)));
    }

    /// Empty input → empty output.
    #[test]
    fn empty_descriptors_empty_configs() {
        let own = [0u8; 32];
        let configs = descriptors_to_peer_configs(&[], &own).expect("empty is valid");
        assert!(configs.is_empty());
    }
}
