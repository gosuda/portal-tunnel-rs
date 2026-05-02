use chrono::{DateTime, TimeZone, Utc};
use k256::ecdsa::SigningKey;
use rand_core_06::OsRng;

use super::descriptor::DESCRIPTOR_TTL;
use super::*;
use crate::auth::identity::address_from_signing_key;
use crate::relay::bridge::RelayMetrics;
use crate::relay::overlay::OverlayDiscoveryInfo;
use crate::state::identity::RelayIdentity;

fn test_relay_identity(key: &SigningKey, name: &str) -> RelayIdentity {
    RelayIdentity {
        name: name.to_string(),
        address: address_from_signing_key(key),
        public_key: hex::encode(key.verifying_key().to_encoded_point(true)),
        private_key: hex::encode(key.to_bytes()),
        admin_secret_key: "admin".to_string(),
        wireguard_public_key: String::new(),
        wireguard_private_key: String::new(),
    }
}

fn signed_descriptor(key: &SigningKey, url: &str, issued_at: DateTime<Utc>) -> RelayDescriptor {
    sign_relay_descriptor(
        RelayDescriptor {
            address: address_from_signing_key(key),
            version: DISCOVERY_VERSION.to_string(),
            issued_at,
            expires_at: issued_at + DESCRIPTOR_TTL,
            api_https_addr: url.to_string(),
            wireguard_public_key: String::new(),
            wireguard_port: 0,
            supports_overlay: false,
            supports_udp: false,
            supports_tcp: true,
            active_connections: 0,
            tcp_bps: 0.0,
            signature: String::new(),
            family: String::new(),
            subnet16: String::new(),
            supports_reservation: false,
        },
        &hex::encode(key.to_bytes()),
    )
    .unwrap()
}

fn signed_overlay_descriptor(
    key: &SigningKey,
    url: &str,
    issued_at: DateTime<Utc>,
) -> RelayDescriptor {
    sign_relay_descriptor(
        RelayDescriptor {
            address: address_from_signing_key(key),
            version: DISCOVERY_VERSION.to_string(),
            issued_at,
            expires_at: issued_at + DESCRIPTOR_TTL,
            api_https_addr: url.to_string(),
            wireguard_public_key: "L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q=".to_string(),
            wireguard_port: 51820,
            supports_overlay: true,
            supports_udp: false,
            supports_tcp: true,
            active_connections: 0,
            tcp_bps: 0.0,
            signature: String::new(),
            family: String::new(),
            subnet16: String::new(),
            supports_reservation: false,
        },
        &hex::encode(key.to_bytes()),
    )
    .unwrap()
}

#[test]
fn canonical_descriptor_uses_go_field_order_and_unix_nano() {
    // Populate `family`, `subnet16`, and `supports_reservation` with non-default values to
    // prove that canonical_descriptor_bytes intentionally EXCLUDES them (Go parity: these
    // fields are unsigned wire metadata and must not affect the descriptor signature).
    let desc = RelayDescriptor {
        address: "0xabc".to_string(),
        version: "7".to_string(),
        issued_at: Utc.timestamp_opt(1, 2).unwrap(),
        expires_at: Utc.timestamp_opt(3, 4).unwrap(),
        api_https_addr: "https://relay.example".to_string(),
        wireguard_public_key: String::new(),
        wireguard_port: 0,
        supports_overlay: false,
        supports_udp: true,
        supports_tcp: false,
        active_connections: 0,
        tcp_bps: 0.0,
        signature: String::new(),
        family: "production-eu".to_string(),
        subnet16: "10.42.0.0/16".to_string(),
        supports_reservation: true,
    };

    let canonical = String::from_utf8(canonical_descriptor_bytes(&desc).unwrap()).unwrap();
    assert_eq!(
        canonical,
        "{\"address\":\"0xabc\",\"version\":\"7\",\"issued_at_unix_nano\":1000000002,\"expires_at_unix_nano\":3000000004,\"api_https_addr\":\"https://relay.example\",\"wireguard_public_key\":\"\",\"wireguard_port\":0,\"supports_overlay\":false,\"supports_udp\":true,\"supports_tcp\":false,\"active_connections\":0,\"tcp_bps\":0}"
    );
    assert!(
        !canonical.contains("family"),
        "family must not appear in canonical signing bytes: {canonical}"
    );
    assert!(
        !canonical.contains("subnet16"),
        "subnet16 must not appear in canonical signing bytes: {canonical}"
    );
    assert!(
        !canonical.contains("supports_reservation"),
        "supports_reservation must not appear in canonical signing bytes: {canonical}"
    );
}

#[test]
fn canonical_descriptor_formats_tcp_bps_like_go_json() {
    let mut desc = RelayDescriptor {
        address: "0xabc".to_string(),
        version: "7".to_string(),
        issued_at: Utc.timestamp_opt(1, 2).unwrap(),
        expires_at: Utc.timestamp_opt(3, 4).unwrap(),
        api_https_addr: "https://relay.example".to_string(),
        wireguard_public_key: String::new(),
        wireguard_port: 0,
        supports_overlay: false,
        supports_udp: false,
        supports_tcp: true,
        active_connections: 0,
        tcp_bps: 45_270.148_289_023_724,
        signature: String::new(),
        family: String::new(),
        subnet16: String::new(),
        supports_reservation: false,
    };

    let canonical = String::from_utf8(canonical_descriptor_bytes(&desc).unwrap()).unwrap();
    assert!(canonical.contains("\"tcp_bps\":45270.148289023724"));

    desc.tcp_bps = 1e-9;
    let canonical = String::from_utf8(canonical_descriptor_bytes(&desc).unwrap()).unwrap();
    assert!(canonical.contains("\"tcp_bps\":1e-9"));

    desc.tcp_bps = 1e21;
    let canonical = String::from_utf8(canonical_descriptor_bytes(&desc).unwrap()).unwrap();
    assert!(canonical.contains("\"tcp_bps\":1e+21"));
}

#[test]
fn signs_and_verifies_relay_descriptor() {
    let key = SigningKey::random(&mut OsRng);
    let address = address_from_signing_key(&key);
    let desc = RelayDescriptor {
        address: address.clone(),
        version: DISCOVERY_VERSION.to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + DESCRIPTOR_TTL,
        api_https_addr: "https://relay.example".to_string(),
        wireguard_public_key: String::new(),
        wireguard_port: 0,
        supports_overlay: false,
        supports_udp: false,
        supports_tcp: true,
        active_connections: 0,
        tcp_bps: 0.0,
        signature: String::new(),
        family: String::new(),
        subnet16: String::new(),
        supports_reservation: false,
    };
    let signed = sign_relay_descriptor(desc, &hex::encode(key.to_bytes())).unwrap();
    let verified = verify_relay_descriptor(signed).unwrap();
    assert_eq!(verified.address, address);
}

#[test]
fn self_descriptor_advertises_overlay_when_runtime_info_is_available() {
    let key = SigningKey::random(&mut OsRng);
    let now = Utc::now();
    let discovery = DiscoveryState::new_with_metrics_and_overlay(
        test_relay_identity(&key, "localhost"),
        "https://self.example".to_string(),
        Vec::new(),
        false,
        true,
        std::sync::Arc::new(RelayMetrics::default()),
        Some(OverlayDiscoveryInfo {
            public_key: "L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q=".to_string(),
            listen_port: 51821,
        }),
    );

    let desc = discovery.self_descriptor(now).unwrap();
    let verified = verify_relay_descriptor(desc).unwrap();

    assert!(verified.supports_overlay);
    assert_eq!(
        verified.wireguard_public_key,
        "L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q="
    );
    assert_eq!(verified.wireguard_port, 51821);
}

#[test]
fn discovery_response_applies_verified_descriptors() {
    let self_key = SigningKey::random(&mut OsRng);
    let peer_key = SigningKey::random(&mut OsRng);
    let now = Utc::now();
    let discovery = DiscoveryState::new(
        test_relay_identity(&self_key, "localhost"),
        "https://self.example".to_string(),
        vec!["https://bootstrap.example".to_string()],
        false,
        true,
    );
    let peer = signed_descriptor(&peer_key, "https://peer.example", now);

    let changed = discovery
        .apply_response(
            Some("https://peer.example"),
            DiscoveryResponse {
                protocol_version: DISCOVERY_VERSION.to_string(),
                generated_at: now,
                relays: vec![peer],
            },
            now,
        )
        .unwrap();

    assert!(changed);
    assert!(
        discovery
            .relays
            .lock()
            .expect("discovery relays lock poisoned")
            .contains_key("https://peer.example")
    );
    assert_eq!(
        discovery.poll_targets(now),
        vec![
            "https://bootstrap.example".to_string(),
            "https://peer.example".to_string(),
        ]
    );
}

#[test]
fn registry_bootstraps_merge_with_explicit_bootstraps() {
    let self_key = SigningKey::random(&mut OsRng);
    let discovery = DiscoveryState::new(
        test_relay_identity(&self_key, "localhost"),
        "https://self.example".to_string(),
        vec!["https://explicit.example".to_string()],
        false,
        true,
    );

    let changed = discovery
        .merge_bootstraps(&[
            "https://registry.example/path".to_string(),
            "https://explicit.example".to_string(),
            "https://self.example".to_string(),
        ])
        .unwrap();

    assert!(changed);
    assert_eq!(
        discovery.bootstrap_targets(),
        vec![
            "https://explicit.example".to_string(),
            "https://registry.example".to_string(),
        ]
    );
}

#[test]
fn overlay_peers_returns_fresh_overlay_descriptors() {
    let self_key = SigningKey::random(&mut OsRng);
    let overlay_key = SigningKey::random(&mut OsRng);
    let direct_key = SigningKey::random(&mut OsRng);
    let now = Utc::now();
    let discovery = DiscoveryState::new(
        test_relay_identity(&self_key, "localhost"),
        "https://self.example".to_string(),
        Vec::new(),
        false,
        true,
    );
    let overlay_peer = signed_overlay_descriptor(&overlay_key, "https://overlay.example", now);
    let direct_peer = signed_descriptor(&direct_key, "https://direct.example", now);

    discovery
        .apply_response(
            None,
            DiscoveryResponse {
                protocol_version: DISCOVERY_VERSION.to_string(),
                generated_at: now,
                relays: vec![direct_peer, overlay_peer.clone()],
            },
            now,
        )
        .unwrap();

    let peers = discovery.overlay_peers(now);

    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].api_https_addr, overlay_peer.api_https_addr);
    assert!(peers[0].has_overlay_peer());
}

#[test]
fn discovery_response_requires_authoritative_target_descriptor() {
    let self_key = SigningKey::random(&mut OsRng);
    let peer_key = SigningKey::random(&mut OsRng);
    let now = Utc::now();
    let discovery = DiscoveryState::new(
        test_relay_identity(&self_key, "localhost"),
        "https://self.example".to_string(),
        Vec::new(),
        false,
        true,
    );
    let peer = signed_descriptor(&peer_key, "https://other.example", now);

    let err = discovery
        .apply_response(
            Some("https://peer.example"),
            DiscoveryResponse {
                protocol_version: DISCOVERY_VERSION.to_string(),
                generated_at: now,
                relays: vec![peer],
            },
            now,
        )
        .unwrap_err();

    assert!(
        err.to_string()
            .contains("target relay descriptor missing from relays")
    );
}
