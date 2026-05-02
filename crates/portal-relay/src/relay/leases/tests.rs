use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use k256::ecdsa::SigningKey;
use rand_core::OsRng;

use super::hop_routes::hop_route_record_key;
use super::port_allocator::PortAllocator;
use super::util::random_id;
use super::*;
use crate::auth::identity::{address_from_signing_key, compressed_public_key_hex};
use crate::auth::lease_token::{issue_lease_access_token, verify_lease_access_token};
use crate::relay::discovery::{DISCOVERY_VERSION, RelayDescriptor};
use crate::relay::hop::HopRoute;

#[test]
fn issues_and_verifies_lease_token() {
    let signing_key = SigningKey::random(&mut OsRng);
    let relay = RelayIdentity {
        name: "localhost".to_string(),
        address: address_from_signing_key(&signing_key),
        public_key: compressed_public_key_hex(&signing_key),
        private_key: hex::encode(signing_key.to_bytes()),
        admin_secret_key: "admin".to_string(),
        wireguard_public_key: String::new(),
        wireguard_private_key: String::new(),
    };
    let identity = Identity {
        name: "demo".to_string(),
        address: relay.address.clone(),
        public_key: String::new(),
        private_key: String::new(),
    };
    let now = Utc::now();
    let expires_at = now + chrono::Duration::seconds(30);
    let (token, claims) =
        issue_lease_access_token(&relay, "https://localhost:4017", &identity, expires_at, now)
            .unwrap();
    assert_eq!(
        claims.sub,
        "demo:".to_string() + &relay.address.to_ascii_lowercase()
    );

    let verified =
        verify_lease_access_token(&token, &relay, "https://localhost:4017", now).unwrap();
    assert_eq!(verified.identity.name, "demo");
}

#[test]
fn port_allocator_keeps_sticky_reservation() {
    let mut allocator = PortAllocator::new(5000, 5001, Duration::from_secs(5 * 60));
    let alice = allocator.allocate("alice").unwrap();
    assert_eq!(alice, 5000);
    allocator.release(alice);

    let bob = allocator.allocate("bob").unwrap();
    assert_eq!(bob, 5001);
    let alice_again = allocator.allocate("alice").unwrap();
    assert_eq!(alice_again, 5000);
}

#[test]
fn cleanup_expired_removes_registry_records() {
    let signing_key = SigningKey::random(&mut OsRng);
    let relay = RelayIdentity {
        name: "localhost".to_string(),
        address: address_from_signing_key(&signing_key),
        public_key: compressed_public_key_hex(&signing_key),
        private_key: hex::encode(signing_key.to_bytes()),
        admin_secret_key: "admin".to_string(),
        wireguard_public_key: String::new(),
        wireguard_private_key: String::new(),
    };
    let policy_path = std::env::temp_dir().join(format!("portal-policy-{}", random_id("")));
    let policy = Arc::new(PolicyRuntime::load(&policy_path, false, false).unwrap());
    let registry = LeaseRegistry::new(LeaseRegistryConfig {
        root_host: "localhost".to_string(),
        relay,
        issuer: "https://localhost:4017".to_string(),
        sni_port: 443,
        udp_enabled: false,
        tcp_enabled: false,
        min_port: 0,
        max_port: 0,
        policy,
        metrics: Arc::new(RelayMetrics::default()),
    });
    let now = Utc::now();
    let expired = now - chrono::Duration::seconds(1);
    let identity = Identity {
        name: "demo".to_string(),
        address: "0x0000000000000000000000000000000000000001".to_string(),
        public_key: String::new(),
        private_key: String::new(),
    };
    let hop_record = HopRouteRecord {
        identity: identity.clone(),
        hostname: "hop.localhost".to_string(),
        metadata: LeaseMetadata::default(),
        expires_at: expired,
        first_seen_at: expired,
        hop_token: String::new(),
        next_overlay_ipv4: "100.64.0.10".to_string(),
        next_token: "hpt_next".to_string(),
    };
    registry
        .inner
        .lock()
        .expect("lease registry lock poisoned")
        .challenges
        .insert(
            "rch_expired".to_string(),
            RegisterChallenge {
                expires_at: expired,
                request: RegisterChallengeRequest {
                    identity: identity.clone(),
                    metadata: LeaseMetadata::default(),
                    ttl: 0,
                    udp_enabled: false,
                    tcp_enabled: false,
                    hop_token: String::new(),
                },
                siwe_message: String::new(),
            },
        );
    registry
        .inner
        .lock()
        .expect("lease registry lock poisoned")
        .leases
        .insert(
            identity.key(),
            LeaseRecord {
                identity: identity.clone(),
                hostname: "demo.localhost".to_string(),
                metadata: LeaseMetadata::default(),
                expires_at: expired,
                first_seen_at: expired,
                last_seen_at: expired,
                client_ip: "127.0.0.1".to_string(),
                reported_ip: String::new(),
                hop_token: String::new(),
                stream: RelayStream::new(),
                udp_runtime: None,
                tcp_runtime: None,
                udp_port: None,
                tcp_port: None,
            },
        );
    registry
        .inner
        .lock()
        .expect("lease registry lock poisoned")
        .hop_routes
        .insert(hop_route_record_key(&hop_record), hop_record);

    assert_eq!(
        registry.cleanup_expired(now),
        CleanupStats {
            challenges: 1,
            leases: 1,
            hop_routes: 1,
        }
    );

    let inner = registry.inner.lock().expect("lease registry lock poisoned");
    assert!(inner.challenges.is_empty());
    assert!(inner.leases.is_empty());
    assert!(inner.hop_routes.is_empty());
}

#[test]
fn register_hop_route_rejects_active_direct_hostname_conflict() {
    let signing_key = SigningKey::random(&mut OsRng);
    let relay = RelayIdentity {
        name: "localhost".to_string(),
        address: address_from_signing_key(&signing_key),
        public_key: compressed_public_key_hex(&signing_key),
        private_key: hex::encode(signing_key.to_bytes()),
        admin_secret_key: "admin".to_string(),
        wireguard_public_key: String::new(),
        wireguard_private_key: String::new(),
    };
    let policy_path = std::env::temp_dir().join(format!("portal-policy-{}", random_id("")));
    let registry = LeaseRegistry::new(LeaseRegistryConfig {
        root_host: "localhost".to_string(),
        relay,
        issuer: "https://localhost:4017".to_string(),
        sni_port: 443,
        udp_enabled: false,
        tcp_enabled: false,
        min_port: 0,
        max_port: 0,
        policy: Arc::new(PolicyRuntime::load(&policy_path, false, false).unwrap()),
        metrics: Arc::new(RelayMetrics::default()),
    });
    let now = Utc::now();
    let identity = Identity {
        name: "demo".to_string(),
        address: "0x0000000000000000000000000000000000000001".to_string(),
        public_key: String::new(),
        private_key: String::new(),
    };
    registry
        .inner
        .lock()
        .expect("lease registry lock poisoned")
        .leases
        .insert(
            identity.key(),
            LeaseRecord {
                identity,
                hostname: "demo.localhost".to_string(),
                metadata: LeaseMetadata::default(),
                expires_at: now + chrono::Duration::seconds(30),
                first_seen_at: now,
                last_seen_at: now,
                client_ip: "127.0.0.1".to_string(),
                reported_ip: String::new(),
                hop_token: String::new(),
                stream: RelayStream::new(),
                udp_runtime: None,
                tcp_runtime: None,
                udp_port: None,
                tcp_port: None,
            },
        );

    let owner = SigningKey::random(&mut OsRng);
    let route = HopRoute {
        owner_public_key: hex::encode(owner.verifying_key().to_encoded_point(true)),
        relay_url: "https://localhost:4017".to_string(),
        match_hostname: "demo.localhost".to_string(),
        match_token: String::new(),
        metadata: LeaseMetadata::default(),
        forward_relay: test_overlay_descriptor(now),
        forward_token: "hpt_next".to_string(),
        first_seen_at: now,
        expires_at: now + chrono::Duration::seconds(30),
        signature: String::new(),
    };

    assert!(matches!(
        registry.register_hop_route(route, now),
        Err(LeaseError::HostnameConflict)
    ));
}

#[test]
fn lookup_next_hop_returns_active_hop_route_target() {
    let registry = test_registry();
    let now = Utc::now();
    let identity = Identity {
        name: "demo".to_string(),
        address: "0x0000000000000000000000000000000000000001".to_string(),
        public_key: String::new(),
        private_key: String::new(),
    };
    let active_record = HopRouteRecord {
        identity: identity.clone(),
        hostname: "demo.localhost".to_string(),
        metadata: LeaseMetadata::default(),
        expires_at: now + chrono::Duration::seconds(30),
        first_seen_at: now,
        hop_token: String::new(),
        next_overlay_ipv4: "100.64.0.10".to_string(),
        next_token: "hpt_next".to_string(),
    };
    let expired_record = HopRouteRecord {
        identity,
        hostname: "expired.localhost".to_string(),
        metadata: LeaseMetadata::default(),
        expires_at: now - chrono::Duration::seconds(1),
        first_seen_at: now,
        hop_token: String::new(),
        next_overlay_ipv4: "100.64.0.11".to_string(),
        next_token: "hpt_expired".to_string(),
    };
    let mut inner = registry.inner.lock().expect("lease registry lock poisoned");
    inner
        .hop_routes
        .insert(hop_route_record_key(&active_record), active_record);
    inner
        .hop_routes
        .insert(hop_route_record_key(&expired_record), expired_record);
    drop(inner);

    assert_eq!(
        registry.lookup_next_hop(" Demo.Localhost. "),
        Some(NextHopTarget {
            overlay_ipv4: "100.64.0.10".to_string(),
            token: "hpt_next".to_string(),
        })
    );
    assert_eq!(registry.lookup_next_hop("expired.localhost"), None);
}

#[test]
fn lookup_next_hop_matches_one_level_wildcard_route() {
    let registry = test_registry();
    let now = Utc::now();
    let wildcard_record = HopRouteRecord {
        identity: Identity {
            name: "*".to_string(),
            address: "0x0000000000000000000000000000000000000001".to_string(),
            public_key: String::new(),
            private_key: String::new(),
        },
        hostname: "*.localhost".to_string(),
        metadata: LeaseMetadata::default(),
        expires_at: now + chrono::Duration::seconds(30),
        first_seen_at: now,
        hop_token: String::new(),
        next_overlay_ipv4: "100.64.0.12".to_string(),
        next_token: "hpt_wildcard".to_string(),
    };
    registry
        .inner
        .lock()
        .expect("lease registry lock poisoned")
        .hop_routes
        .insert(hop_route_record_key(&wildcard_record), wildcard_record);

    assert_eq!(
        registry.lookup_next_hop("app.localhost"),
        Some(NextHopTarget {
            overlay_ipv4: "100.64.0.12".to_string(),
            token: "hpt_wildcard".to_string(),
        })
    );
    assert_eq!(registry.lookup_next_hop("deep.app.localhost"), None);
}

#[test]
fn lookup_hop_token_returns_direct_hop_lease() {
    let registry = test_registry();
    let now = Utc::now();
    let identity = Identity {
        name: "demo".to_string(),
        address: "0x0000000000000000000000000000000000000001".to_string(),
        public_key: String::new(),
        private_key: String::new(),
    };
    let identity_key = identity.key();
    registry
        .inner
        .lock()
        .expect("lease registry lock poisoned")
        .leases
        .insert(
            identity_key,
            LeaseRecord {
                identity,
                hostname: "demo.localhost".to_string(),
                metadata: LeaseMetadata::default(),
                expires_at: now + chrono::Duration::seconds(30),
                first_seen_at: now,
                last_seen_at: now,
                client_ip: "127.0.0.1".to_string(),
                reported_ip: String::new(),
                hop_token: "hpt_exit".to_string(),
                stream: RelayStream::new(),
                udp_runtime: None,
                tcp_runtime: None,
                udp_port: None,
                tcp_port: None,
            },
        );

    let Some(HopRelayTarget::Direct(target)) = registry.lookup_hop_token(" hpt_exit ") else {
        panic!("expected direct hop target");
    };
    assert_eq!(
        target.identity_key,
        "demo:0x0000000000000000000000000000000000000001"
    );
}

#[test]
fn lookup_hop_token_returns_middle_next_hop_route() {
    let registry = test_registry();
    let now = Utc::now();
    let route = HopRouteRecord {
        identity: Identity {
            name: String::new(),
            address: "0x0000000000000000000000000000000000000001".to_string(),
            public_key: String::new(),
            private_key: String::new(),
        },
        hostname: String::new(),
        metadata: LeaseMetadata::default(),
        expires_at: now + chrono::Duration::seconds(30),
        first_seen_at: now,
        hop_token: "hpt_middle".to_string(),
        next_overlay_ipv4: "100.64.0.20".to_string(),
        next_token: "hpt_next".to_string(),
    };
    registry
        .inner
        .lock()
        .expect("lease registry lock poisoned")
        .hop_routes
        .insert(hop_route_record_key(&route), route);

    assert!(matches!(
        registry.lookup_hop_token("hpt_middle"),
        Some(HopRelayTarget::NextHop(NextHopTarget {
            overlay_ipv4,
            token,
        })) if overlay_ipv4 == "100.64.0.20" && token == "hpt_next"
    ));
    assert!(registry.lookup_hop_token("").is_none());
}

#[test]
fn lookup_stream_returns_identity_bps_limit() {
    let signing_key = SigningKey::random(&mut OsRng);
    let relay = RelayIdentity {
        name: "localhost".to_string(),
        address: address_from_signing_key(&signing_key),
        public_key: compressed_public_key_hex(&signing_key),
        private_key: hex::encode(signing_key.to_bytes()),
        admin_secret_key: "admin".to_string(),
        wireguard_public_key: String::new(),
        wireguard_private_key: String::new(),
    };
    let policy_path = std::env::temp_dir().join(format!("portal-policy-{}", random_id("")));
    let policy = Arc::new(PolicyRuntime::load(&policy_path, false, false).unwrap());
    let registry = LeaseRegistry::new(LeaseRegistryConfig {
        root_host: "localhost".to_string(),
        relay,
        issuer: "https://localhost:4017".to_string(),
        sni_port: 443,
        udp_enabled: false,
        tcp_enabled: false,
        min_port: 0,
        max_port: 0,
        policy: Arc::clone(&policy),
        metrics: Arc::new(RelayMetrics::default()),
    });
    let identity = Identity {
        name: "demo".to_string(),
        address: "0x0000000000000000000000000000000000000001".to_string(),
        public_key: String::new(),
        private_key: String::new(),
    };
    let identity_key = identity.key();
    policy.set_identity_bps(&identity_key, 4096);
    registry
        .inner
        .lock()
        .expect("lease registry lock poisoned")
        .leases
        .insert(
            identity_key,
            LeaseRecord {
                identity,
                hostname: "demo.localhost".to_string(),
                metadata: LeaseMetadata::default(),
                expires_at: Utc::now() + chrono::Duration::seconds(30),
                first_seen_at: Utc::now(),
                last_seen_at: Utc::now(),
                client_ip: "127.0.0.1".to_string(),
                reported_ip: String::new(),
                hop_token: String::new(),
                stream: RelayStream::new(),
                udp_runtime: None,
                tcp_runtime: None,
                udp_port: None,
                tcp_port: None,
            },
        );

    let target = registry.lookup_stream("demo.localhost").unwrap();
    assert_eq!(
        target.identity_key,
        "demo:0x0000000000000000000000000000000000000001"
    );
    assert_eq!(
        target.policy.identity_status(&target.identity_key, "").bps,
        4096
    );
}

#[test]
#[ignore = "requires GO_V218_TOKEN env var set from a real v2.1.8 server run"]
fn verifies_go_v218_issued_lease_token() {
    let token = std::env::var("GO_V218_TOKEN").expect("GO_V218_TOKEN is required");
    let relay = RelayIdentity {
        name: "localhost".to_string(),
        address: "0xrelay".to_string(),
        public_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            .to_string(),
        private_key: "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
        admin_secret_key: "admin".to_string(),
        wireguard_public_key: String::new(),
        wireguard_private_key: String::new(),
    };
    let claims = verify_lease_access_token(&token, &relay, "https://localhost:4017", Utc::now())
        .expect("Go v2.1.8 token must verify in Rust");
    assert_eq!(
        claims.sub,
        "demo:0x000000000000000000000000000000000000dead"
    );
    assert_eq!(claims.identity.name, "demo");
    assert_eq!(
        claims.identity.address,
        "0x000000000000000000000000000000000000dEaD"
    );
}

#[test]
fn one_level_wildcard_candidate_uses_only_leftmost_label() {
    use super::hop_routes::one_level_wildcard_hostname;
    assert_eq!(
        one_level_wildcard_hostname("app.example.com").as_deref(),
        Some("*.example.com")
    );
    assert_eq!(
        one_level_wildcard_hostname("deep.app.example.com").as_deref(),
        Some("*.app.example.com")
    );
    assert!(one_level_wildcard_hostname("example").is_none());
}

fn test_registry() -> LeaseRegistry {
    let signing_key = SigningKey::random(&mut OsRng);
    let relay = RelayIdentity {
        name: "localhost".to_string(),
        address: address_from_signing_key(&signing_key),
        public_key: compressed_public_key_hex(&signing_key),
        private_key: hex::encode(signing_key.to_bytes()),
        admin_secret_key: "admin".to_string(),
        wireguard_public_key: String::new(),
        wireguard_private_key: String::new(),
    };
    let policy_path = std::env::temp_dir().join(format!("portal-policy-{}", random_id("")));
    LeaseRegistry::new(LeaseRegistryConfig {
        root_host: "localhost".to_string(),
        relay,
        issuer: "https://localhost:4017".to_string(),
        sni_port: 443,
        udp_enabled: false,
        tcp_enabled: false,
        min_port: 0,
        max_port: 0,
        policy: Arc::new(PolicyRuntime::load(&policy_path, false, false).unwrap()),
        metrics: Arc::new(RelayMetrics::default()),
    })
}

fn test_overlay_descriptor(now: DateTime<Utc>) -> RelayDescriptor {
    RelayDescriptor {
        address: "0x0000000000000000000000000000000000000002".to_string(),
        version: DISCOVERY_VERSION.to_string(),
        issued_at: now,
        expires_at: now + chrono::Duration::minutes(5),
        api_https_addr: "https://forward.example".to_string(),
        wireguard_public_key: "L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q=".to_string(),
        wireguard_port: 51820,
        supports_overlay: true,
        supports_udp: false,
        supports_tcp: true,
        active_connections: 0,
        tcp_bps: 0.0,
        signature: String::new(),
    }
}
