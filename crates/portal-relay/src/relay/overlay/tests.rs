use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{TimeZone, Utc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time;

use super::ipc::{
    relay_wireguard_endpoint, render_peer_ipc_config, render_resolved_peer_ipc_config,
    resolve_peer_endpoint,
};
use super::*;
use crate::relay::discovery::{DISCOVERY_VERSION, RelayDescriptor};
use crate::relay::hop_mux::{HopMux, HopMuxConnector};
use crate::state::identity::RelayIdentity;

#[test]
fn overlay_defaults_match_go_runtime() {
    assert_eq!(WIREGUARD_MTU, 1420);
    assert_eq!(DEFAULT_WIREGUARD_LISTEN_PORT, 51820);
    assert_eq!(DEFAULT_PEER_API_HTTP_PORT, 7777);
    assert_eq!(DEFAULT_PEER_YAMUX_PORT, 7778);
    assert_eq!(DEFAULT_PERSISTENT_KEEPALIVE_SECS, 25);
    assert_eq!(DEFAULT_ENDPOINT_RESOLVE_TTL, Duration::from_secs(3));
}

#[test]
fn overlay_config_derives_wireguard_identity_material() {
    let identity = RelayIdentity {
        name: "relay.example".to_string(),
        address: "0x0000000000000000000000000000000000000000".to_string(),
        public_key: String::new(),
        private_key: String::new(),
        admin_secret_key: "admin".to_string(),
        wireguard_public_key: "L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q=".to_string(),
        wireguard_private_key: "0100000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
    };

    let cfg = OverlayConfig::from_identity(&identity, 51820).unwrap();

    assert_eq!(
        cfg.private_key,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEA="
    );
    assert_eq!(
        cfg.private_key_hex,
        "0000000000000000000000000000000000000000000000000000000000000040"
    );
    assert_eq!(cfg.public_key, identity.wireguard_public_key);
    assert_eq!(cfg.overlay_ipv4.to_string(), "100.99.60.238");
    assert_eq!(
        cfg.base_ipc_config(),
        "private_key=0000000000000000000000000000000000000000000000000000000000000040\nlisten_port=51820\n"
    );
}

#[test]
fn overlay_peer_renders_wireguard_ipc_peer_config() {
    let desc = overlay_descriptor("https://relay.example:4017");

    let peer = OverlayPeer::from_descriptor(&desc).unwrap();

    assert_eq!(peer.relay_url, "https://relay.example:4017");
    assert_eq!(
        peer.public_key_hex,
        "2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74"
    );
    assert_eq!(peer.endpoint, "relay.example:51820");
    assert_eq!(peer.allowed_ip.to_string(), "100.99.60.238");
    assert_eq!(
        render_peer_ipc_config(&[peer]),
        concat!(
            "replace_peers=true\n",
            "public_key=2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74\n",
            "endpoint=relay.example:51820\n",
            "allowed_ip=100.99.60.238/32\n",
            "persistent_keepalive_interval=25\n",
        )
    );
}

#[test]
fn relay_wireguard_endpoint_formats_ipv6_hosts() {
    let desc = overlay_descriptor("https://[2001:db8::1]:4017");

    assert_eq!(
        relay_wireguard_endpoint(&desc).unwrap(),
        "[2001:db8::1]:51820"
    );
}

#[tokio::test]
async fn resolve_peer_endpoint_preserves_ip_endpoints() {
    assert_eq!(
        resolve_peer_endpoint("127.0.0.1:51820").await.unwrap(),
        "127.0.0.1:51820"
    );
    assert_eq!(
        resolve_peer_endpoint("[::1]:51820").await.unwrap(),
        "[::1]:51820"
    );
}

#[tokio::test]
async fn resolved_peer_ipc_config_uses_previous_endpoint_on_resolution_failure() {
    let mut peer =
        OverlayPeer::from_descriptor(&overlay_descriptor("https://relay.example")).unwrap();
    peer.endpoint = "bad endpoint".to_string();
    let mut previous = HashMap::new();
    previous.insert(
        peer.public_key_hex.clone(),
        "203.0.113.10:51820".to_string(),
    );

    let resolved = render_resolved_peer_ipc_config(&[peer], &previous).await;

    assert_eq!(
        resolved.endpoints.values().next().unwrap(),
        "203.0.113.10:51820"
    );
    assert!(resolved.warnings[0].contains("using current endpoint"));
    assert!(
        resolved
            .ipc_config
            .contains("endpoint=203.0.113.10:51820\n")
    );
}

#[tokio::test]
async fn overlay_peer_config_state_tracks_changes_and_cached_endpoints() {
    let mut peer =
        OverlayPeer::from_descriptor(&overlay_descriptor("https://relay.example")).unwrap();
    peer.endpoint = "203.0.113.10:51820".to_string();
    let public_key_hex = peer.public_key_hex.clone();
    let mut state = OverlayPeerConfigState::default();

    let first = state.build_update(&[peer.clone()]).await;
    let second = state.build_update(&[peer.clone()]).await;

    assert!(first.changed);
    assert!(!second.changed);
    assert_eq!(state.endpoint(&public_key_hex), Some("203.0.113.10:51820"));
    assert_eq!(state.current_ipc_config(), first.ipc_config);

    peer.endpoint = "bad endpoint".to_string();
    let fallback = state.build_update(&[peer]).await;

    assert!(!fallback.changed);
    assert_eq!(state.endpoint(&public_key_hex), Some("203.0.113.10:51820"));
    assert!(fallback.warnings[0].contains("using current endpoint"));
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN to bring up the kernel wg interface"]
async fn overlay_runtime_builds_wireguard_interface_metadata() {
    let identity = overlay_identity(
        "relay-a.example",
        "0100000000000000000000000000000000000000000000000000000000000000",
    );
    let cfg = OverlayConfig::from_identity(&identity, free_udp_port()).unwrap();
    let runtime = OverlayRuntime::new(cfg.clone()).await.unwrap();

    assert_eq!(runtime.overlay_ipv4(), cfg.overlay_ipv4);
    assert_eq!(
        runtime.discovery_info(),
        OverlayDiscoveryInfo {
            public_key: cfg.public_key,
            listen_port: cfg.listen_port,
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires CAP_NET_ADMIN and a running kernel WG module"]
async fn overlay_runtime_carries_hop_mux_streams() {
    let identity_a = overlay_identity(
        "relay-a.example",
        "0100000000000000000000000000000000000000000000000000000000000000",
    );
    let identity_b = overlay_identity(
        "relay-b.example",
        "0001000000000000000000000000000000000000000000000000000000000000",
    );
    let cfg_a = OverlayConfig::from_identity(&identity_a, free_udp_port()).unwrap();
    let cfg_b = OverlayConfig::from_identity(&identity_b, free_udp_port()).unwrap();
    let runtime_a = Arc::new(OverlayRuntime::new(cfg_a.clone()).await.unwrap());
    let runtime_b = Arc::new(OverlayRuntime::new(cfg_b.clone()).await.unwrap());
    let peer_a = OverlayPeer::from_descriptor(&overlay_descriptor_with_key(
        "https://127.0.0.1",
        &cfg_a.public_key,
        cfg_a.listen_port,
    ))
    .unwrap();
    let peer_b = OverlayPeer::from_descriptor(&overlay_descriptor_with_key(
        "https://127.0.0.1",
        &cfg_b.public_key,
        cfg_b.listen_port,
    ))
    .unwrap();

    let stats_a = runtime_a.sync_peers(&[peer_b]).await.unwrap();
    let stats_b = runtime_b.sync_peers(&[peer_a]).await.unwrap();

    assert_eq!(stats_a.added, 1);
    assert_eq!(stats_b.added, 1);

    let server = HopMux::new();
    let listener_task = Arc::clone(&runtime_b)
        .start_hop_mux_listener(Arc::clone(&server))
        .await
        .unwrap();
    let connector: Arc<dyn HopMuxConnector> = runtime_a;
    let client = HopMux::with_connector(connector);

    let mut client_stream = time::timeout(
        Duration::from_secs(5),
        client.open_stream(&cfg_b.overlay_ipv4.to_string(), "hpt_overlay"),
    )
    .await
    .unwrap()
    .unwrap();
    let mut hop_stream = time::timeout(Duration::from_secs(5), server.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(hop_stream.token, "hpt_overlay");

    client_stream.write_all(b"ping").await.unwrap();
    let mut inbound = [0u8; 4];
    hop_stream.stream.read_exact(&mut inbound).await.unwrap();
    assert_eq!(&inbound, b"ping");

    hop_stream.stream.write_all(b"pong").await.unwrap();
    let mut outbound = [0u8; 4];
    client_stream.read_exact(&mut outbound).await.unwrap();
    assert_eq!(&outbound, b"pong");

    listener_task.abort();
}

fn overlay_identity(name: &str, wireguard_private_key: &str) -> RelayIdentity {
    let mut identity = RelayIdentity {
        name: name.to_string(),
        address: "0x0000000000000000000000000000000000000000".to_string(),
        public_key: String::new(),
        private_key: String::new(),
        admin_secret_key: "admin".to_string(),
        wireguard_public_key: String::new(),
        wireguard_private_key: wireguard_private_key.to_string(),
    };
    let cfg = OverlayConfig::from_identity(&identity, 51820).unwrap();
    identity.wireguard_public_key = cfg.public_key;
    identity.wireguard_private_key = cfg.private_key;
    identity
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn overlay_descriptor(api_https_addr: &str) -> RelayDescriptor {
    overlay_descriptor_with_key(
        api_https_addr,
        "L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q=",
        51820,
    )
}

fn overlay_descriptor_with_key(
    api_https_addr: &str,
    wireguard_public_key: &str,
    wireguard_port: u16,
) -> RelayDescriptor {
    RelayDescriptor {
        address: "0x0000000000000000000000000000000000000000".to_string(),
        version: DISCOVERY_VERSION.to_string(),
        issued_at: Utc.timestamp_opt(1, 0).unwrap(),
        expires_at: Utc.timestamp_opt(300, 0).unwrap(),
        api_https_addr: api_https_addr.to_string(),
        wireguard_public_key: wireguard_public_key.to_string(),
        wireguard_port: wireguard_port.into(),
        supports_overlay: true,
        supports_udp: true,
        supports_tcp: true,
        active_connections: 0,
        tcp_bps: 0.0,
        signature: String::new(),
    }
}
