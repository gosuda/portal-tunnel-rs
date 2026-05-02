// PRE: cap_net_admin granted (Dockerfile setcap). INVARIANT: Drop tears down link before kernel netlink scope ends.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use defguard_wireguard_rs::{InterfaceConfiguration, WGApi, WireguardInterfaceApi};
use futures_util::TryStreamExt;
use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::relay::hop_mux::{HOP_MUX_PORT, HopMux};
use crate::state::identity::normalize_wireguard_private_key;

use super::{
    OVERLAY_INTERFACE_NAME, OverlayConfig, OverlayDiscoveryInfo, OverlayPeer, OverlayPeerSyncStats,
    OverlayRuntime, OverlayRuntimePeer, WIREGUARD_MTU, identity::wireguard_key,
    ipc::resolve_peer_endpoint, peers::wireguard_peer,
};

impl OverlayRuntime {
    pub async fn new(config: OverlayConfig) -> anyhow::Result<Self> {
        let _handle = tokio::runtime::Handle::try_current()
            .context("wireguard overlay requires a Tokio runtime")?;
        // Normalize and re-encode so the key passed to the kernel is always
        // clamped (even if config.private_key was stored pre-clamp).
        let private_key_bytes = normalize_wireguard_private_key(&config.private_key)
            .context("normalize overlay wireguard private key")?;
        let private_key_b64 = STANDARD.encode(private_key_bytes);
        let interface_name = OVERLAY_INTERFACE_NAME.to_string();

        // Configure kernel WireGuard. defguard_wireguard_rs creates the link via
        // netlink RTM_NEWLINK if it doesn't exist yet, then pushes the private key
        // + listen port via the WG generic netlink family.
        let mut api: WGApi = WGApi::new(interface_name.clone()).with_context(|| {
            format!("open wireguard netlink handle for {OVERLAY_INTERFACE_NAME}")
        })?;
        api.create_interface().with_context(|| {
            format!("create kernel wireguard interface {OVERLAY_INTERFACE_NAME}")
        })?;

        // Guard: if any step between create_interface and Ok(Self) fails, remove
        // the interface so subsequent restarts get a clean slate.
        let mut guard = CleanupGuard::new(interface_name.clone());

        api.configure_interface(&InterfaceConfiguration {
            name: interface_name.clone(),
            prvkey: private_key_b64,
            port: config.listen_port,
            addresses: vec![],
            peers: vec![],
            mtu: Some(WIREGUARD_MTU as u32),
            fwmark: None,
        })
        .with_context(|| {
            format!(
                "configure kernel wireguard interface {OVERLAY_INTERFACE_NAME} on udp port {}",
                config.listen_port
            )
        })?;

        // Bring the interface up and assign the overlay address using rtnetlink.
        configure_overlay_link_address(&interface_name, config.overlay_ipv4)
            .await
            .with_context(|| {
                format!(
                    "configure overlay address {} on {OVERLAY_INTERFACE_NAME}",
                    config.overlay_ipv4
                )
            })?;

        // Disarm the cleanup guard — all setup steps succeeded.
        guard.disarm();

        info!(
            overlay_ipv4 = %config.overlay_ipv4,
            wireguard_port = config.listen_port,
            wireguard_public_key = %config.public_key,
            wireguard_interface = OVERLAY_INTERFACE_NAME,
            mtu = WIREGUARD_MTU,
            "wireguard overlay runtime ready"
        );

        Ok(Self {
            config,
            interface_name,
            peers: tokio::sync::Mutex::new(HashMap::new()),
            closed: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub fn discovery_info(&self) -> OverlayDiscoveryInfo {
        OverlayDiscoveryInfo {
            public_key: self.config.public_key.clone(),
            listen_port: self.config.listen_port,
        }
    }

    pub fn overlay_ipv4(&self) -> std::net::Ipv4Addr {
        self.config.overlay_ipv4
    }

    pub async fn start_hop_mux_listener(
        self: Arc<Self>,
        hop_mux: Arc<HopMux>,
    ) -> anyhow::Result<JoinHandle<()>> {
        let addr = SocketAddr::new(IpAddr::V4(self.overlay_ipv4()), HOP_MUX_PORT);
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("listen overlay hop mux on {addr}"))?;
        info!(overlay_addr = %addr, "overlay hop mux listener ready");

        Ok(tokio::spawn(async move {
            self.serve_hop_mux(listener, hop_mux).await;
        }))
    }

    async fn serve_hop_mux(self: Arc<Self>, listener: TcpListener, hop_mux: Arc<HopMux>) {
        loop {
            match listener.accept().await {
                Ok((conn, remote_addr)) => {
                    // Hop_mux yamux pings/ACKs are tiny; disable Nagle so the kernel
                    // doesn't hold them. Buffering bigger frames is fine, the ones
                    // that matter for multi-hop liveness are sub-MSS.
                    if let Err(err) = conn.set_nodelay(true) {
                        warn!(remote_addr = %remote_addr, error = %err, "overlay hop mux tcp set_nodelay failed");
                    }
                    debug!(remote_addr = %remote_addr, "overlay hop mux tcp stream accepted");
                    let hop_mux = Arc::clone(&hop_mux);
                    tokio::spawn(async move {
                        hop_mux
                            .serve_connection(conn, remote_addr.to_string())
                            .await;
                    });
                }
                Err(err) if self.is_closed() => {
                    debug!(error = %err, "overlay hop mux listener closed");
                    return;
                }
                Err(err) => {
                    warn!(error = %err, "overlay hop mux accept failed");
                    return;
                }
            }
        }
    }

    pub(super) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    pub async fn sync_peers(&self, peers: &[OverlayPeer]) -> anyhow::Result<OverlayPeerSyncStats> {
        let (desired, warnings) = self.resolve_runtime_peers(peers).await;
        let mut stats = OverlayPeerSyncStats {
            warnings,
            ..OverlayPeerSyncStats::default()
        };
        let desired = desired
            .into_iter()
            .map(|peer| (peer.public_key.clone(), peer))
            .collect::<HashMap<_, _>>();
        let mut configured = self.peers.lock().await;

        let mut removed = Vec::new();
        let mut added = Vec::new();
        let mut updated = Vec::new();

        for (public_key, _) in configured.iter() {
            if desired.contains_key(public_key) {
                continue;
            }
            removed.push(public_key.clone());
        }

        let mut desired_peers = desired.into_values().collect::<Vec<_>>();
        desired_peers.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        for peer in &desired_peers {
            match configured.get(&peer.public_key) {
                Some(existing) if existing == peer => {
                    stats.unchanged += 1;
                }
                Some(_) => {
                    updated.push(peer.public_key.clone());
                }
                None => {
                    added.push(peer.public_key.clone());
                }
            }
        }

        if removed.is_empty() && added.is_empty() && updated.is_empty() {
            return Ok(stats);
        }

        // Apply peer removals — one netlink call per removed peer.
        for key_str in &removed {
            let key = wireguard_key(key_str)?;
            let api: WGApi = WGApi::new(self.interface_name.clone()).with_context(|| {
                format!("open wireguard netlink handle for {}", self.interface_name)
            })?;
            api.remove_peer(&key).with_context(|| {
                format!(
                    "remove wireguard peer {} on {}",
                    key_str, self.interface_name
                )
            })?;
        }

        // Apply peer additions and updates — one netlink call per peer.
        for peer in &desired_peers {
            if added.contains(&peer.public_key) || updated.contains(&peer.public_key) {
                let wg_peer = wireguard_peer(peer)?;
                let api: WGApi = WGApi::new(self.interface_name.clone()).with_context(|| {
                    format!("open wireguard netlink handle for {}", self.interface_name)
                })?;
                api.configure_peer(&wg_peer).with_context(|| {
                    format!(
                        "configure wireguard peer {} on {}",
                        peer.public_key, self.interface_name
                    )
                })?;
            }
        }

        for key in removed {
            configured.remove(&key);
            stats.removed += 1;
            info!(wireguard_public_key = %key, "overlay peer removed");
        }
        for peer in desired_peers {
            if added.contains(&peer.public_key) {
                info!(
                    wireguard_public_key = %peer.public_key,
                    endpoint = %peer.endpoint,
                    allowed_ip = %peer.allowed_ip,
                    "overlay peer added"
                );
                stats.added += 1;
                configured.insert(peer.public_key.clone(), peer);
            } else if updated.contains(&peer.public_key) {
                info!(
                    wireguard_public_key = %peer.public_key,
                    endpoint = %peer.endpoint,
                    allowed_ip = %peer.allowed_ip,
                    "overlay peer updated"
                );
                stats.updated += 1;
                configured.insert(peer.public_key.clone(), peer);
            }
        }

        Ok(stats)
    }

    async fn resolve_runtime_peers(
        &self,
        peers: &[OverlayPeer],
    ) -> (Vec<OverlayRuntimePeer>, Vec<String>) {
        let configured = self.peers.lock().await.clone();
        let mut resolved = Vec::new();
        let mut warnings = Vec::new();
        let mut peers = peers.to_vec();
        peers.sort_by(|a, b| a.public_key.cmp(&b.public_key));

        for peer in peers {
            if peer.public_key == self.config.public_key {
                continue;
            }
            let endpoint = match resolve_peer_endpoint(&peer.endpoint).await {
                Ok(endpoint) => endpoint,
                Err(err) => {
                    if let Some(existing) = configured.get(&peer.public_key) {
                        warnings.push(format!(
                            "resolve peer {} endpoint: {}; using current endpoint {}",
                            peer.public_key, err, existing.endpoint
                        ));
                        existing.endpoint.to_string()
                    } else {
                        warnings.push(format!(
                            "resolve peer {} endpoint: {}",
                            peer.public_key, err
                        ));
                        continue;
                    }
                }
            };
            match endpoint.parse::<SocketAddr>() {
                Ok(endpoint) => resolved.push(OverlayRuntimePeer {
                    public_key: peer.public_key,
                    endpoint,
                    allowed_ip: peer.allowed_ip,
                }),
                Err(err) => warnings.push(format!(
                    "parse peer {} endpoint {}: {}",
                    peer.public_key, endpoint, err
                )),
            }
        }

        (resolved, warnings)
    }
}

/// RAII guard that removes the `WireGuard` kernel interface on drop unless
/// `disarm()` has been called (i.e. construction succeeded).
struct CleanupGuard {
    interface_name: String,
    armed: bool,
}

impl CleanupGuard {
    fn new(interface_name: String) -> Self {
        Self {
            interface_name,
            armed: true,
        }
    }

    /// Disarm the guard so that drop becomes a no-op.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if self.armed {
            if let Ok(api) = WGApi::new(self.interface_name.clone()) {
                let api: WGApi = api;
                let _ = api.remove_interface();
            }
        }
    }
}

/// Bring the overlay `WireGuard` link up and assign the overlay address. Idempotent
/// across restarts: removes any pre-existing addresses on the interface and
/// re-adds the desired one so a stale state from a previous run cannot trap us.
async fn configure_overlay_link_address(
    interface_name: &str,
    overlay_ipv4: std::net::Ipv4Addr,
) -> anyhow::Result<()> {
    let (connection, handle, _) = rtnetlink::new_connection().context("open netlink connection")?;
    tokio::spawn(connection);

    let name = interface_name.to_string();
    let mut links = handle.link().get().match_name(name.clone()).execute();
    let link = links
        .try_next()
        .await
        .with_context(|| format!("look up wg link {name}"))?
        .with_context(|| format!("wg link {name} not present after wireguard interface create"))?;
    let link_index = link.header.index;

    // Strip any existing addresses (covers crash-restart scenarios where the
    // wg link survives but the IP is stale).
    let mut existing = handle
        .address()
        .get()
        .set_link_index_filter(link_index)
        .execute();
    while let Some(addr) = existing
        .try_next()
        .await
        .with_context(|| format!("enumerate existing addresses on {name}"))?
    {
        handle
            .address()
            .del(addr)
            .execute()
            .await
            .with_context(|| format!("remove stale address on {name}"))?;
    }

    // Assign with the full CGNAT prefix so the kernel auto-installs a route
    // for the entire overlay (100.64.0.0/10) via wg-portal. Without this route,
    // packets destined to peers' overlay IPs follow the default route on eth0
    // and never enter the WireGuard interface (we observed that as silent
    // unreachability for ping/TCP to other relays' overlay addresses).
    handle
        .address()
        .add(link_index, IpAddr::V4(overlay_ipv4), 10)
        .execute()
        .await
        .with_context(|| format!("add overlay address {overlay_ipv4}/10 on {name}"))?;

    let mut link_msg = LinkMessage::default();
    link_msg.header.index = link_index;
    link_msg.header.flags = LinkFlags::Up;
    link_msg.header.change_mask = LinkFlags::Up;
    link_msg.attributes.push(LinkAttribute::Mtu(WIREGUARD_MTU as u32));
    handle
        .link()
        .set(link_msg)
        .execute()
        .await
        .with_context(|| format!("set link up + mtu on {name}"))?;

    Ok(())
}
