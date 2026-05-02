// PRE: cap_net_admin granted (Dockerfile setcap). INVARIANT: Drop tears down link before kernel netlink scope ends.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::Context;
use futures_util::TryStreamExt;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use wireguard_control::{
    Backend as WgBackend, DeviceUpdate as WgDeviceUpdate, InterfaceName as WgInterfaceName,
    Key as WgKey,
};

use crate::relay::hop_mux::{HOP_MUX_PORT, HopMux};
use crate::state::identity::normalize_wireguard_private_key;

use super::{
    OVERLAY_INTERFACE_NAME, OverlayConfig, OverlayDiscoveryInfo, OverlayPeer, OverlayPeerSyncStats,
    OverlayRuntime, OverlayRuntimePeer, WIREGUARD_MTU, identity::wireguard_key,
    ipc::resolve_peer_endpoint, peers::wireguard_peer_builder,
};

impl OverlayRuntime {
    pub async fn new(config: OverlayConfig) -> anyhow::Result<Self> {
        let _handle = tokio::runtime::Handle::try_current()
            .context("wireguard overlay requires a Tokio runtime")?;
        let private_key = normalize_wireguard_private_key(&config.private_key)
            .context("normalize overlay wireguard private key")?;
        let interface_name = WgInterfaceName::from_str(OVERLAY_INTERFACE_NAME)
            .map_err(|err| anyhow::anyhow!("invalid wireguard interface name: {err}"))?;

        // Configure kernel WireGuard. wireguard-control's apply() will create
        // the link via netlink RTM_NEWLINK if it doesn't exist yet, then push
        // the private key + listen port via the WG generic netlink family.
        WgDeviceUpdate::new()
            .set_private_key(WgKey(private_key))
            .set_listen_port(config.listen_port)
            .replace_peers()
            .apply(&interface_name, WgBackend::Kernel)
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

        let mut update = WgDeviceUpdate::new();
        let mut removed = Vec::new();
        let mut added = Vec::new();
        let mut updated = Vec::new();

        for (public_key, _) in configured.iter() {
            if desired.contains_key(public_key) {
                continue;
            }
            let key = wireguard_key(public_key)?;
            update = update.remove_peer_by_key(&key);
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
                    update = update.add_peer(wireguard_peer_builder(peer)?);
                    updated.push(peer.public_key.clone());
                }
                None => {
                    update = update.add_peer(wireguard_peer_builder(peer)?);
                    added.push(peer.public_key.clone());
                }
            }
        }

        if removed.is_empty() && added.is_empty() && updated.is_empty() {
            return Ok(stats);
        }

        // wireguard-control merges these into a single WG_CMD_SET_DEVICE call.
        update
            .apply(&self.interface_name, WgBackend::Kernel)
            .with_context(|| {
                format!(
                    "apply wireguard peer update on {}",
                    self.interface_name.as_str_lossy()
                )
            })?;

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

/// Bring the overlay `WireGuard` link up and assign the overlay address. Idempotent
/// across restarts: removes any pre-existing addresses on the interface and
/// re-adds the desired one so a stale state from a previous run cannot trap us.
async fn configure_overlay_link_address(
    interface_name: &WgInterfaceName,
    overlay_ipv4: std::net::Ipv4Addr,
) -> anyhow::Result<()> {
    let (connection, handle, _) = rtnetlink::new_connection().context("open netlink connection")?;
    tokio::spawn(connection);

    let name = interface_name.as_str_lossy().to_string();
    let mut links = handle.link().get().match_name(name.clone()).execute();
    let link = links
        .try_next()
        .await
        .with_context(|| format!("look up wg link {name}"))?
        .with_context(|| format!("wg link {name} not present after wireguard-control apply"))?;
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

    handle
        .link()
        .set(
            rtnetlink::LinkUnspec::new_with_index(link_index)
                .mtu(WIREGUARD_MTU as u32)
                .up()
                .build(),
        )
        .execute()
        .await
        .with_context(|| format!("set link up + mtu on {name}"))?;

    Ok(())
}
