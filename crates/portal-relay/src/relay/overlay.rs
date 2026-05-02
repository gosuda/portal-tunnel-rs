#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use futures_util::future::BoxFuture;
use futures_util::TryStreamExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time;
use tracing::{debug, info, warn};
use wireguard_control::{
    AllowedIp as WgAllowedIp, Backend as WgBackend, Device as WgDevice,
    DeviceUpdate as WgDeviceUpdate, InterfaceName as WgInterfaceName, Key as WgKey,
    PeerConfigBuilder,
};

use crate::relay::discovery::RelayDescriptor;
use crate::relay::hop_mux::{BoxedHopMuxIo, HopMux, HopMuxConnector, HOP_MUX_PORT};
use crate::state::identity::{
    derive_wireguard_overlay_ipv4, normalize_wireguard_private_key, validate_wireguard_public_key,
    wireguard_public_key_from_private_bytes, RelayIdentity,
};

pub const WIREGUARD_MTU: usize = 1420;
pub const DEFAULT_WIREGUARD_LISTEN_PORT: u16 = 51820;
pub const DEFAULT_PEER_API_HTTP_PORT: u16 = 7777;
pub const DEFAULT_PEER_YAMUX_PORT: u16 = 7778;
pub const DEFAULT_PERSISTENT_KEEPALIVE_SECS: u16 = 25;
pub const DEFAULT_ENDPOINT_RESOLVE_TTL: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayDiscoveryInfo {
    pub public_key: String,
    pub listen_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayConfig {
    pub private_key: String,
    pub private_key_hex: String,
    pub public_key: String,
    pub listen_port: u16,
    pub overlay_ipv4: Ipv4Addr,
}

impl OverlayConfig {
    pub fn from_identity(identity: &RelayIdentity, listen_port: u16) -> anyhow::Result<Self> {
        if listen_port == 0 {
            bail!("wireguard listen port is invalid");
        }
        let private = normalize_wireguard_private_key(&identity.wireguard_private_key)
            .context("normalize wireguard private key")?;
        let public_key = wireguard_public_key_from_private_bytes(private);
        if !identity.wireguard_public_key.trim().is_empty()
            && identity.wireguard_public_key.trim() != public_key
        {
            bail!("identity wireguard public key does not match private key");
        }
        let overlay_ipv4 = derive_wireguard_overlay_ipv4(&public_key)?;
        Ok(Self {
            private_key: STANDARD.encode(private),
            private_key_hex: hex::encode(private),
            public_key,
            listen_port,
            overlay_ipv4,
        })
    }

    pub fn base_ipc_config(&self) -> String {
        format!(
            "private_key={}\nlisten_port={}\n",
            self.private_key_hex, self.listen_port
        )
    }
}

/// Kernel-WireGuard backed overlay transport. Interface name (`wg-portal`) is
/// created via netlink at startup; all hop_mux traffic uses the kernel TCP
/// stack against the overlay address, which avoids the smoltcp/gvisor interop
/// failure observed when going through `tokio-wireguard`.
pub const OVERLAY_INTERFACE_NAME: &str = "wg-portal";

pub struct OverlayRuntime {
    config: OverlayConfig,
    interface_name: WgInterfaceName,
    peers: tokio::sync::Mutex<HashMap<String, OverlayRuntimePeer>>,
    closed: AtomicBool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OverlayRuntimePeer {
    public_key: String,
    endpoint: SocketAddr,
    allowed_ip: Ipv4Addr,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OverlayPeerSyncStats {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    pub unchanged: usize,
    pub warnings: Vec<String>,
}

impl OverlayPeerSyncStats {
    pub fn changed(&self) -> bool {
        self.added > 0 || self.updated > 0 || self.removed > 0
    }
}

impl OverlayRuntime {
    pub async fn new(config: OverlayConfig) -> anyhow::Result<Self> {
        let _handle = tokio::runtime::Handle::try_current()
            .context("wireguard overlay requires a Tokio runtime")?;
        let private_key = normalize_wireguard_private_key(&config.private_key)
            .context("normalize overlay wireguard private key")?;
        let interface_name = WgInterfaceName::from_str(OVERLAY_INTERFACE_NAME).map_err(|err| {
            anyhow::anyhow!("invalid wireguard interface name: {err}")
        })?;

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
            closed: AtomicBool::new(false),
        })
    }

    pub fn discovery_info(&self) -> OverlayDiscoveryInfo {
        OverlayDiscoveryInfo {
            public_key: self.config.public_key.clone(),
            listen_port: self.config.listen_port,
        }
    }

    pub fn overlay_ipv4(&self) -> Ipv4Addr {
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

    fn is_closed(&self) -> bool {
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

impl Drop for OverlayRuntime {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
        // Best effort: tear down the kernel WG interface so a subsequent process
        // start gets a clean slate. Ignore errors (the interface may already be
        // gone or the kernel may not have CAP_NET_ADMIN delegated, which is also
        // fine because the next startup re-applies state).
        if let Ok(device) = WgDevice::get(&self.interface_name, WgBackend::Kernel) {
            let _ = device.delete();
        }
    }
}

impl HopMuxConnector for OverlayRuntime {
    fn connect(&self, overlay_ipv4: &str) -> BoxFuture<'static, anyhow::Result<BoxedHopMuxIo>> {
        let overlay_ipv4 = overlay_ipv4.trim().to_string();
        Box::pin(async move {
            if overlay_ipv4.is_empty() {
                bail!("next hop overlay ipv4 is required");
            }
            let ip: IpAddr = overlay_ipv4
                .parse()
                .context("next hop overlay ipv4 must be an IP address")?;
            let addr = SocketAddr::new(ip, HOP_MUX_PORT);
            debug!(overlay_addr = %addr, "opening overlay hop mux tcp stream");
            let stream = TcpStream::connect(addr)
                .await
                .with_context(|| format!("connect overlay hop mux peer at {addr}"))?;
            if let Err(err) = stream.set_nodelay(true) {
                warn!(overlay_addr = %addr, error = %err, "overlay hop mux tcp set_nodelay failed");
            }
            debug!(overlay_addr = %addr, "overlay hop mux tcp stream connected");
            Ok(Box::new(stream) as BoxedHopMuxIo)
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayPeer {
    pub relay_url: String,
    pub public_key: String,
    pub public_key_hex: String,
    pub endpoint: String,
    pub allowed_ip: Ipv4Addr,
}

impl OverlayPeer {
    pub fn from_descriptor(desc: &RelayDescriptor) -> anyhow::Result<Self> {
        if !desc.has_overlay_peer() {
            bail!("relay wireguard overlay metadata is required");
        }
        validate_wireguard_public_key(&desc.wireguard_public_key)?;
        let public_key_hex = wireguard_key_hex(&desc.wireguard_public_key)
            .context("normalize peer wireguard public key")?;
        let endpoint = relay_wireguard_endpoint(desc)?;
        let allowed_ip = derive_wireguard_overlay_ipv4(&desc.wireguard_public_key)?;
        Ok(Self {
            relay_url: desc.api_https_addr.clone(),
            public_key: desc.wireguard_public_key.clone(),
            public_key_hex,
            endpoint,
            allowed_ip,
        })
    }
}

pub fn render_peer_ipc_config(peers: &[OverlayPeer]) -> String {
    let mut out = String::from("replace_peers=true\n");
    let mut peers = peers.to_vec();
    peers.sort_by(|a, b| a.public_key.cmp(&b.public_key));
    for peer in peers {
        out.push_str("public_key=");
        out.push_str(&peer.public_key_hex);
        out.push('\n');
        out.push_str("endpoint=");
        out.push_str(&peer.endpoint);
        out.push('\n');
        out.push_str("allowed_ip=");
        out.push_str(&peer.allowed_ip.to_string());
        out.push_str("/32\n");
        if DEFAULT_PERSISTENT_KEEPALIVE_SECS > 0 {
            out.push_str("persistent_keepalive_interval=");
            out.push_str(&DEFAULT_PERSISTENT_KEEPALIVE_SECS.to_string());
            out.push('\n');
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPeerIpcConfig {
    pub ipc_config: String,
    pub endpoints: HashMap<String, String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct OverlayPeerConfigState {
    peer_endpoints: HashMap<String, String>,
    peer_config: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayPeerConfigUpdate {
    pub ipc_config: String,
    pub changed: bool,
    pub warnings: Vec<String>,
}

impl OverlayPeerConfigState {
    pub async fn build_update(&mut self, peers: &[OverlayPeer]) -> OverlayPeerConfigUpdate {
        let resolved = render_resolved_peer_ipc_config(peers, &self.peer_endpoints).await;
        let changed = self.peer_config != resolved.ipc_config;
        if changed {
            self.peer_config = resolved.ipc_config.clone();
        }
        self.peer_endpoints = resolved.endpoints;
        OverlayPeerConfigUpdate {
            ipc_config: resolved.ipc_config,
            changed,
            warnings: resolved.warnings,
        }
    }

    pub fn current_ipc_config(&self) -> &str {
        &self.peer_config
    }

    pub fn endpoint(&self, public_key_hex: &str) -> Option<&str> {
        self.peer_endpoints
            .get(public_key_hex)
            .map(std::string::String::as_str)
    }
}

pub async fn render_resolved_peer_ipc_config(
    peers: &[OverlayPeer],
    previous_endpoints: &HashMap<String, String>,
) -> ResolvedPeerIpcConfig {
    let mut resolved_peers = Vec::new();
    let mut endpoints = HashMap::new();
    let mut warnings = Vec::new();
    let mut peers = peers.to_vec();
    peers.sort_by(|a, b| a.public_key.cmp(&b.public_key));

    for mut peer in peers {
        match resolve_peer_endpoint(&peer.endpoint).await {
            Ok(endpoint) => {
                endpoints.insert(peer.public_key_hex.clone(), endpoint.clone());
                peer.endpoint = endpoint;
                resolved_peers.push(peer);
            }
            Err(err) => {
                if let Some(endpoint) = previous_endpoints.get(&peer.public_key_hex) {
                    warnings.push(format!(
                        "resolve peer {} endpoint: {}; using current endpoint {}",
                        peer.public_key, err, endpoint
                    ));
                    peer.endpoint = endpoint.clone();
                    endpoints.insert(peer.public_key_hex.clone(), endpoint.clone());
                    resolved_peers.push(peer);
                } else {
                    warnings.push(format!(
                        "resolve peer {} endpoint: {}",
                        peer.public_key, err
                    ));
                }
            }
        }
    }

    ResolvedPeerIpcConfig {
        ipc_config: render_peer_ipc_config(&resolved_peers),
        endpoints,
        warnings,
    }
}

pub async fn resolve_peer_endpoint(raw: &str) -> anyhow::Result<String> {
    let (host, port) = split_host_port(raw)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(join_host_port(&ip.to_string(), port));
    }

    let mut addrs = time::timeout(
        DEFAULT_ENDPOINT_RESOLVE_TTL,
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    .with_context(|| format!("lookup {host:?} timed out"))?
    .with_context(|| format!("lookup {host:?}"))?;

    let mut selected = None;
    for addr in &mut addrs {
        if selected.is_none() {
            selected = Some(addr.ip());
        }
        if addr.ip().is_ipv4() {
            selected = Some(addr.ip());
            break;
        }
    }
    let selected = selected.with_context(|| format!("lookup {host:?}: no IP addresses found"))?;
    Ok(join_host_port(&selected.to_string(), port))
}

pub fn relay_wireguard_endpoint(desc: &RelayDescriptor) -> anyhow::Result<String> {
    let url = url::Url::parse(desc.api_https_addr.trim())
        .with_context(|| format!("parse relay url {:?}", desc.api_https_addr))?;
    let host = url
        .host_str()
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .context("api_https_addr host is required")?;
    if desc.wireguard_port <= 0 || desc.wireguard_port > 65_535 {
        bail!("wireguard_port is invalid");
    }
    Ok(join_host_port(host, desc.wireguard_port as u16))
}

fn wireguard_key_hex(raw: &str) -> anyhow::Result<String> {
    let decoded = STANDARD
        .decode(raw.trim())
        .context("wireguard key must be base64 encoded")?;
    if decoded.len() != 32 {
        bail!("wireguard key must be 32 bytes");
    }
    Ok(hex::encode(decoded))
}

fn wireguard_key(raw: &str) -> anyhow::Result<WgKey> {
    let decoded = STANDARD
        .decode(raw.trim())
        .context("wireguard key must be base64 encoded")?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("wireguard key must be 32 bytes"))?;
    Ok(WgKey(bytes))
}

fn wireguard_peer_builder(peer: &OverlayRuntimePeer) -> anyhow::Result<PeerConfigBuilder> {
    let public = wireguard_key(&peer.public_key)?;
    let allowed = WgAllowedIp {
        address: IpAddr::V4(peer.allowed_ip),
        cidr: 32,
    };
    Ok(PeerConfigBuilder::new(&public)
        .set_endpoint(peer.endpoint)
        .add_allowed_ip(allowed.address, allowed.cidr)
        .set_persistent_keepalive_interval(DEFAULT_PERSISTENT_KEEPALIVE_SECS))
}

/// Bring the overlay WireGuard link up and assign the overlay address. Idempotent
/// across restarts: removes any pre-existing addresses on the interface and
/// re-adds the desired one so a stale state from a previous run cannot trap us.
async fn configure_overlay_link_address(
    interface_name: &WgInterfaceName,
    overlay_ipv4: Ipv4Addr,
) -> anyhow::Result<()> {
    let (connection, handle, _) =
        rtnetlink::new_connection().context("open netlink connection")?;
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

fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn split_host_port(endpoint: &str) -> anyhow::Result<(String, u16)> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        bail!("wireguard endpoint is required");
    }

    let (host, port) = if let Some(rest) = endpoint.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .context("wireguard endpoint is missing closing bracket")?;
        let port = rest
            .strip_prefix(':')
            .context("wireguard endpoint port is required")?;
        (host, port)
    } else {
        let (host, port) = endpoint
            .rsplit_once(':')
            .context("wireguard endpoint port is required")?;
        if host.contains(':') {
            bail!("wireguard endpoint ipv6 host must be bracketed");
        }
        (host, port)
    };

    let host = host.trim();
    if host.is_empty() {
        bail!("wireguard endpoint host is required");
    }
    let port: u16 = port
        .parse()
        .context("wireguard endpoint port must be a valid port")?;
    if port == 0 {
        bail!("wireguard endpoint port is invalid");
    }
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use chrono::{TimeZone, Utc};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::relay::discovery::{RelayDescriptor, DISCOVERY_VERSION};

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
            wireguard_private_key:
                "0100000000000000000000000000000000000000000000000000000000000000".to_string(),
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
        assert!(resolved
            .ipc_config
            .contains("endpoint=203.0.113.10:51820\n"));
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
}
