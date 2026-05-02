// INVARIANT: relay_wireguard_endpoint formats IPv6 hosts with brackets.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, bail};
use futures_util::future::BoxFuture;
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::relay::discovery::RelayDescriptor;
use crate::relay::hop_mux::{BoxedHopMuxIo, HOP_MUX_PORT, HopMuxConnector};

use super::{
    DEFAULT_ENDPOINT_RESOLVE_TTL, DEFAULT_PERSISTENT_KEEPALIVE_SECS, OverlayPeer, OverlayRuntime,
    ResolvedPeerIpcConfig,
};

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
    use tokio::time;
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

pub(super) fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub(super) fn split_host_port(endpoint: &str) -> anyhow::Result<(String, u16)> {
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
