// INVARIANT: build_update emits a config delta only when peer endpoints OR keys change — cached endpoint reused on resolution failure.

use std::net::IpAddr;

use anyhow::Context;
use defguard_wireguard_rs::net::IpAddrMask;
use defguard_wireguard_rs::peer::Peer;

use crate::relay::discovery::RelayDescriptor;
use crate::state::identity::{derive_wireguard_overlay_ipv4, validate_wireguard_public_key};

use super::{
    DEFAULT_PERSISTENT_KEEPALIVE_SECS, OverlayPeer, OverlayPeerConfigState,
    OverlayPeerConfigUpdate, OverlayPeerSyncStats, OverlayRuntimePeer,
    identity::{wireguard_key, wireguard_key_hex},
    ipc::{relay_wireguard_endpoint, render_resolved_peer_ipc_config},
};

impl OverlayPeer {
    pub fn from_descriptor(desc: &RelayDescriptor) -> anyhow::Result<Self> {
        if !desc.has_overlay_peer() {
            anyhow::bail!("relay wireguard overlay metadata is required");
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

impl OverlayPeerSyncStats {
    pub fn changed(&self) -> bool {
        self.added > 0 || self.updated > 0 || self.removed > 0
    }
}

impl OverlayPeerConfigState {
    pub async fn build_update(&mut self, peers: &[OverlayPeer]) -> OverlayPeerConfigUpdate {
        let resolved = render_resolved_peer_ipc_config(peers, &self.peer_endpoints).await;
        let changed = self.peer_config != resolved.ipc_config;
        if changed {
            self.peer_config.clone_from(&resolved.ipc_config);
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

pub(super) fn wireguard_peer(peer: &OverlayRuntimePeer) -> anyhow::Result<Peer> {
    let public = wireguard_key(&peer.public_key)?;
    let mut wg_peer = Peer::new(public);
    wg_peer.endpoint = Some(peer.endpoint);
    wg_peer.allowed_ips = vec![IpAddrMask {
        address: IpAddr::V4(peer.allowed_ip),
        cidr: 32,
    }];
    wg_peer.persistent_keepalive_interval = Some(DEFAULT_PERSISTENT_KEEPALIVE_SECS);
    Ok(wg_peer)
}
