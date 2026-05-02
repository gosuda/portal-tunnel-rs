#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use wireguard_control::{
    Backend as WgBackend, Device as WgDevice, InterfaceName as WgInterfaceName,
};

pub mod identity;
pub mod ipc;
pub mod peers;
pub mod runtime;

#[cfg(test)]
mod tests;

pub const WIREGUARD_MTU: usize = 1420;
pub const DEFAULT_WIREGUARD_LISTEN_PORT: u16 = 51820;
pub const DEFAULT_PEER_API_HTTP_PORT: u16 = 7777;
pub const DEFAULT_PEER_YAMUX_PORT: u16 = 7778;
pub const DEFAULT_PERSISTENT_KEEPALIVE_SECS: u16 = 25;
pub const DEFAULT_ENDPOINT_RESOLVE_TTL: Duration = Duration::from_secs(3);

/// Kernel-WireGuard backed overlay transport. Interface name (`wg-portal`) is
/// created via netlink at startup; all `hop_mux` traffic uses the kernel TCP
/// stack against the overlay address, which avoids the smoltcp/gvisor interop
/// failure observed when going through `tokio-wireguard`.
pub const OVERLAY_INTERFACE_NAME: &str = "wg-portal";

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

pub struct OverlayRuntime {
    pub(super) config: OverlayConfig,
    pub(super) interface_name: WgInterfaceName,
    pub(super) peers: tokio::sync::Mutex<HashMap<String, OverlayRuntimePeer>>,
    pub(super) closed: AtomicBool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct OverlayRuntimePeer {
    pub(super) public_key: String,
    pub(super) endpoint: SocketAddr,
    pub(super) allowed_ip: Ipv4Addr,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OverlayPeerSyncStats {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    pub unchanged: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayPeer {
    pub relay_url: String,
    pub public_key: String,
    pub public_key_hex: String,
    pub endpoint: String,
    pub allowed_ip: Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPeerIpcConfig {
    pub ipc_config: String,
    pub endpoints: HashMap<String, String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct OverlayPeerConfigState {
    pub(super) peer_endpoints: HashMap<String, String>,
    pub(super) peer_config: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayPeerConfigUpdate {
    pub ipc_config: String,
    pub changed: bool,
    pub warnings: Vec<String>,
}

impl Drop for OverlayRuntime {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
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
