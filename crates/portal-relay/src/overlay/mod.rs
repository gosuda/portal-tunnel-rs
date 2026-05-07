//! Overlay subsystem (Phase 6b/B) — sealed `WgDevice` trait + smoltcp
//! netstack + orchestrator.
//!
//! ## Phase 6b/B implementation status
//!
//! - **U5 (landed)** — ADR-0014 + ADR-0015 + workspace deps.
//! - **U6 (landed)** — sealed [`wg_device::WgDevice`] +
//!   [`wg_device::DefguardAdapter`] + [`wg_device::PeerConfig`] +
//!   [`error::OverlayError`].
//! - **U7 (landed)** — [`netstack::Netstack`] (smoltcp `Interface` +
//!   `SocketSet` + poll loop), [`peer_sync::descriptors_to_peer_configs`]
//!   (self-skip + collision detection), [`hop_mux::HopMuxSocket`]
//!   (smoltcp UDP socket wrapper), [`overlay_ipv4::derive_overlay_ipv4`],
//!   and [`Overlay`] orchestrator.
//!
//! ## Deferred to Phase 7 / follow-up
//!
//! - TCP listen/dial async surface on [`Netstack`].
//! - Quinn UDP integration inside [`hop_mux::HopMuxSocket`].
//! - Real `DefguardAdapter::read_packet` / `write_packet` via
//!   `noise::Tunn` encapsulation (currently
//!   [`OverlayError::NotYetImplemented`]).
//! - `portal-wire::RelayDescriptor` → [`PeerConfig`] direct translation
//!   (blocked on WG public-key field in `RelayDescriptor`).

pub mod error;
pub mod hop_mux;
pub mod netstack;
pub mod overlay_ipv4;
pub mod peer_sync;
pub mod wg_device;

pub use error::OverlayError;
pub use hop_mux::HopMuxSocket;
pub use netstack::Netstack;
pub use overlay_ipv4::derive_overlay_ipv4;
pub use peer_sync::{OverlayPeerDescriptor, descriptors_to_peer_configs};
#[cfg(test)]
pub use wg_device::PairedWgDevice;
pub use wg_device::{AllowedIp, DefguardAdapter, PeerConfig, WgDevice};

use std::sync::Arc;

use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
/// Minimal configuration for the overlay.
///
/// Phase 6b/B U7 — holds only the parameters needed to construct the
/// `WgDevice` and `Netstack`.  Expanded in follow-up batches.
#[derive(Debug)]
pub struct OverlayConfig {
    /// Static private key for the local `WireGuard` identity.
    pub static_private_key: secrecy::SecretBox<[u8; 32]>,
}

/// Overlay orchestrator that owns the `WgDevice`, `Netstack`, and the
/// smoltcp poll-loop task.
///
/// Phase 6b/B U7 — the orchestrator spawns the poll loop into the
/// caller-supplied [`JoinSet`] and listens on the [`CancellationToken`]
/// for clean shutdown.
pub struct Overlay {
    device: Arc<dyn WgDevice>,
    own_public_key: [u8; 32],
    netstack: Arc<std::sync::Mutex<Netstack>>,
}

impl Overlay {
    /// Construct a new overlay from the supplied configuration.
    ///
    /// # Errors
    ///
    /// Returns [`OverlayError::DeviceInit`] if the `WgDevice` cannot be
    /// constructed from the supplied private key.
    pub fn new(
        config: OverlayConfig,
        joinset: &mut JoinSet<()>,
        cancel: CancellationToken,
    ) -> Result<Self, OverlayError> {
        let adapter = DefguardAdapter::new(config.static_private_key)?;
        let own_public_key = adapter.static_public_bytes();
        let ipv4_addr = overlay_ipv4::derive_overlay_ipv4(&own_public_key);
        let device: Arc<dyn WgDevice> = Arc::new(adapter);
        let netstack = Netstack::new(Arc::clone(&device), ipv4_addr)?;
        let netstack_arc = Arc::new(std::sync::Mutex::new(netstack));

        // Spawn the smoltcp poll-loop task.
        let ns_clone = Arc::clone(&netstack_arc);
        joinset.spawn(async move {
            let start = std::time::Instant::now();
            loop {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    () = tokio::time::sleep(std::time::Duration::from_millis(10)) => {
                        let elapsed = start.elapsed();
                        let millis = i64::try_from(elapsed.as_millis())
                            .unwrap_or(i64::MAX);
                        let timestamp = smoltcp::time::Instant::from_millis(millis);
                        if let Ok(mut ns) = ns_clone.lock() {
                            ns.poll(timestamp);
                        }
                    }
                }
            }
        });

        Ok(Self {
            device,
            own_public_key,
            netstack: netstack_arc,
        })
    }

    /// Apply a new peer set to the underlying `WgDevice`.
    ///
    /// # Errors
    ///
    /// Returns [`OverlayError::PeerConfig`] if any descriptor fails
    /// validation or triggers a collision.
    pub fn apply_peers(&self, descriptors: &[OverlayPeerDescriptor]) -> Result<(), OverlayError> {
        let configs = peer_sync::descriptors_to_peer_configs(descriptors, &self.own_public_key)?;
        self.device.apply_peers(&configs)
    }

    /// Access the netstack (for tests and direct socket manipulation).
    #[must_use]
    pub const fn netstack(&self) -> &Arc<std::sync::Mutex<Netstack>> {
        &self.netstack
    }

    /// Access the underlying `WgDevice` (for diagnostics).
    #[must_use]
    pub fn device(&self) -> &Arc<dyn WgDevice> {
        &self.device
    }
}
