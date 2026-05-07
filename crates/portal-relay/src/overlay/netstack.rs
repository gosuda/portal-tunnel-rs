//! smoltcp-backed in-process TCP/IP+UDP stack (Phase 6b/B U7).
//!
//! `Netstack` owns a [`smoltcp::iface::Interface`], a [`smoltcp::iface::SocketSet`],
//! and a [`smoltcp::phy::Device`] implementation that bridges to the sealed [`WgDevice`] trait.
//!
//! ## Deferred to Phase 7 / follow-up
//!
//! - TCP `listen` / `dial` async surface.
//! - Quinn UDP integration inside [`hop_mux`](super::hop_mux).
//! - IPv6-first data-path coverage beyond interface-address configuration.

use std::sync::Arc;

use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, PollResult, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::udp::{
        PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata, Socket as UdpSocket,
    },
    time::Instant as SmolInstant,
    wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address},
};
use tracing;

use super::{error::OverlayError, wg_device::WgDevice};

/// A [`smoltcp::phy::Device`] implementation that forwards cleartext IP
/// packets to / from a [`WgDevice`].
pub struct WgSmolDevice {
    wg: Arc<dyn WgDevice>,
}

impl WgSmolDevice {
    /// Wrap the supplied `WgDevice` for consumption by smoltcp.
    pub fn new(wg: Arc<dyn WgDevice>) -> Self {
        Self { wg }
    }
}

/// Receive token produced by [`WgSmolDevice`].
pub struct WgRxToken {
    buf: Vec<u8>,
}

impl RxToken for WgRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buf)
    }
}

/// Transmit token produced by [`WgSmolDevice`].
pub struct WgTxToken {
    wg: Arc<dyn WgDevice>,
}

impl TxToken for WgTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        if let Err(e) = self.wg.write_packet(&buf) {
            tracing::debug!(error = %e, "wg write_packet failed");
        }
        result
    }
}

impl Device for WgSmolDevice {
    type RxToken<'a> = WgRxToken;
    type TxToken<'a> = WgTxToken;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut buf = vec![0u8; 2048];
        let n = match self.wg.read_packet(&mut buf) {
            Ok(0) | Err(OverlayError::NotYetImplemented(_)) => return None,
            Ok(n) => n,
            Err(e) => {
                tracing::debug!(error = %e, "wg read_packet failed");
                return None;
            }
        };
        buf.truncate(n);
        Some((
            WgRxToken { buf },
            WgTxToken {
                wg: self.wg.clone(),
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(WgTxToken {
            wg: self.wg.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }
}

/// Opaque handle to a UDP socket inside a [`Netstack`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpHandle {
    smol_handle: smoltcp::iface::SocketHandle,
}

/// In-process network stack backed by smoltcp.
pub struct Netstack {
    device: WgSmolDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
}

impl Netstack {
    /// Construct a new netstack over the supplied `WgDevice`.
    ///
    /// The `ipv4_addr` is assigned to the interface as a `/32` so the
    /// stack knows which packets are locally destined.
    ///
    /// # Errors
    ///
    /// Returns [`OverlayError::PeerConfig`] if the interface address
    /// cannot be inserted.
    pub fn new(wg: Arc<dyn WgDevice>, ipv4_addr: Ipv4Address) -> Result<Self, OverlayError> {
        let mut device = WgSmolDevice::new(wg);
        let config = InterfaceConfig::new(HardwareAddress::Ip);
        let now = SmolInstant::from_millis(0);
        let mut interface = Interface::new(config, &mut device, now);
        let sockets = SocketSet::new(vec![]);

        let mut push_result = Ok(());
        interface.update_ip_addrs(|addrs| {
            push_result = addrs
                .push(IpCidr::new(IpAddress::Ipv4(ipv4_addr), 32))
                .map_err(|e| {
                    OverlayError::PeerConfig(format!("interface address insert failed: {e:?}"))
                });
        });
        push_result?;

        Ok(Self {
            device,
            interface,
            sockets,
        })
    }

    /// Drive the stack forward.  Returns `true` if any state changed.
    pub fn poll(&mut self, timestamp: SmolInstant) -> bool {
        matches!(
            self.interface
                .poll(timestamp, &mut self.device, &mut self.sockets),
            PollResult::SocketStateChanged
        )
    }

    /// Add a UDP socket to the stack and return a handle.
    ///
    /// # Errors
    ///
    /// Currently returns `Ok` for all inputs; `Result` is retained for
    /// API compatibility with the rest of the overlay surface.
    pub fn create_udp_socket(&mut self) -> Result<UdpHandle, OverlayError> {
        const PACKET_COUNT: usize = 4;
        const PACKET_SIZE: usize = 1500;
        let rx_buffer = UdpPacketBuffer::new(
            vec![UdpPacketMetadata::EMPTY; PACKET_COUNT],
            vec![0u8; PACKET_COUNT * PACKET_SIZE],
        );
        let tx_buffer = UdpPacketBuffer::new(
            vec![UdpPacketMetadata::EMPTY; PACKET_COUNT],
            vec![0u8; PACKET_COUNT * PACKET_SIZE],
        );
        let socket = UdpSocket::new(rx_buffer, tx_buffer);
        let smol_handle = self.sockets.add(socket);
        Ok(UdpHandle { smol_handle })
    }

    /// Bind the UDP socket to a local port.
    ///
    /// # Errors
    ///
    /// Returns [`OverlayError::PeerConfig`] if smoltcp refuses the bind
    /// (e.g. port already in use).
    pub fn udp_bind(&mut self, handle: UdpHandle, port: u16) -> Result<(), OverlayError> {
        let socket = self.sockets.get_mut::<UdpSocket>(handle.into());
        socket
            .bind(port)
            .map_err(|e| OverlayError::PeerConfig(format!("udp bind failed: {e:?}")))
    }

    /// Send a UDP datagram from the given socket.
    ///
    /// # Errors
    ///
    /// Returns [`OverlayError::PeerConfig`] if smoltcp refuses the send.
    pub fn udp_send_to(
        &mut self,
        handle: UdpHandle,
        data: &[u8],
        dst_addr: IpAddress,
        dst_port: u16,
    ) -> Result<(), OverlayError> {
        let socket = self.sockets.get_mut::<UdpSocket>(handle.into());
        socket
            .send_slice(data, (dst_addr, dst_port))
            .map_err(|e| OverlayError::PeerConfig(format!("udp send failed: {e:?}")))
    }

    /// Receive a UDP datagram on the given socket.
    pub fn udp_recv_from(&mut self, handle: UdpHandle) -> Option<(Vec<u8>, IpAddress, u16)> {
        let socket = self.sockets.get_mut::<UdpSocket>(handle.into());
        socket.recv().ok().map(|(data, endpoint)| {
            (
                data.to_vec(),
                endpoint.endpoint.addr,
                endpoint.endpoint.port,
            )
        })
    }
}

impl From<UdpHandle> for smoltcp::iface::SocketHandle {
    fn from(h: UdpHandle) -> Self {
        h.smol_handle
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use super::*;
    use crate::overlay::{HopMuxSocket, PairedWgDevice, derive_overlay_ipv4};

    #[tokio::test]
    async fn udp_round_trip_via_paired_wg_device() -> Result<(), Box<dyn std::error::Error>> {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];

        let ip_a = derive_overlay_ipv4(&key_a);
        let ip_b = derive_overlay_ipv4(&key_b);

        let (dev_a, dev_b) = PairedWgDevice::new_pair();

        let mut net_a = Netstack::new(Arc::new(dev_a), Ipv4Address::from_octets(ip_a.octets()))?;
        let mut net_b = Netstack::new(Arc::new(dev_b), Ipv4Address::from_octets(ip_b.octets()))?;

        let sock_a = HopMuxSocket::bind(&mut net_a, 1234)?;
        let sock_b = HopMuxSocket::bind(&mut net_b, 1234)?;

        let payload = b"hello from overlay";
        let dst_b = SocketAddr::from((ip_b, 1234));

        sock_a.send_to(&mut net_a, payload, dst_b)?;

        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(5);
        let mut recv_buf = [0u8; 256];
        let mut received = None;

        while start.elapsed() < timeout && received.is_none() {
            let millis = i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX);
            let now = smoltcp::time::Instant::from_millis(millis);
            net_a.poll(now);
            net_b.poll(now);

            if let Some((n, src)) = sock_b.recv_from(&mut net_b, &mut recv_buf) {
                received = Some((n, src));
            }

            tokio::task::yield_now().await;
        }

        let Some((n, src)) = received else {
            panic!("packet must arrive at B within timeout");
        };
        assert_eq!(&recv_buf[..n], payload);
        assert_eq!(src.ip(), ip_a);
        assert_eq!(src.port(), 1234);

        Ok(())
    }
}
