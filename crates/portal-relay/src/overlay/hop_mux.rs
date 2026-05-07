//! Hop-mux UDP socket abstraction (Phase 6b/B U7).
//!
//! `HopMux` wraps a smoltcp UDP socket so that higher layers can send and
//! receive QUIC datagrams without interacting with smoltcp directly.
//!
//! ## Deferred to Phase 7
//!
//! - Quinn integration: the UDP socket is not yet handed to a quinn
//!   `UdpSocket` adapter.  That wiring lands in Phase 7/U8 e2e work.
//! - TCP stream mux: the plan's yamux replacement is out of scope for
//!   v0.1; UDP datagram carriage is the v0.1 overlay transport.

use std::net::SocketAddr;

use super::{
    error::OverlayError,
    netstack::{Netstack, UdpHandle},
};
use smoltcp::wire::IpAddress;

/// A UDP socket inside the overlay that can send/receive datagrams.
pub struct HopMuxSocket {
    handle: UdpHandle,
}

impl HopMuxSocket {
    /// Bind a UDP socket on the given port.
    ///
    /// # Errors
    ///
    /// Returns [`OverlayError::PeerConfig`] if socket creation or binding fails.
    pub fn bind(netstack: &mut Netstack, port: u16) -> Result<Self, OverlayError> {
        let handle = netstack.create_udp_socket()?;
        netstack.udp_bind(handle, port)?;
        Ok(Self { handle })
    }

    /// Send a datagram to the given destination.
    ///
    /// # Errors
    ///
    /// Returns [`OverlayError::PeerConfig`] if the UDP send fails.
    pub fn send_to(
        &self,
        netstack: &mut Netstack,
        data: &[u8],
        dst: SocketAddr,
    ) -> Result<(), OverlayError> {
        let (addr, port) = match dst {
            SocketAddr::V4(v4) => (IpAddress::Ipv4(*v4.ip()), v4.port()),
            SocketAddr::V6(v6) => (IpAddress::Ipv6(*v6.ip()), v6.port()),
        };
        netstack.udp_send_to(self.handle, data, addr, port)
    }

    /// Try to receive a datagram.  Returns `None` if no packet is queued.
    pub fn recv_from(
        &self,
        netstack: &mut Netstack,
        buf: &mut [u8],
    ) -> Option<(usize, SocketAddr)> {
        let (data, addr, port) = netstack.udp_recv_from(self.handle)?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        let addr = match addr {
            IpAddress::Ipv4(v4) => SocketAddr::from((v4, port)),
            IpAddress::Ipv6(v6) => SocketAddr::from((v6, port)),
        };
        Some((n, addr))
    }
}
