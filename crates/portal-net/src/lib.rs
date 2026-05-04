//! QUIC backhaul + TCP/UDP relay primitives for the portal-tunnel-rs workspace.
//!
//! Owns R2 trust boundary 3 (QUIC datagram identity).

#![forbid(unsafe_code)]

pub mod dual_stack;
pub mod error;
pub mod quic;
pub mod tcp;
pub mod udp;

pub use dual_stack::{
    bind_dual_stack_tcp, bind_dual_stack_udp, canonicalize_ip, canonicalize_socket,
};
pub use error::NetError;
pub use quic::identity::{
    QuicIdentityKey, generate_quic_identity_key, load_quic_identity_key,
    quic_identity_verifying_key, save_quic_identity_key,
};
pub use quic::{Endpoint, EndpointRole, InboundStream, SpkiPinVerifier, TcpProxyKind};
pub use tcp::TcpPortRelay;
pub use udp::{DatagramSession, UdpRelay};
