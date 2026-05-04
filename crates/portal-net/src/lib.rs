//! QUIC backhaul + TCP/UDP relay primitives for the portal-tunnel-rs workspace.
//!
//! Owns R2 trust boundary 3 (QUIC datagram identity).

#![forbid(unsafe_code)]

pub mod error;
pub(crate) mod quic;

pub use error::NetError;
pub use quic::identity::{
    QuicIdentityKey, generate_quic_key, load_quic_key, save_quic_key, verifying_key,
};
