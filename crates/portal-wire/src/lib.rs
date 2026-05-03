//! Greenfield wire protocol — types, framing constants, and pure codecs.
//!
//! No I/O, no async runtime in the public API (tokio-util codecs are sync
//! `Encoder`/`Decoder` traits). Cryptographic signing lives in `portal-crypto`.

pub mod api;
pub mod channel;
pub mod constants;
pub mod datagram;
pub mod descriptor;
pub mod domain_separators;
pub mod envelope;
pub mod error;
pub mod hop;
pub mod lease;
pub mod limits;
pub mod mitm;
pub mod paths;
pub mod reputation;
pub mod response;
pub mod routed_hostname;

pub use error::Error;
