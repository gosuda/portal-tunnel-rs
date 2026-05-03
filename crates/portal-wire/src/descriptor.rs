//! [`RelayDescriptor`](RelayDescriptor) — relay identity + dual-stack addresses (R12).

use std::net::{SocketAddrV4, SocketAddrV6};

use serde::{Deserialize, Serialize};

use crate::domain_separators;
use crate::error::Error;
use crate::limits;

/// Signed announcement of a relay's identity and reachable addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayDescriptor {
    /// Ed25519 identity pubkey (raw 32 bytes).
    pub identity_key: [u8; 32],
    /// IPv4 bind/connect addresses advertised for this relay.
    pub addresses_v4: Vec<SocketAddrV4>,
    /// IPv6 bind/connect addresses advertised for this relay.
    pub addresses_v6: Vec<SocketAddrV6>,
}

impl RelayDescriptor {
    /// Canonical signing input: domain separator || postcard(self).
    ///
    /// # Errors
    /// Returns [`Error::FrameTooLarge`] when the inner encoding exceeds the SEC-014 cap, or
    /// [`Error::PostcardEncode`] on serialization failure.
    pub fn canonical_signing_input(&self) -> Result<Vec<u8>, Error> {
        let inner = postcard::to_stdvec(self)?;
        if inner.len() > limits::RELAY_DESCRIPTOR_CANON_MAX {
            return Err(Error::FrameTooLarge);
        }
        postcard::to_stdvec(&(domain_separators::RELAY_DESCRIPTOR, self)).map_err(Into::into)
    }
}
