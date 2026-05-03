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
    /// Canonical signing input: domain separator || postcard(normalized self).
    ///
    /// Address-order-invariant by construction: clones of `addresses_v4`/`addresses_v6`
    /// are stable-sorted by their full key tuple before encoding the canonical signing
    /// input. The wire encoding of the descriptor itself (via `postcard::to_stdvec(self)`
    /// outside this function) still preserves the source address order — normalization
    /// happens on a clone here, never on `self`.
    ///
    /// # Errors
    /// Returns [`Error::FrameTooLarge`] when the inner encoding exceeds the SEC-014 cap, or
    /// [`Error::PostcardEncode`] on serialization failure.
    pub fn canonical_signing_input(&self) -> Result<Vec<u8>, Error> {
        // Normalize address order so the signing input is invariant under
        // permutation of addresses_v4 / addresses_v6. The postcard wire
        // encoding of `self` (used by RelayDescriptor round-trip) is
        // unaffected — normalization happens on a clone, never on `self`.
        let mut v4 = self.addresses_v4.clone();
        v4.sort_by_key(|s| (s.ip().to_bits(), s.port()));
        let mut v6 = self.addresses_v6.clone();
        v6.sort_by_key(|s| (s.ip().to_bits(), s.port(), s.flowinfo(), s.scope_id()));
        let normalized = Self {
            identity_key: self.identity_key,
            addresses_v4: v4,
            addresses_v6: v6,
        };
        let inner = postcard::to_stdvec(&normalized)?;
        if inner.len() > limits::RELAY_DESCRIPTOR_CANON_MAX {
            return Err(Error::FrameTooLarge);
        }
        postcard::to_stdvec(&(domain_separators::RELAY_DESCRIPTOR, &normalized)).map_err(Into::into)
    }
}
