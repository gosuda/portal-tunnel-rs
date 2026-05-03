//! [`LeaseToken`](LeaseToken) + [`Scope`](Scope) (SEC-003).

use serde::{Deserialize, Serialize};

use crate::domain_separators;
use crate::error::Error;
use crate::limits;

/// Granted capabilities for a lease (Phase 5 fills semantics).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    /// TCP exposure allowed.
    pub tcp: bool,
    /// UDP exposure allowed.
    pub udp: bool,
    /// Overlay hop allowed.
    pub hop: bool,
    /// Optional bandwidth ceiling (bps).
    pub max_bps: Option<u64>,
}

/// Bearer credential bound to a specific relay pubkey (SEC-003).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseToken {
    /// Relay that minted this token — prevents cross-relay replay.
    pub relay_pubkey: [u8; 32],
    /// Opaque session / lease id.
    pub lease_id: u64,
    /// Capability scope.
    pub scope: Scope,
}

impl LeaseToken {
    /// Canonical signing input.
    ///
    /// # Errors
    /// Returns [`Error::FrameTooLarge`] when the inner encoding exceeds the SEC-014 cap, or
    /// [`Error::PostcardEncode`] on serialization failure.
    pub fn canonical_signing_input(&self) -> Result<Vec<u8>, Error> {
        let inner = postcard::to_stdvec(self)?;
        if inner.len() > limits::LEASE_TOKEN_MAX {
            return Err(Error::FrameTooLarge);
        }
        postcard::to_stdvec(&(domain_separators::LEASE_TOKEN, self)).map_err(Into::into)
    }
}
