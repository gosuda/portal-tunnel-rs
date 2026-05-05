//! [`HopRoute`] — multi-hop attestation payload (Phase 6b consumes).

use serde::{Deserialize, Serialize};

use crate::domain_separators;
use crate::error::Error;

/// Attested next-hop routing decision (wire reservation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopRoute {
    /// Opaque route id for logging / correlation.
    pub route_id: u64,
    /// Next relay identity (raw pubkey).
    pub next_hop: [u8; 32],
}

impl HopRoute {
    /// Canonical signing input for hop attestations.
    ///
    /// # Errors
    /// Returns [`Error::PostcardEncode`] on serialization failure.
    pub fn canonical_signing_input(&self) -> Result<Vec<u8>, Error> {
        postcard::to_stdvec(&(domain_separators::HOP_ROUTE, self)).map_err(Into::into)
    }
}
