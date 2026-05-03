//! [`ReputationDelta`](ReputationDelta) — v0.2 wire reservation (R10); **must not be emitted in v0.1**.

use serde::{Deserialize, Serialize};

use crate::domain_separators;
use crate::error::Error;
use crate::limits;

/// Opaque reason namespace until Phase 5 assigns enum variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReasonCode(pub u16);

/// Cross-relay reputation propagation envelope (v0.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReputationDelta {
    /// Subject identity pubkey.
    pub identity_pubkey: [u8; 32],
    /// Score adjustment.
    pub score_delta: i32,
    /// Decay window for this delta.
    pub decay_window_secs: u64,
    /// Opaque reason until Phase 5 assigns enum variants.
    pub reason_code: ReasonCode,
    /// Relay that signed this delta.
    pub signed_by_relay_pubkey: [u8; 32],
}

impl ReputationDelta {
    /// Canonical signing input (v0.2).
    ///
    /// # Errors
    /// Returns [`Error::FrameTooLarge`] when the inner encoding exceeds the SEC-014 cap, or
    /// [`Error::PostcardEncode`] on serialization failure.
    pub fn canonical_signing_input(&self) -> Result<Vec<u8>, Error> {
        let inner = postcard::to_stdvec(self)?;
        if inner.len() > limits::REPUTATION_DELTA_MAX {
            return Err(Error::FrameTooLarge);
        }
        postcard::to_stdvec(&(domain_separators::REPUTATION_DELTA, self)).map_err(Into::into)
    }
}
